/*
 * Copyright (C) Shachar Sharon <ssharon@redhat.com> 2025
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "lib/util/time.h"
#include "lib/util/memcache.h"
#include "lib/util/tevent_unix.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "util_tdb.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

struct vfs_ceph_iostat_entry {
	uint64_t count; /* number of events */
	uint64_t time;	/* microseconds */
	uint64_t bytes; /* bytes */
	uint64_t reserved;
};

struct vfs_ceph_iostat_record {
	char svc[64];
	struct vfs_ceph_iostat_entry read;
	struct vfs_ceph_iostat_entry write;
	uint8_t pad[128];
};

struct vfs_ceph_iostat_info {
	char *svc;
	int snum;
	int refcnt;
	struct vfs_ceph_iostat_entry read;
	struct vfs_ceph_iostat_entry write;
};

struct vfs_ceph_iostat_aio_state {
	struct vfs_ceph_iostat_info *info;
	struct vfs_aio_state vfs_aio_state;
	ssize_t ret;
};

static unsigned int vfs_ceph_iostatdb_refcnt;
static struct db_context *vfs_ceph_iostatdb;

static int vfs_ceph_iostatdb_init(void)
{
	struct db_context *db = vfs_ceph_iostatdb;
	char *dbname = NULL;
	int ret = -1;

	if (db != NULL) {
		goto out_ok;
	}

	dbname = state_path(talloc_tos(), "ceph_iostat.tdb");
	if (dbname == NULL) {
		errno = ENOSYS;
		goto out;
	}

	become_root();
	db = db_open(NULL,
		     dbname,
		     0,
		     TDB_DEFAULT,
		     O_RDWR | O_CREAT,
		     0600,
		     DBWRAP_LOCK_ORDER_1,
		     DBWRAP_FLAG_NONE);
	unbecome_root();

	TALLOC_FREE(dbname);

	if (db == NULL) {
		errno = ENOSYS;
		goto out;
	}
	vfs_ceph_iostatdb = db;

out_ok:
	vfs_ceph_iostatdb_refcnt++;
	ret = 0;
out:
	return ret;
}

static void vfs_ceph_iostatdb_fini(void)
{
	vfs_ceph_iostatdb_refcnt--;
	if (vfs_ceph_iostatdb_refcnt == 0) {
		TALLOC_FREE(vfs_ceph_iostatdb);
	}
}

static void vfs_ceph_iostat_mkrec(const struct vfs_ceph_iostat_info *info,
				  struct vfs_ceph_iostat_record *rec)
{
	memset(rec, 0, sizeof(*rec));
	memcpy(&rec->read, &info->read, sizeof(rec->read));
	memcpy(&rec->write, &info->write, sizeof(rec->write));
	strncpy(rec->svc, info->svc, sizeof(rec->svc) - 1);
}

static TDB_DATA vfs_ceph_iostatdb_key(const struct vfs_ceph_iostat_record *rec)
{
	return make_tdb_data((const uint8_t *)(rec->svc), sizeof(rec->svc));
}

static TDB_DATA vfs_ceph_iostatdb_data(struct vfs_ceph_iostat_record *rec)
{
	return make_tdb_data((const void *)rec, sizeof(rec));
}

static int vfs_ceph_iostatdb_store(const struct vfs_ceph_iostat_info *info)
{
	struct vfs_ceph_iostat_record rec;
	NTSTATUS status;

	vfs_ceph_iostat_mkrec(info, &rec);
	status = dbwrap_store(vfs_ceph_iostatdb,
			      vfs_ceph_iostatdb_key(&rec),
			      vfs_ceph_iostatdb_data(&rec),
			      0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("failed to store: snum=%d svc='%s' %s\n",
			  info->snum,
			  info->svc,
			  nt_errstr(status));
		return -1;
	}
	return 0;
}

static uint64_t vfs_ceph_iostat_ts(void)
{
	struct timespec ts;

	clock_gettime_mono(&ts);
	return (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000); /* usec */
}

static DATA_BLOB vfs_ceph_iostat_cache_key(const int *p_snum)
{
	return data_blob_const(p_snum, sizeof(*p_snum));
}

static struct vfs_ceph_iostat_info *vfs_ceph_iostat_cache_lookup(int snum)
{
	struct vfs_ceph_iostat_info *info = NULL;
	DATA_BLOB value = {};
	bool ok;

	ok = memcache_lookup(smbd_memcache(),
			     IOSTAT_CACHE,
			     vfs_ceph_iostat_cache_key(&snum),
			     &value);
	if (!ok || (value.length != sizeof(*info))) {
		return NULL;
	}

	info = (struct vfs_ceph_iostat_info *)value.data;
	return info;
}

static struct vfs_ceph_iostat_info *vfs_ceph_iostat_cache_add(int snum, const char *sname)
{
	struct vfs_ceph_iostat_info info = {
		.snum = snum,
		.svc = talloc_strdup(NULL, sname),
	};
	bool ok;

	if (info.svc == NULL) {
		return NULL;
	}

	ok = memcache_add(smbd_memcache(),
			  IOSTAT_CACHE,
			  vfs_ceph_iostat_cache_key(&info.snum),
			  data_blob_const(&info, sizeof(info)));
	if (!ok) {
		TALLOC_FREE(info.svc);
		return NULL;
	}
	return vfs_ceph_iostat_cache_lookup(snum);
}

static struct vfs_ceph_iostat_info *vfs_ceph_iostat_cache_lookup_or_add(
	int snum,
	const char *sname)
{
	struct vfs_ceph_iostat_info *info = NULL;

	info = vfs_ceph_iostat_cache_lookup(snum);
	if (info != NULL) {
		goto out_ok;
	}
	info = vfs_ceph_iostat_cache_add(snum, sname);
	if (info == NULL) {
		goto out;
	}
out_ok:
	info->refcnt++;
out:
	return info;
}

static void vfs_ceph_iostat_cache_unref(int snum)
{
	struct vfs_ceph_iostat_info *info = NULL;

	info = vfs_ceph_iostat_cache_lookup(snum);
	if (info == NULL) {
		return;
	}
	info->refcnt--;
	if (info->refcnt > 0) {
		return;
	}
	TALLOC_FREE(info->svc);
	memcache_delete(smbd_memcache(),
			IOSTAT_CACHE,
			vfs_ceph_iostat_cache_key(&snum));
}

static int vfs_ceph_iostat_connect(struct vfs_handle_struct *handle,
				   const char *svc,
				   const char *user)
{
	struct vfs_ceph_iostat_info *info = NULL;
	char *sname = NULL;
	int snum = -1;
	int res = 0;

	res = vfs_ceph_iostatdb_init();
	if (res != 0) {
		return res;
	}
	res = SMB_VFS_NEXT_CONNECT(handle, svc, user);
	if (res < 0) {
		vfs_ceph_iostatdb_fini();
		return res;
	}
	snum = find_service(talloc_tos(), svc, &sname);
	if (snum == -1 || sname == NULL) {
		/* following the footsteps of vfs_posix_eadb.c */
		return 0;
	}
	info = vfs_ceph_iostat_cache_lookup_or_add(snum, sname);
	if (info != NULL) {
		DBG_DEBUG("snum=%d svc='%s'\n", info->snum, info->svc);
	}
	return res;
}

static void vfs_ceph_iostat_disconnect(vfs_handle_struct *handle)
{
	struct vfs_ceph_iostat_info *info = NULL;
	int snum = SNUM(handle->conn);

	info = vfs_ceph_iostat_cache_lookup(snum);
	if (info != NULL) {
		DBG_DEBUG("snum=%d svc='%s'\n", info->snum, info->svc);
		vfs_ceph_iostat_cache_unref(snum);
	}
	SMB_VFS_NEXT_DISCONNECT(handle);
	vfs_ceph_iostatdb_fini();
}

static ssize_t vfs_ceph_iostat_pread(struct vfs_handle_struct *handle,
				     files_struct *fsp,
				     void *data,
				     size_t n,
				     off_t offset)
{
	struct vfs_ceph_iostat_info *info = NULL;
	int snum = SNUM(handle->conn);
	uint64_t ts = 0;
	ssize_t res = 0;

	ts = vfs_ceph_iostat_ts();
	res = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
	if (res < 0) {
		goto out;
	}
	info = vfs_ceph_iostat_cache_lookup(snum);
	if (info == NULL) {
		goto out;
	}
	info->read.count++;
	info->read.bytes += (uint64_t)res;
	info->read.time += (vfs_ceph_iostat_ts() - ts);
	DBG_DEBUG("snum=%d svc='%s' count=%" PRIu64 " bytes=%" PRIu64
		  " time=%" PRIu64 "\n",
		  info->snum,
		  info->svc,
		  info->read.count,
		  info->read.bytes,
		  info->read.time);

	vfs_ceph_iostatdb_store(info);
out:
	return res;
}

static void vfs_ceph_iostat_pread_done(struct tevent_req *subreq);

static struct tevent_req *vfs_ceph_iostat_pread_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp,
	void *data,
	size_t n,
	off_t off)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct vfs_ceph_iostat_aio_state *state = NULL;
	int snum = SNUM(handle->conn);

	req = tevent_req_create(mem_ctx,
				&state,
				struct vfs_ceph_iostat_aio_state);
	if (req == NULL) {
		return NULL;
	}
	state->info = vfs_ceph_iostat_cache_lookup(snum);

	subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp, data, n, off);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_ceph_iostat_pread_done, req);
	return req;
}

static void vfs_ceph_iostat_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct vfs_ceph_iostat_aio_state *state = tevent_req_data(
		req, struct vfs_ceph_iostat_aio_state);
	struct vfs_ceph_iostat_info *info = state->info;

	state->ret = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	if ((state->ret >= 0) && (info != NULL)) {
		info->read.count++;
		info->read.bytes += (uint64_t)state->ret;
		info->read.time += state->vfs_aio_state.duration;
		DBG_DEBUG("snum=%d svc='%s' count=%" PRIu64 " bytes=%" PRIu64
			  " time=%" PRIu64 "\n",
			  info->snum,
			  info->svc,
			  info->read.count,
			  info->read.bytes,
			  info->read.time);
		vfs_ceph_iostatdb_store(info);
	}

	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t vfs_ceph_iostat_pread_recv(struct tevent_req *req,
					  struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_ceph_iostat_aio_state *state = tevent_req_data(
		req, struct vfs_ceph_iostat_aio_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static ssize_t vfs_ceph_iostat_pwrite(struct vfs_handle_struct *handle,
				      files_struct *fsp,
				      const void *data,
				      size_t n,
				      off_t off)
{
	struct vfs_ceph_iostat_info *info = NULL;
	int snum = SNUM(handle->conn);
	uint64_t ts = 0;
	ssize_t res = 0;

	ts = vfs_ceph_iostat_ts();
	res = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, off);
	if (res < 0) {
		goto out;
	}
	info = vfs_ceph_iostat_cache_lookup(snum);
	if (info == NULL) {
		goto out;
	}
	info->write.count++;
	info->write.bytes += (uint64_t)res;
	info->write.time += (vfs_ceph_iostat_ts() - ts);
	DBG_DEBUG("snum=%d svc='%s' count=%" PRIu64 " bytes=%" PRIu64
		  " time=%" PRIu64 "\n",
		  info->snum,
		  info->svc,
		  info->write.count,
		  info->write.bytes,
		  info->write.time);
	vfs_ceph_iostatdb_store(info);
out:
	return res;
}

static void vfs_ceph_iostat_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *vfs_ceph_iostat_pwrite_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp,
	const void *data,
	size_t n,
	off_t off)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct vfs_ceph_iostat_aio_state *state = NULL;
	int snum = SNUM(handle->conn);

	req = tevent_req_create(mem_ctx,
				&state,
				struct vfs_ceph_iostat_aio_state);
	if (req == NULL) {
		return NULL;
	}
	state->info = vfs_ceph_iostat_cache_lookup(snum);

	subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp, data, n, off);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_ceph_iostat_pwrite_done, req);
	return req;
}

static void vfs_ceph_iostat_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct vfs_ceph_iostat_aio_state *state = tevent_req_data(
		req, struct vfs_ceph_iostat_aio_state);
	struct vfs_ceph_iostat_info *info = state->info;

	state->ret = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	if ((state->ret >= 0) && (info != NULL)) {
		info->write.count++;
		info->write.bytes += (uint64_t)state->ret;
		info->write.time += state->vfs_aio_state.duration;
		DBG_DEBUG("snum=%d svc='%s' count=%" PRIu64 " bytes=%" PRIu64
			  " time=%" PRIu64 "\n",
			  info->snum,
			  info->svc,
			  info->write.count,
			  info->write.bytes,
			  info->write.time);
		vfs_ceph_iostatdb_store(info);
	}

	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t vfs_ceph_iostat_pwrite_recv(struct tevent_req *req,
					   struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_ceph_iostat_aio_state *state = tevent_req_data(
		req, struct vfs_ceph_iostat_aio_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;

	return state->ret;
}

static struct vfs_fn_pointers ceph_iostat_fns = {
	.connect_fn = vfs_ceph_iostat_connect,
	.disconnect_fn = vfs_ceph_iostat_disconnect,
	.pread_fn = vfs_ceph_iostat_pread,
	.pread_send_fn = vfs_ceph_iostat_pread_send,
	.pread_recv_fn = vfs_ceph_iostat_pread_recv,
	.pwrite_fn = vfs_ceph_iostat_pwrite,
	.pwrite_send_fn = vfs_ceph_iostat_pwrite_send,
	.pwrite_recv_fn = vfs_ceph_iostat_pwrite_recv,

};

static_decl_vfs;
NTSTATUS vfs_ceph_iostat_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"ceph_iostat",
				&ceph_iostat_fns);
}

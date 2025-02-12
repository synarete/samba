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
#include "lib/util/tevent_unix.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "util_tdb.h"
#include "vfs_iostat.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

struct vfs_iostat_info {
	struct vfs_iostat_info *prev;
	struct vfs_iostat_info *next;
	struct vfs_iostat_dbkey dbkey;
	struct vfs_iostat_entry read;
	struct vfs_iostat_entry write;
	uint64_t store_ts;
	char *svc;
	int snum;
	int refcnt;
	bool changed;
};

struct vfs_iostat_aio_state {
	struct vfs_iostat_info *info;
	struct vfs_aio_state vfs_aio_state;
	ssize_t ret;
};

static struct vfs_iostat_info *vfs_iostat_cache[512];
static unsigned int vfs_iostatdb_refcnt;
static struct db_context *vfs_iostatdb;

static uint64_t vfs_iostat_ts(void)
{
	struct timespec ts;

	clock_gettime_mono(&ts);
	return (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000); /* usec  */
}

static int vfs_iostatdb_init(void)
{
	struct db_context *db = vfs_iostatdb;
	char *dbname = NULL;
	int ret = -1;

	if (db != NULL) {
		goto out_ok;
	}

	dbname = state_path(talloc_tos(), VFS_IOSTAT_TDB_FILE);
	if (dbname == NULL) {
		errno = ENOSYS;
		goto out;
	}

	become_root();
	db = db_open(NULL,
		     dbname,
		     0,
		     TDB_CLEAR_IF_FIRST | TDB_MUTEX_LOCKING | TDB_NOSYNC,
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
	vfs_iostatdb = db;

out_ok:
	vfs_iostatdb_refcnt++;
	ret = 0;
out:
	return ret;
}

static void vfs_iostatdb_unref(void)
{
	vfs_iostatdb_refcnt--;
	if (vfs_iostatdb_refcnt == 0) {
		TALLOC_FREE(vfs_iostatdb);
	}
}

#define VFS_IOSTATDB_REC_ALIGN(_size_) (((_size_) + 15) & ~15)

static struct vfs_iostat_record *vfs_iostat_mkrec(
	TALLOC_CTX *mem_ctx,
	const struct vfs_iostat_info *info,
	uint64_t ts)
{
	struct vfs_iostat_record *rec = NULL;
	const size_t len = strlen(info->svc);
	const size_t rsz = VFS_IOSTATDB_REC_ALIGN(sizeof(*rec) + len + 1);

	rec = talloc_zero_size(mem_ctx, rsz);
	if (rec == NULL) {
		return NULL;
	}
	rec->timestamp = ts;
	memcpy(&rec->read, &info->read, sizeof(rec->read));
	memcpy(&rec->write, &info->write, sizeof(rec->write));
	strncpy(rec->service, info->svc, len);
	return rec;
}

static TDB_DATA vfs_iostatdb_key(const struct vfs_iostat_info *info)
{
	const void *dbkey = &info->dbkey;

	return make_tdb_data(dbkey, sizeof(info->dbkey));
}

static TDB_DATA vfs_iostatdb_data(struct vfs_iostat_record *rec)
{
	const size_t len = strlen(rec->service);
	const size_t rsz = VFS_IOSTATDB_REC_ALIGN(sizeof(*rec) + len + 1);

	return make_tdb_data((const void *)rec, rsz);
}

static int vfs_iostatdb_store(const struct vfs_iostat_info *info, uint64_t ts)
{
	struct vfs_iostat_record *rec = NULL;
	NTSTATUS status;

	rec = vfs_iostat_mkrec(talloc_tos(), info, ts);
	if (rec == NULL) {
		return -1;
	}
	status = dbwrap_store(vfs_iostatdb,
			      vfs_iostatdb_key(info),
			      vfs_iostatdb_data(rec),
			      0);
	TALLOC_FREE(rec);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("failed to store: snum=%d svc='%s' %s\n",
			  info->snum,
			  info->svc,
			  nt_errstr(status));
		return -1;
	}
	return 0;
}

static int vfs_iostatdb_update(struct vfs_iostat_info *info)
{
	const uint64_t ts = vfs_iostat_ts();
	const uint64_t dif = ts - info->store_ts;
	int res = 0;

	if (!info->store_ts || ((dif > 10000000) && info->changed)) {
		res = vfs_iostatdb_store(info, ts);
		info->store_ts = ts;
		info->changed = false;
	}
	return res;
}

static int vfs_iostatdb_delete(struct vfs_iostat_info *info)
{
	NTSTATUS status;

	status = dbwrap_delete(vfs_iostatdb, vfs_iostatdb_key(info));
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("failed to delete: snum=%d svc='%s' %s\n",
			  info->snum,
			  info->svc,
			  nt_errstr(status));
		return -1;
	}
	return 0;
}

static size_t vfs_iostat_cache_slot(int snum)
{
	return (size_t)snum % ARRAY_SIZE(vfs_iostat_cache);
}

static struct vfs_iostat_info *vfs_iostat_cache_lookup(int snum)
{
	struct vfs_iostat_info *info = NULL;
	const size_t slot = vfs_iostat_cache_slot(snum);

	info = vfs_iostat_cache[slot];
	while (info != NULL) {
		if (info->snum == snum) {
			return info;
		}
		info = info->next;
	}
	return NULL;
}

static struct vfs_iostat_info *vfs_iostat_cache_lookup_by(
	const struct vfs_handle_struct *handle)
{
	return vfs_iostat_cache_lookup(SNUM(handle->conn));
}

static struct vfs_iostat_info *vfs_iostat_cache_add(int snum, const char *sname)
{
	struct vfs_iostat_info *info = NULL;
	size_t slot;

	info = talloc_zero(NULL, struct vfs_iostat_info);
	if (info == NULL) {
		return NULL;
	}

	info->svc = talloc_strdup(info, sname);
	if (info->svc == NULL) {
		TALLOC_FREE(info);
		return NULL;
	}

	info->snum = snum;
	info->dbkey.k[0] = (uint64_t)tevent_cached_getpid();
	info->dbkey.k[1] = (uint64_t)snum;
	info->refcnt = 0;

	slot = vfs_iostat_cache_slot(info->snum);
	DLIST_ADD(vfs_iostat_cache[slot], info);

	return info;
}

static struct vfs_iostat_info *vfs_iostat_cache_lookup_or_add(int snum,
							      const char *sname)
{
	struct vfs_iostat_info *info = NULL;

	if (!strlen(sname)) {
		goto out;
	}
	info = vfs_iostat_cache_lookup(snum);
	if (info != NULL) {
		goto out_ok;
	}
	info = vfs_iostat_cache_add(snum, sname);
	if (info == NULL) {
		goto out;
	}
out_ok:
	info->refcnt++;
out:
	return info;
}

static void vfs_iostat_cache_delete(struct vfs_iostat_info *info)
{
	size_t slot;

	info->refcnt--;
	if (info->refcnt > 0) {
		return;
	}
	slot = vfs_iostat_cache_slot(info->snum);
	DLIST_REMOVE(vfs_iostat_cache[slot], info);
	TALLOC_FREE(info->svc);
	TALLOC_FREE(info);
}

static int vfs_iostat_connect(struct vfs_handle_struct *handle,
			      const char *svc,
			      const char *user)
{
	struct vfs_iostat_info *info = NULL;
	char *sname = NULL;
	int snum = -1;
	int res = 0;

	res = vfs_iostatdb_init();
	if (res != 0) {
		return res;
	}
	res = SMB_VFS_NEXT_CONNECT(handle, svc, user);
	if (res < 0) {
		vfs_iostatdb_unref();
		return res;
	}
	snum = find_service(talloc_tos(), svc, &sname);
	if (snum == -1 || sname == NULL) {
		/* following the footsteps of vfs_posix_eadb.c */
		return 0;
	}
	info = vfs_iostat_cache_lookup_or_add(snum, sname);
	if (info != NULL) {
		DBG_DEBUG("snum=%d svc='%s'\n", info->snum, info->svc);
	}
	return res;
}

static void vfs_iostat_disconnect(vfs_handle_struct *handle)
{
	struct vfs_iostat_info *info = NULL;
	int snum = SNUM(handle->conn);

	SMB_VFS_NEXT_DISCONNECT(handle);

	info = vfs_iostat_cache_lookup(snum);
	if (info == NULL) {
		goto out;
	}
	DBG_DEBUG("snum=%d svc='%s'\n", info->snum, info->svc);
	if (info->refcnt == 1) {
		vfs_iostatdb_delete(info);
	}
	vfs_iostat_cache_delete(info);
out:
	vfs_iostatdb_unref();
}

static int vfs_iostat_openat(vfs_handle_struct *handle,
			     const struct files_struct *dirfsp,
			     const struct smb_filename *smb_fname,
			     files_struct *fsp,
			     const struct vfs_open_how *how)
{
	struct vfs_iostat_info *info = NULL;
	int ret;

	ret = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
	if (ret != 0) {
		goto out;
	}
	info = vfs_iostat_cache_lookup_by(handle);
	if (info == NULL) {
		goto out;
	}
	vfs_iostatdb_update(info);
out:
	return ret;
}

static int vfs_iostat_close(vfs_handle_struct *handle, files_struct *fsp)
{
	struct vfs_iostat_info *info = NULL;
	int ret;

	ret = SMB_VFS_NEXT_CLOSE(handle, fsp);
	if (ret != 0) {
		goto out;
	}
	info = vfs_iostat_cache_lookup_by(handle);
	if (info == NULL) {
		goto out;
	}
	vfs_iostatdb_update(info);
out:
	return ret;
}

static int vfs_iostat_closedir(vfs_handle_struct *handle, DIR *dirp)
{
	struct vfs_iostat_info *info = NULL;
	int ret;

	ret = SMB_VFS_NEXT_CLOSEDIR(handle, dirp);
	if (ret != 0) {
		goto out;
	}
	info = vfs_iostat_cache_lookup_by(handle);
	if (info == NULL) {
		goto out;
	}
	vfs_iostatdb_update(info);
out:
	return ret;
}

static ssize_t vfs_iostat_pread(struct vfs_handle_struct *handle,
				files_struct *fsp,
				void *data,
				size_t n,
				off_t offset)
{
	struct vfs_iostat_info *info = NULL;
	uint64_t ts = 0;
	ssize_t res = 0;

	ts = vfs_iostat_ts();
	res = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
	if (res < 0) {
		goto out;
	}
	info = vfs_iostat_cache_lookup_by(handle);
	if (info == NULL) {
		goto out;
	}
	info->read.count++;
	info->read.bytes += (uint64_t)res;
	info->read.time += (vfs_iostat_ts() - ts);
	info->changed = true;
	DBG_DEBUG("snum=%d svc='%s' count=%" PRIu64 " bytes=%" PRIu64
		  " time=%" PRIu64 "\n",
		  info->snum,
		  info->svc,
		  info->read.count,
		  info->read.bytes,
		  info->read.time);

	vfs_iostatdb_update(info);
out:
	return res;
}

static void vfs_iostat_pread_done(struct tevent_req *subreq);

static struct tevent_req *vfs_iostat_pread_send(
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
	struct vfs_iostat_aio_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct vfs_iostat_aio_state);
	if (req == NULL) {
		return NULL;
	}
	state->info = vfs_iostat_cache_lookup_by(handle);

	subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp, data, n, off);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_iostat_pread_done, req);
	return req;
}

static void vfs_iostat_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct vfs_iostat_aio_state *state = tevent_req_data(
		req, struct vfs_iostat_aio_state);
	struct vfs_iostat_info *info = state->info;

	state->ret = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	if ((state->ret < 0) || (info == NULL)) {
		goto out;
	}
	info->read.count++;
	info->read.bytes += (uint64_t)state->ret;
	info->read.time += state->vfs_aio_state.duration;
	info->changed = true;
	DBG_DEBUG("snum=%d svc='%s' count=%" PRIu64 " bytes=%" PRIu64
		  " time=%" PRIu64 "\n",
		  info->snum,
		  info->svc,
		  info->read.count,
		  info->read.bytes,
		  info->read.time);
	vfs_iostatdb_update(info);
out:
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t vfs_iostat_pread_recv(struct tevent_req *req,
				     struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_iostat_aio_state *state = tevent_req_data(
		req, struct vfs_iostat_aio_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static ssize_t vfs_iostat_pwrite(struct vfs_handle_struct *handle,
				 files_struct *fsp,
				 const void *data,
				 size_t n,
				 off_t off)
{
	struct vfs_iostat_info *info = NULL;
	uint64_t ts = 0;
	ssize_t res = 0;

	ts = vfs_iostat_ts();
	res = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, off);
	if (res < 0) {
		goto out;
	}
	info = vfs_iostat_cache_lookup_by(handle);
	if (info == NULL) {
		goto out;
	}
	info->write.count++;
	info->write.bytes += (uint64_t)res;
	info->write.time += (vfs_iostat_ts() - ts);
	info->changed = true;
	DBG_DEBUG("snum=%d svc='%s' count=%" PRIu64 " bytes=%" PRIu64
		  " time=%" PRIu64 "\n",
		  info->snum,
		  info->svc,
		  info->write.count,
		  info->write.bytes,
		  info->write.time);
	vfs_iostatdb_update(info);
out:
	return res;
}

static void vfs_iostat_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *vfs_iostat_pwrite_send(
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
	struct vfs_iostat_aio_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct vfs_iostat_aio_state);
	if (req == NULL) {
		return NULL;
	}
	state->info = vfs_iostat_cache_lookup_by(handle);

	subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp, data, n, off);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_iostat_pwrite_done, req);
	return req;
}

static void vfs_iostat_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct vfs_iostat_aio_state *state = tevent_req_data(
		req, struct vfs_iostat_aio_state);
	struct vfs_iostat_info *info = state->info;

	state->ret = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	if ((state->ret < 0) || (info == NULL)) {
		goto out;
	}
	info->write.count++;
	info->write.bytes += (uint64_t)state->ret;
	info->write.time += state->vfs_aio_state.duration;
	info->changed = true;
	DBG_DEBUG("snum=%d svc='%s' count=%" PRIu64 " bytes=%" PRIu64
		  " time=%" PRIu64 "\n",
		  info->snum,
		  info->svc,
		  info->write.count,
		  info->write.bytes,
		  info->write.time);
	vfs_iostatdb_update(info);
out:
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t vfs_iostat_pwrite_recv(struct tevent_req *req,
				      struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_iostat_aio_state *state = tevent_req_data(
		req, struct vfs_iostat_aio_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;

	return state->ret;
}

static int vfs_iostat_ftruncate(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				off_t offset)
{
	struct vfs_iostat_info *info = NULL;
	int ret;

	ret = SMB_VFS_NEXT_FTRUNCATE(handle, fsp, offset);
	if (ret != 0) {
		goto out;
	}
	info = vfs_iostat_cache_lookup_by(handle);
	if (info == NULL) {
		goto out;
	}
	vfs_iostatdb_update(info);
out:
	return ret;
}

static int vfs_iostat_chdir(struct vfs_handle_struct *handle,
			    const struct smb_filename *smb_fname)
{
	struct vfs_iostat_info *info = NULL;
	int ret;

	ret = SMB_VFS_NEXT_CHDIR(handle, smb_fname);
	if (ret != 0) {
		goto out;
	}
	info = vfs_iostat_cache_lookup_by(handle);
	if (info == NULL) {
		goto out;
	}
	vfs_iostatdb_update(info);
out:
	return ret;
}

static int vfs_iostat_fallocate(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				uint32_t mode,
				off_t offset,
				off_t len)
{
	struct vfs_iostat_info *info = NULL;
	int ret;

	ret = SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);
	if (ret != 0) {
		goto out;
	}
	info = vfs_iostat_cache_lookup_by(handle);
	if (info == NULL) {
		goto out;
	}
	vfs_iostatdb_update(info);
out:
	return ret;
}

static struct vfs_fn_pointers iostat_fns = {
	.connect_fn = vfs_iostat_connect,
	.disconnect_fn = vfs_iostat_disconnect,
	.openat_fn = vfs_iostat_openat,
	.close_fn = vfs_iostat_close,
	.closedir_fn = vfs_iostat_closedir,
	.pread_fn = vfs_iostat_pread,
	.pread_send_fn = vfs_iostat_pread_send,
	.pread_recv_fn = vfs_iostat_pread_recv,
	.pwrite_fn = vfs_iostat_pwrite,
	.pwrite_send_fn = vfs_iostat_pwrite_send,
	.pwrite_recv_fn = vfs_iostat_pwrite_recv,
	.chdir_fn = vfs_iostat_chdir,
	.ftruncate_fn = vfs_iostat_ftruncate,
	.fallocate_fn = vfs_iostat_fallocate,
};

static_decl_vfs;
NTSTATUS vfs_iostat_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"iostat",
				&iostat_fns);
}

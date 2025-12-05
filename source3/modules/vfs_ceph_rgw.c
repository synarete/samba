/*
 * Bridge between Samba's VFS layer and Ceph-RGW.
 *
 * Copyright (c) 2025 Vinit Agnihotri <vagnihot@redhat.com>
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

/*
 * Add the following smb.conf parameter to each share that will be hosted on
 * Ceph with rgw:
 *
 *   vfs objects = ceph_rgw
 */
#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include <dirent.h>
#include <sys/statvfs.h>
#include "smbprofile.h"
#include "lib/util/tevent_unix.h"
#include <rados/librgw.h>
#include <rados/rgw_file.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

struct vfs_ceph_rgw_config {

	/* Module parameters */
	const char *bkt_name;
	const char *user_id;
	const char *access_key;
	const char *secret_access_key;
	const char *config_file;
	const char *keyring_file;
	bool debug_enable;

	/* rgw objects */
	librgw_t rgw_lib_handle;
	struct rgw_fs *rgw_root_fs;
	struct rgw_file_handle *rgw_root_fh;

	/* misc parameters */
	int ceph_rgw_fd;
};

struct vfs_ceph_rgw_dir {
	int pos;
	int num;
	struct dirent *dirs;
};

/* Ceph-rgw file-handles via fsp-extension */
struct vfs_ceph_rgw_fh {
	struct vfs_ceph_rgw_dir *dirp;
	struct files_struct *fsp;
	struct vfs_ceph_rgw_config *config;
	struct Fh *fh;
	struct rgw_file_handle *rgw_fh;
	int fd;
	int o_flags;
};

/*
 * Note, librgw's return code model is to return -errno. Thus we have to
 * convert to what Samba expects: set errno to non-negative value and return -1.
 *
 * Using convenience helper functions to avoid non-hygienic macro.
 */
static int status_code(int ret)
{
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	return ret;
}

static ssize_t lstatus_code(intmax_t ret)
{
	if (ret < 0) {
		errno = -((int)ret);
		return -1;
	}
	return (ssize_t)ret;
}

static const char *fsp_name(const files_struct *fsp)
{
	return fsp->fsp_name->base_name;
}

static int cephrgw_next_fd(struct vfs_ceph_rgw_config *config)
{
	/*
	 * Those file-descriptor numbers are reported back to VFS layer
	 * (debug-hints only). Using numbers within a large range of
	 * [1000, 1001000], thus the chances of (annoying but harmless)
	 * collision are low.
	 */
	uint64_t next;

	next = (config->ceph_rgw_fd++ % 1000000) + 1000;
	return (int)next;
}

/*
 * Trim trailing '/', '.', '..'
 */
static char *normalise_name(void *ctx, const char *recv_name)
{
	int len = 0;

	len = strlen(recv_name);
	while(len != 0) {
		if (recv_name[len-1] == '.' || recv_name[len-1] == '/') {
			len--;
			continue;
		}
		break;
	}

	return talloc_strndup(ctx, recv_name, len);
}

static bool vfs_ceph_rgw_mount_bucket(struct connection_struct *conn,
				      struct vfs_ceph_rgw_config *config)
{
	int rc = 0;
	int nparams = 0;
	int i = 0;

	char *librgw_params[] = {
		NULL, /* program name="vfs_ceph_rgw" */
		NULL, /* --name: Must be client.admin */
		NULL, /* --cluster: Must be ceph */
		NULL, /* cluster config file */
		NULL, /* keyring file */
		NULL, /* ceph debug param */ /* remove later */
		NULL  /* Last param must be NULL */
	};

	/* Prepare parameters */
	librgw_params[nparams] = talloc_asprintf(conn, "vfs_ceph_rgw");
	nparams++;

	librgw_params[nparams] = talloc_asprintf(conn, "--name=client.admin");
	nparams++;

	librgw_params[nparams] = talloc_asprintf(conn, "--cluster=ceph");
	nparams++;

	librgw_params[nparams] = talloc_asprintf(conn,
						 "--conf=%s",
						 config->config_file);
	nparams++;

	librgw_params[nparams] = talloc_asprintf(conn,
						 "--keyring=%s",
						 config->keyring_file);
	nparams++;

	if (config->debug_enable) {
		librgw_params[nparams] = talloc_strdup(conn,
						       "-d --debug-rgw=20");
		nparams++;
	}

	for (i = 0; i < nparams; i++) {
		if (librgw_params[i] == NULL) {
			DBG_ERR("[CEPH_RGW] Not enough memory for librgw "
				"params\n");
			return false;
		}
	}

	rc = librgw_create(&config->rgw_lib_handle,
			   nparams,
			   librgw_params);
	if (rc != 0) {
		DBG_ERR("[CEPH_RGW] Failed to init librgw. rc=%d\n", rc);
		return false;
	}

	rc = rgw_mount2(config->rgw_lib_handle,
			config->user_id,
			config->access_key,
			config->secret_access_key,
			config->bkt_name,
			&config->rgw_root_fs,
			RGW_MOUNT_FLAG_NONE);
	if (rc != 0) {
		DBG_ERR("[CEPH_ERR] Unable to mount bucket=%s.Err=%d\n",
			config->bkt_name,
			rc);
		if (rc == -EINVAL) {
			DBG_ERR("[CEPH_RGW]Unable to authorise user=%s\n",
				config->user_id);
		}
		return false;
	}

	config->rgw_root_fh = config->rgw_root_fs->root_fh;
	config->ceph_rgw_fd = 0;

	return true;
};


static const char *vfs_ceph_rgw_parm(const struct vfs_handle_struct *handle,
				     const char *opt, const char *def)
{
	const char *parm = NULL;

	parm = lp_parm_const_string(SNUM(handle->conn), "ceph_rgw", opt, def);
	if ((parm == NULL) || !strlen(parm)) {
		DBG_ERR("[CEPH_RGW] missing config: '%s'\n", opt);
		return NULL;
	}
	return parm;
}


static bool vfs_ceph_rgw_load_config(struct vfs_handle_struct *handle,
				     struct vfs_ceph_rgw_config **config)
{
	struct vfs_ceph_rgw_config *config_tmp = NULL;

	config_tmp = talloc_zero(handle->conn, struct vfs_ceph_rgw_config);
	if (config_tmp == NULL) {
		errno = ENOMEM;
		return false;
	}

	config_tmp->config_file = vfs_ceph_rgw_parm(handle,
						    "config_file",
						    "/etc/ceph/ceph.conf");
	if (config_tmp->config_file == NULL) {
		return false;
	}

	config_tmp->keyring_file = vfs_ceph_rgw_parm(
		handle,
		"keyring_file",
		"/etc/ceph/ceph.client.admin.keyring");
	if (config_tmp->keyring_file == NULL) {
		return false;
	}

	config_tmp->user_id = vfs_ceph_rgw_parm(handle,
						"user_id",
						"");
	if (config_tmp->user_id == NULL) {
		return false;
	}

	config_tmp->access_key = vfs_ceph_rgw_parm(handle,
						   "access_key",
						   "");
	if (config_tmp->access_key == NULL) {
		return false;
	}

	config_tmp->secret_access_key = vfs_ceph_rgw_parm(
		handle,
		"secret_access_key",
		"");
	if (config_tmp->secret_access_key == NULL) {
		return false;
	}

	config_tmp->bkt_name = vfs_ceph_rgw_parm(handle,
						 "bucket",
						 "");
	if (config_tmp->bkt_name == NULL) {
		return false;
	}

	config_tmp->debug_enable = lp_parm_bool(SNUM(handle->conn),
						"ceph_rgw",
						"debug",
						"off");

	SMB_VFS_HANDLE_SET_DATA(handle,
				config_tmp,
				NULL,
				struct vfs_ceph_rgw_config,
				return false);

	*config = config_tmp;
	return true;
}

static int vfs_ceph_rgw_connect(struct vfs_handle_struct *handle,
				const char *service,
				const char *user)
{
	struct vfs_ceph_rgw_config *config = NULL;

	bool ok = false;

	ok = vfs_ceph_rgw_load_config(handle, &config);
	if (!ok) {
		return -1;
	}

	ok = vfs_ceph_rgw_mount_bucket(handle->conn, config);
	if (!ok) {
		return -1;
	}

	return 0;
}

static void vfs_ceph_rgw_disconnect(struct vfs_handle_struct *handle)
{
	int ret = 0;
	struct vfs_ceph_rgw_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				return);

	ret = rgw_umount(config->rgw_root_fs, RGW_UMOUNT_FLAG_NONE);
	if (ret < 0) {
		DBG_ERR("[CEPH_RGW] failed to unmount: snum=%d %s\n",
			SNUM(handle->conn),
			strerror(-ret));
	}

	librgw_shutdown(config->rgw_lib_handle);

	TALLOC_FREE(config);
}

static struct smb_filename *vfs_ceph_rgw_realpath(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *ctx,
	const struct smb_filename *smb_fname)
{
	char *result = NULL;
	const char *path = smb_fname->base_name;
	struct smb_filename *result_fname = NULL;

	START_PROFILE_X(SNUM(handle->conn), syscall_realpath);

	result = talloc_strdup(ctx, path);
	if (result == NULL) {
		goto out;
	}

	DBG_NOTICE("[CEPH_RGW] realpath(%p, %s) = %s\n", handle, path, result);
	result_fname = cp_smb_basename(ctx, result);
	TALLOC_FREE(result);
out:
	END_PROFILE_X(syscall_realpath);
	return result_fname;
}

/****************************************************************************
 Return the best approximation to a 'create time' under UNIX from a stat
 structure.
****************************************************************************/

static struct timespec calc_create_time_stat(const struct stat *st)
{
	struct timespec ret, ret1;
	struct timespec c_time = get_ctimespec(st);
	struct timespec m_time = get_mtimespec(st);
	struct timespec a_time = get_atimespec(st);

	ret = timespec_compare(&c_time, &m_time) < 0 ? c_time : m_time;
	ret1 = timespec_compare(&ret, &a_time) < 0 ? ret : a_time;

	if (!null_timespec(ret1)) {
		return ret1;
	}

	/*
	 * One of ctime, mtime or atime was zero (probably atime).
	 * Just return MIN(ctime, mtime).
	 */
	return ret;
}

static void make_create_timespec(const struct stat *pst,
				 struct stat_ex *dst,
				 bool fake_dir_create_times)
{
	if (S_ISDIR(pst->st_mode) && fake_dir_create_times) {
		dst->st_ex_btime.tv_sec = 315493200L; /* 1/1/1980 */
		dst->st_ex_btime.tv_nsec = 0;
		return;
	}

	dst->st_ex_iflags &= ~ST_EX_IFLAG_CALCULATED_BTIME;

#if defined(HAVE_STRUCT_STAT_ST_BIRTHTIMESPEC_TV_NSEC)
	dst->st_ex_btime = pst->st_birthtimespec;
#elif defined(HAVE_STRUCT_STAT_ST_BIRTHTIMENSEC)
	dst->st_ex_btime.tv_sec = pst->st_birthtime;
	dst->st_ex_btime.tv_nsec = pst->st_birthtimenspec;
#elif defined(HAVE_STRUCT_STAT_ST_BIRTHTIME)
	dst->st_ex_btime.tv_sec = pst->st_birthtime;
	dst->st_ex_btime.tv_nsec = 0;
#else
	dst->st_ex_btime = calc_create_time_stat(pst);
	dst->st_ex_iflags |= ST_EX_IFLAG_CALCULATED_BTIME;
#endif

	/* Deal with systems that don't initialize birthtime correctly.
	 * Pointed out by SATOH Fumiyasu <fumiyas@osstech.jp>.
	 */
	if (null_timespec(dst->st_ex_btime)) {
		dst->st_ex_btime = calc_create_time_stat(pst);
		dst->st_ex_iflags |= ST_EX_IFLAG_CALCULATED_BTIME;
	}
}

static void smb_stat_from_ceph_rgw_stat(SMB_STRUCT_STAT *st,
					const struct stat *st_rgw)
{
	ZERO_STRUCTP(st);

	st->st_ex_dev = st_rgw->st_dev;
	st->st_ex_rdev = st_rgw->st_rdev;
	st->st_ex_ino = st_rgw->st_ino;
	st->st_ex_mode = st_rgw->st_mode;
	st->st_ex_uid = st_rgw->st_uid;
	st->st_ex_gid = st_rgw->st_gid;
	st->st_ex_size = st_rgw->st_size;
	st->st_ex_nlink = st_rgw->st_nlink;
	st->st_ex_atime.tv_sec = st_rgw->st_atim.tv_sec;
	st->st_ex_ctime.tv_sec = st_rgw->st_ctim.tv_sec;
	st->st_ex_mtime.tv_sec = st_rgw->st_mtim.tv_sec;
	make_create_timespec(st_rgw, st, false);
	st->st_ex_blksize = st_rgw->st_blksize;
	st->st_ex_blocks = st_rgw->st_blocks;
}

static int vfs_ceph_rgw_stat(struct vfs_handle_struct *handle,
			     struct smb_filename *smb_fname)
{
	int result = -ENOMEM;
	struct vfs_ceph_rgw_config *config = NULL;
	struct stat st = {0};

	START_PROFILE_X(SNUM(handle->conn), syscall_stat);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);

	if (strlen(smb_fname->base_name) == 1) {
		if ((strncmp(smb_fname->base_name, ".", 1) == 0) ||
		    (strncmp(smb_fname->base_name, "/", 1) == 0))
		{
			result = rgw_getattr(config->rgw_root_fs,
					     config->rgw_root_fh,
					     &st,
					     RGW_GETATTR_FLAG_NONE);
			if (result < 0) {
				DBG_ERR("[CEPH_RGW] Unable to get attr for "
					"[%s]. "
					"rc = %d\n",
					smb_fname->base_name,
					result);
				goto out;
			}
			smb_stat_from_ceph_rgw_stat(&smb_fname->st, &st);
			goto out;
		}
	}

	if (smb_fname->stream_name) {
		result = -ENOENT;
		goto out;
	}

	result = rgw_getattr(config->rgw_root_fs,
			     config->rgw_root_fh,
			     &st,
			     RGW_GETATTR_FLAG_NONE);
	if (result < 0) {
		DBG_ERR("[CEPH_RGW] Unable to get attr for [%s]. rc = %d\n",
			smb_fname->base_name,
			result);
		goto out;
	}

	DBG_NOTICE("[CEPH_RGW] stat: [%s] Success.\n", smb_fname->base_name);
	smb_stat_from_ceph_rgw_stat(&smb_fname->st, &st);
out:
	END_PROFILE_X(syscall_stat);
	return status_code(result);
}

/*
 * librgw do not have concept of current working directory.
 * Thus we just perform a lookup if its not same as bucket name.
 */

static int vfs_ceph_rgw_chdir(struct vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname)
{
	int rc = 0;
	START_PROFILE_X(SNUM(handle->conn), syscall_chdir);
	DBG_NOTICE("[CEPH_RGW] chdir is for %s\n", smb_fname->base_name);
	END_PROFILE_X(syscall_chdir);
	return status_code(rc);
#if 0
	int rc = -1;
	struct vfs_ceph_rgw_config *config = NULL;
	struct rgw_file_handle *rgw_fh = NULL;
	const char *path = smb_fname->base_name;
	struct stat st = {0};

	START_PROFILE_X(SNUM(handle->conn), syscall_chdir);
	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_rgw_config,
				return -ENOMEM);

	DBG_NOTICE("[CEPH_RGW] chdir called with path=%s\n", path);

	len = strlen(path);

	if (path[0] == '/') {
		path++;
	}

	/* Return success, if chdir path is bucket itself */
	if (strncmp(config->bkt_name, path, strlen(config->bkt_name)) == 0) {
		rc = 0;
		goto out;
	}

	rc = rgw_lookup(config->rgw_root_fs,
			config->rgw_root_fh,
			path,
			&rgw_fh,
			&st,
			0,
			RGW_LOOKUP_TYPE_FLAGS);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Error changing dir to %s. rc=%d\n",
			path, rc);
	} else {
		/* release handle returned by lookup operation */
		(void)rgw_fh_rele(config->rgw_root_fs,
				  rgw_fh,
				  RGW_FH_RELE_FLAG_NONE);
	}

out:
	END_PROFILE_X(syscall_chdir);
	return status_code(rc);
#endif
}

static struct smb_filename *vfs_ceph_rgw_getwd(struct vfs_handle_struct *handle,
					       TALLOC_CTX *ctx)
{
	const char *cwd = "/";

	START_PROFILE_X(SNUM(handle->conn), syscall_getwd);
	END_PROFILE_X(syscall_getwd);
	return cp_smb_basename(ctx, cwd);
}


static void vfs_ceph_rgw_put_fh_dirent(struct vfs_ceph_rgw_fh *cfh)
{
}

static int vfs_ceph_rgw_release_fh(struct vfs_ceph_rgw_fh *cfh)
{
	int ret = 0;

	/* TODO: call release/close function? */
	vfs_ceph_rgw_put_fh_dirent(cfh);
	cfh->fd = -1;

	return ret;
}

static void vfs_ceph_rgw_fsp_ext_destroy_cb(void *p_data)
{
	vfs_ceph_rgw_release_fh((struct vfs_ceph_rgw_fh *)p_data);
}

static int vfs_ceph_rgw_add_fh(struct vfs_handle_struct *handle,
			       files_struct *fsp,
			       struct vfs_ceph_rgw_fh **out_cfh)
{
	struct vfs_ceph_rgw_config *config = NULL;
	int ret = -ENOMEM;
	char *name = NULL;

	name = normalise_name(talloc_tos(), fsp_name(fsp));
	if (name == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for name\n");
		goto out;
	}

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);

	*out_cfh = VFS_ADD_FSP_EXTENSION(handle,
					 fsp,
					 struct vfs_ceph_rgw_fh,
					 vfs_ceph_rgw_fsp_ext_destroy_cb);
	if (*out_cfh == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	(*out_cfh)->fsp = fsp;
	(*out_cfh)->config = config;
	(*out_cfh)->fd = -1;
	ret = 0;
out:
	DBG_NOTICE("[CEPH_RGW] vfs_ceph_add_fh: name = %s ret = %d\n",
		   name,
		   ret);
	TALLOC_FREE(name);
	return ret;
}

static void vfs_ceph_rgw_remove_fh(struct vfs_handle_struct *handle,
				   struct files_struct *fsp)
{
	VFS_REMOVE_FSP_EXTENSION(handle, fsp);
}

static int vfs_ceph_rgw_fetch_fh(struct vfs_handle_struct *handle,
				 const struct files_struct *fsp,
				 struct vfs_ceph_rgw_fh **out_cfh)
{
	int ret = 0;
	*out_cfh = VFS_FETCH_FSP_EXTENSION(handle, fsp);
	ret = (*out_cfh == NULL) ? -EBADF : 0;
	DBG_NOTICE("[CEPH_RGW] vfs_ceph_fetch_fh: name = %s ret = %d\n",
		   fsp_name(fsp),
		   ret);
	return ret;
}

static int vfs_ceph_rgw_fetch_io_fh(struct vfs_handle_struct *handle,
				    const struct files_struct *fsp,
				    struct vfs_ceph_rgw_fh **out_cfh)
{
	int ret = 0;

	*out_cfh = VFS_FETCH_FSP_EXTENSION(handle, fsp);
	ret = (*out_cfh == NULL) || ((*out_cfh)->rgw_fh == NULL) ? -EBADF : 0;
	DBG_DEBUG("[CEPH_RGW] vfs_ceph_rgw_fetch_io_fh: name='%s' ret=%d\n",
		  fsp_str_dbg(fsp),
		  ret);
	return ret;
}

static int vfs_ceph_rgw_openat(struct vfs_handle_struct *handle,
			       const struct files_struct *dirfsp,
			       const struct smb_filename *smb_fname,
			       files_struct *fsp,
			       const struct vfs_open_how *how)
{
	int rc = -ENOMEM;
	struct vfs_ceph_rgw_fh *newfh = NULL;
	struct rgw_file_handle *rgw_fh = NULL;
	struct vfs_ceph_rgw_config *config = NULL;
	struct stat st = {0};
	int flags = how->flags;
	mode_t mode = how->mode;
	uint32_t mask = RGW_SETATTR_UID | RGW_SETATTR_GID | RGW_SETATTR_MODE;
	bool skip_open = false;
	uint32_t file_type = 0;
	const struct security_unix_token *utok = NULL;
	char *open_name = NULL;

	START_PROFILE_X(SNUM(handle->conn), syscall_openat);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);

	utok = get_current_utok(handle->conn);

	open_name = normalise_name(talloc_tos(), fsp_name(fsp));
	if (open_name == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for name\n");
		rc = -ENOMEM;
		goto out;
	}

	DBG_NOTICE("[CEPH_RGW] base_name=[%s] dir->name=[%s] "
		   "fsp->name=[%s] open_name=[%s]\n",
		   smb_fname->base_name,
		   fsp_name(dirfsp),
		   fsp_name(fsp),
		   open_name);

	if (strlen(open_name) == 0) {
		skip_open = true;
	}

	rc = vfs_ceph_rgw_fetch_fh(handle, fsp, &newfh);
	if (rc != 0) {
		/* We do not found any handle, so this is new open
		 * create handle and add.
		 */

		rc = vfs_ceph_rgw_add_fh(handle, fsp, &newfh);
		if (rc < 0) {
			DBG_ERR("Unable to add handle. rc=%d\n", rc);
			goto out;
		}
		newfh->fd = cephrgw_next_fd(config);
	}

	if (skip_open) {
		DBG_NOTICE("[CEPH_RGW] Skipping open\n");
		newfh->rgw_fh = config->rgw_root_fh;
		rc = newfh->fd;
		goto out;
	}

	if (flags & O_CREAT) {
		st.st_uid = utok->uid;
		st.st_gid = utok->gid;
		st.st_mode = mode;
		DBG_NOTICE("[CEPH_RGW] create file: uid = %u gid = %u mode = "
			   "%u flags = %u\n",
			   utok->uid,
			   utok->gid,
			   mode,
			   flags);

		rc = rgw_create(config->rgw_root_fs,
				config->rgw_root_fh,
				open_name,
				&st,
				mask,
				&rgw_fh,
				flags,
				RGW_CREATE_FLAG_NONE);
		if (rc < 0) {
			vfs_ceph_rgw_remove_fh(handle, fsp);
			DBG_ERR("[CEPH_RGW] Error creating [%s]. rc = %d\n",
				open_name,
				rc);
			goto out;
		}
		newfh->rgw_fh = rgw_fh;
		DBG_NOTICE("[CEPH_RGW] In create [%s]. rgw_fh=%p\n",
			   open_name,
			   rgw_fh);
	} else {
		DBG_NOTICE("[CEPH_RGW] Before lookup [%s]. newfh->rgw_fh=%p\n",
			   fsp_name(fsp),
			   newfh->rgw_fh);
		rc = rgw_lookup(config->rgw_root_fs,
				config->rgw_root_fh,
				open_name,
				&rgw_fh,
				&st,
				flags,
				RGW_LOOKUP_TYPE_FLAGS);
		if (rc < 0) {
			vfs_ceph_rgw_remove_fh(handle, fsp);
			DBG_ERR("[CEPH_RGW] Error looking up [%s]. rc = %d\n",
				open_name,
				rc);
			goto out;
		}
		DBG_NOTICE("[CEPH_RGW] After lookup [%s]. uid=%u gid=%u\n",
			   fsp_name(fsp),
			   st.st_uid,
			   st.st_gid);
		file_type = st.st_mode & S_IFMT;
		if (file_type == S_IFREG) {
			rc = rgw_open(config->rgw_root_fs,
				      rgw_fh,
				      flags,
				      RGW_OPEN_FLAG_NONE);
			if (rc < 0) {
				vfs_ceph_rgw_remove_fh(handle, fsp);
				DBG_ERR("[CEPH_RGW] Unable to open [%s]. rc = "
					"%d\n",
					open_name,
					rc);
				goto out;
			}
			DBG_NOTICE("[CEPH_RGW] After open [%s]. rgw_fh=%p\n",
				   open_name,
				   rgw_fh);
		}
		newfh->rgw_fh = rgw_fh;

		rc = rgw_fh_rele(config->rgw_root_fs,
				rgw_fh,
				RGW_FH_RELE_FLAG_NONE);
		if (rc < 0) {
			vfs_ceph_rgw_remove_fh(handle, fsp);
			DBG_ERR("[CEPH_RGW] Error releasing handle [%s]. rc = "
				"%d\n",
				open_name,
				rc);
			goto out;
		}
		rc = newfh->fd;
	}
	newfh->o_flags = flags;

	DBG_NOTICE("[CEPH_RGW] openat: [%s] success\n", open_name);
out:
	TALLOC_FREE(open_name);
	END_PROFILE_X(syscall_openat);
	return status_code(rc);
}

static int vfs_ceph_rgw_close(struct vfs_handle_struct *handle,
			      files_struct *fsp)
{
	int rc = -ENOMEM;
	struct vfs_ceph_rgw_fh *openfh = NULL;
	struct vfs_ceph_rgw_config *config = NULL;
	START_PROFILE_X(SNUM(handle->conn), syscall_close);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);

	DBG_NOTICE("[CEPH_RGW] close is for [%s]\n", fsp_name(fsp));
	if (strlen(fsp_name(fsp)) == 1) {
		if ((strncmp(fsp_name(fsp), ".", 1) == 0) ||
		    (strncmp(fsp_name(fsp), "/", 1) == 0))
		{
			vfs_ceph_rgw_remove_fh(handle, fsp);
			rc = 0;
			goto out;
		}
	}

	if (strlen(fsp_name(fsp)) == 0) {
		vfs_ceph_rgw_remove_fh(handle, fsp);
		rc = 0;
		goto out;
	}

	rc = vfs_ceph_rgw_fetch_fh(handle, fsp, &openfh);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to find open handle for %s. rc=%d\n",
			fsp_name(fsp),
			rc);
		goto out;
	}

	rc = rgw_close(config->rgw_root_fs,
		       openfh->rgw_fh,
		       RGW_CLOSE_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to close [%s]. rc = %d\n",
			fsp_name(fsp),
			rc);
		goto err_out;
	}

	DBG_NOTICE("[CEPH_RGW] close: [%s] success\n", fsp_name(fsp));

err_out:
	vfs_ceph_rgw_remove_fh(handle, fsp);
out:
	END_PROFILE_X(syscall_close);
	return status_code(rc);
}

static int vfs_ceph_rgw_fstat(struct vfs_handle_struct *handle,
			      files_struct *fsp,
			      SMB_STRUCT_STAT *sbuf)
{
	int rc = -ENOMEM;
	struct vfs_ceph_rgw_fh *openfh = NULL;
	struct vfs_ceph_rgw_config *config = NULL;
	struct stat st = {0};

	START_PROFILE_X(SNUM(handle->conn), syscall_fstatat);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);
#if 0
	if (strlen(fsp_name(fsp)) == 1) {
		if ((strncmp(fsp_name(fsp), ".", 1) == 0) ||
		    (strncmp(fsp_name(fsp), "/", 1) == 0)) {
			rc = rgw_getattr(config->rgw_root_fs,
					 config->rgw_root_fh,
					 &st,
					 RGW_GETATTR_FLAG_NONE);
			if (rc < 0) {
				goto out;
			}
			smb_stat_from_ceph_rgw_stat(sbuf, &st);
			goto out;
		}
	}
#endif

	DBG_NOTICE("[CEPH_RGW] fstatat: name [%s]\n", fsp_name(fsp));

	rc = vfs_ceph_rgw_fetch_fh(handle, fsp, &openfh);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to find open handle for %s. rc=%d\n",
			fsp_name(fsp),
			rc);
		goto out;
	}

	rc = rgw_getattr(config->rgw_root_fs,
			 openfh->rgw_fh,
			 &st,
			 RGW_GETATTR_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to stat [%s]. rc=%d\n",
			fsp_name(fsp),
			rc);
		goto out;
	}

	DBG_NOTICE("[CEPH_RGW] fstatat: [%s] success\n", fsp_name(fsp));
	smb_stat_from_ceph_rgw_stat(sbuf, &st);

out:
	END_PROFILE_X(syscall_fstatat);
	return status_code(rc);
}

#if 0
struct vfs_ceph_rgw_dir {
	int pos;
	int num;
	struct dirent *dirs;
};
#endif

struct vfs_ceph_rgw_rd_arg {
	struct vfs_ceph_rgw_dir *dirp;
	void *ctx;
	bool eof;
};

static int vfs_ceph_rgw_rd_cb(const char *name,
			      void *arg,
			      uint64_t offset,
			      struct stat *st,
			      uint32_t mask,
			      uint32_t flags)
{
	struct vfs_ceph_rgw_rd_arg *cb_arg = (struct vfs_ceph_rgw_rd_arg *)arg;
	struct dirent *d = NULL;
	struct vfs_ceph_rgw_dir *dirp = cb_arg->dirp;

	DBG_NOTICE("[CEPH_RGW]: Object-name: %s offset=%lu mask=%u flags=%u\n",
		   name,
		   offset,
		   mask,
		   flags);

	if (cb_arg->eof == true) {
		/* Its end of dir listing, return 0 */
		return 0;
	}

	dirp->dirs = talloc_realloc(cb_arg->ctx,
				    dirp->dirs,
				    struct dirent,
				    dirp->num + 1);
	if (dirp->dirs == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for dir entries\n");
		return 0;
	}

	/* prepare dentry */
	d = &dirp->dirs[dirp->num];
	d->d_ino = st->st_ino;
	d->d_off = dirp->pos;
	d->d_reclen = strlen(name);
	if (flags & DT_DIR) {
		d->d_type = DT_DIR;
	} else if (flags & DT_REG) {
		d->d_type = DT_REG;
	} else {
		d->d_type = DT_UNKNOWN;
	}
	strncpy(d->d_name, name, sizeof(d->d_name) - 1);
	dirp->num += 1;

	/* Since its not end of dir listing, return non-zero value to continue
	 * listing.
	 */
	return 1;
}

static DIR *vfs_ceph_rgw_fdopendir(vfs_handle_struct *handle,
				   files_struct *fsp,
				   const char *mask,
				   uint32_t attr)
{
	int rc = 0;
	struct vfs_ceph_rgw_dir *dirp = NULL;
	struct vfs_ceph_rgw_fh *openfh = NULL;
	struct vfs_ceph_rgw_config *config = NULL;
	const char *r_whence = NULL;
	struct vfs_ceph_rgw_rd_arg *cb_arg = NULL;
	START_PROFILE_X(SNUM(handle->conn), syscall_fdopendir);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);

	DBG_NOTICE("[CEPH_RGW] fdopendir: name [%s]\n", fsp_name(fsp));

	rc = vfs_ceph_rgw_fetch_fh(handle, fsp, &openfh);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to find open handle for %s. rc=%d\n",
			fsp_name(fsp),
			rc);
		goto out;
	}

	/* We might not need this */
#if 0
	rc = rgw_getattr(config->rgw_root_fs,
			 openfh,
			 &st,
			 RGW_GETATTR_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to get attr for [%s]. rc = %d\n",
			fsp_name(fsp), rc);
		goto out;
	}
#endif

	dirp = talloc_zero(handle->conn, struct vfs_ceph_rgw_dir);
	if (dirp == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for dir info.");
		goto out;
	}

	cb_arg = talloc(handle->conn, struct vfs_ceph_rgw_rd_arg);
	if (cb_arg == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for cb arg\n");
		goto out;
		return NULL;
	}
	cb_arg->dirp = dirp;
	cb_arg->eof = false;
	cb_arg->ctx = handle->conn;

	rc = rgw_readdir2(config->rgw_root_fs,
			  openfh->rgw_fh,
			  r_whence,
			  vfs_ceph_rgw_rd_cb,
			  cb_arg,
			  &cb_arg->eof,
			  RGW_READDIR_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] readdir faild. rc=%d\n", rc);
		goto out;
	}

	TALLOC_FREE(cb_arg);
	DBG_NOTICE("[CEPH_RGW] fdopendir: [%s] success.\n", fsp_name(fsp));

out:
	END_PROFILE_X(syscall_fdopendir);
	return (DIR *)dirp;
}

static int vfs_ceph_rgw_closedir(struct vfs_handle_struct *handle, DIR *dirp)
{
	int rc = 0;
	START_PROFILE_X(SNUM(handle->conn), syscall_closedir);

	DBG_NOTICE("[CEPH_RGW] closedir: dirp=%p\n", dirp);

	END_PROFILE_X(syscall_closedir);
	return status_code(rc);
}

static struct dirent *vfs_ceph_rgw_readdir(struct vfs_handle_struct *handle,
					   struct files_struct *dirfsp,
					   DIR *dirp)
{
	struct dirent *ret = NULL;
	struct vfs_ceph_rgw_dir *rgw_dirp = (struct vfs_ceph_rgw_dir *)dirp;
	START_PROFILE_X(SNUM(handle->conn), syscall_readdir);

	if (rgw_dirp == NULL) {
		/* TODO: Why would this happen */
		DBG_NOTICE("rgw_dirp is NULL for [%s]\n", fsp_name(dirfsp));
		ret = NULL;
		goto out;
	}

	DBG_NOTICE("[CEPH_RGW] readdir: name [%s]\n", fsp_name(dirfsp));

	if (rgw_dirp->pos < rgw_dirp->num) {
		ret = (struct dirent *)&rgw_dirp->dirs[rgw_dirp->pos++];
	}
	DBG_NOTICE("[CEPH_RGW] readdir: [%s] success.\n", fsp_name(dirfsp));
out:
	END_PROFILE_X(syscall_readdir);
	return ret;
}

static void vfs_ceph_rgw_rewinddir(struct vfs_handle_struct *handle, DIR *dirp)
{
	struct vfs_ceph_rgw_dir *rgw_dirp = (struct vfs_ceph_rgw_dir *)dirp;
	START_PROFILE_X(SNUM(handle->conn), syscall_rewinddir);

	if (rgw_dirp == NULL) {
		/* TODO: Why would this happen */
		DBG_NOTICE("rgw_dirp is NULL for in rewinddir\n");
		goto out;
	}

	rgw_dirp->pos = 0;
out:
	END_PROFILE_X(syscall_rewinddir);
	return;
}

static NTSTATUS vfs_ceph_rgw_get_real_filename_at(
	struct vfs_handle_struct *handle,
	struct files_struct *dirfsp,
	const char *name,
	TALLOC_CTX *mem_ctx,
	char **found_name)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static int vfs_ceph_rgw_fcntl(vfs_handle_struct *handle,
			      files_struct *fsp,
			      int cmd,
			      va_list cmd_arg)
{
	int result = 0;

	START_PROFILE_X(SNUM(handle->conn), syscall_fcntl);
	/*
	 * SMB_VFS_FCNTL() is currently only called by vfs_set_blocking() to
	 * clear O_NONBLOCK, etc for LOCK_MAND and FIFOs. Ignore it.
	 */
	if (cmd == F_GETFL) {
		goto out;
	} else if (cmd == F_SETFL) {
		va_list dup_cmd_arg;
		int opt;

		va_copy(dup_cmd_arg, cmd_arg);
		opt = va_arg(dup_cmd_arg, int);
		va_end(dup_cmd_arg);
		if (opt == 0) {
			goto out;
		}
		DBG_ERR("[CEPH_RGW] unexpected fcntl SETFL(%d)\n", opt);
		goto err_out;
	}
	DBG_ERR("[CEPH_RGW] unexpected fcntl: %d\n", cmd);
err_out:
	result = -1;
	errno = EINVAL;
out:
	END_PROFILE_X(syscall_fcntl);
	return result;
}

static int vfs_ceph_rgw_mkdirat(struct vfs_handle_struct *handle,
				files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				mode_t mode)
{
	int rc = -ENOMEM;
	uint32_t mask = RGW_SETATTR_UID | RGW_SETATTR_GID | RGW_SETATTR_MODE;
	struct vfs_ceph_rgw_fh *dircfh = NULL;
	struct rgw_file_handle *rgw_fh = NULL;
	struct vfs_ceph_rgw_config *config = NULL;
	const struct security_unix_token *utok = NULL;
	struct stat st = {0};
	char *name = NULL;
	char *abs_path = NULL;
	START_PROFILE_X(SNUM(handle->conn), syscall_mkdirat);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);

	/* Get abs name */
	abs_path = normalise_name(talloc_tos(), fsp_name(dirfsp));
	if (abs_path == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for abs path\n");
		goto out;
	}

	/* Prepare dir name, i.e. add '/' to end of dir name */
	if (strlen(abs_path) != 0) {
		name = talloc_asprintf(talloc_tos(),
			       "%s/%s/",
			       abs_path,
			       smb_fname->base_name);
	} else {
		name = talloc_asprintf(talloc_tos(),
			       "%s/",
			       smb_fname->base_name);
	}

	if (name == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for dir name\n");
		goto out;
	}

	DBG_NOTICE("[CEPH_RGW] mkdirat: name [%s]\n", name);
	rc = vfs_ceph_rgw_fetch_fh(handle, dirfsp, &dircfh);
	if (rc != 0) {
		DBG_ERR("[CEPH_RGW] Unable to locate dir handle for [%s]\n",
			fsp_name(dirfsp));
		goto out;
	}

	utok = get_current_utok(handle->conn);
	st.st_uid = utok->uid;
	st.st_gid = utok->gid;
	if (mode == 0) {
		mask &= ~RGW_SETATTR_MODE;
	} else {
		st.st_mode = mode;
	}
	DBG_NOTICE("[CEPH_RGW] mkdirat: uid = %u gid = %u mode = %u\n",
		   utok->uid,
		   utok->gid,
		   mode);

	rc = rgw_create(config->rgw_root_fs,
			config->rgw_root_fh,
			name,
			&st,
			mask,
			&rgw_fh,
			mode,
			RGW_CREATE_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Error creating [%s]. rc = %d\n",
			name,
			rc);
		goto out;
	}

	DBG_NOTICE("[CEPH_RGW] mkdirat: [%s] success. mode = %u\n",
		   name, st.st_mode);
out:
	TALLOC_FREE(abs_path);
	TALLOC_FREE(name);
	END_PROFILE_X(syscall_mkdirat);
	return status_code(rc);
}


#if 0
static int vfs_ceph_rgw_mkdirat(struct vfs_handle_struct *handle,
				files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				mode_t mode)
{
	int rc = -1;
	uint32_t mask = RGW_SETATTR_UID | RGW_SETATTR_GID | RGW_SETATTR_MODE;
	const char *name = smb_fname->base_name;
	struct vfs_ceph_rgw_fh *dircfh = NULL;
	struct rgw_file_handle *rgw_fh = NULL;
	struct vfs_ceph_rgw_config *config = NULL;
	const struct security_unix_token *utok = NULL;
	struct stat st = {0};
	START_PROFILE_X(SNUM(handle->conn), syscall_mkdirat);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				return -1);

	DBG_NOTICE("[CEPH_RGW] mkdirat: name [%s]\n", name);
	rc = vfs_ceph_rgw_fetch_fh(handle, dirfsp, &dircfh);
	if (rc != 0) {
		DBG_ERR("[CEPH_RGW] Unable to locate dir handle for [%s]\n",
			fsp_name(dirfsp));
		goto out;
	}

	utok = get_current_utok(handle->conn);
	st.st_uid = utok->uid;
	st.st_gid = utok->gid;
	st.st_mode = mode;
	DBG_NOTICE("[CEPH_RGW] mkdirat: uid = %u gid = %u mode = %u\n",
		   utok->uid,
		   utok->gid,
		   mode);

	rc = rgw_mkdir(config->rgw_root_fs,
		       dircfh->rgw_fh,
		       name,
		       &st,
		       mask,
		       &rgw_fh,
		       RGW_MKDIR_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to create directory [%s]. rc=%d\n",
			name,
			rc);
		goto out;
	}

	rc = rgw_fh_rele(config->rgw_root_fs,
			 rgw_fh,
			 RGW_FH_RELE_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Error release handle for [%s]. rc=%d\n",
			name,
			rc);
		goto out;
	}
	DBG_NOTICE("[CEPH_RGW] mkdirat: [%s] success.\n", name);
out:
	END_PROFILE_X(syscall_mkdirat);
	return status_code(rc);
}
#endif

static int vfs_ceph_rgw_renameat(struct vfs_handle_struct *handle,
				 files_struct *src_dirfsp,
				 const struct smb_filename *smb_fname_src,
				 files_struct *dst_dirfsp,
				 const struct smb_filename *smb_fname_dst,
				 const struct vfs_rename_how *how)
{
	int rc = -ENOMEM;
	struct vfs_ceph_rgw_fh *src_dircfh = NULL;
	struct vfs_ceph_rgw_fh *dst_dircfh = NULL;
	struct vfs_ceph_rgw_config *config = NULL;
	char *src_name = NULL;
	char *dst_name = NULL;
	char *src_abs_path = NULL;
	char *dst_abs_path = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	START_PROFILE_X(SNUM(handle->conn), syscall_renameat);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);
	DBG_NOTICE("[CEPH_RGW] renameat: src [%s] dst [%s]\n",
		   smb_fname_src->base_name,
		   smb_fname_dst->base_name);

	if (smb_fname_src->stream_name || smb_fname_dst->stream_name) {
		DBG_ERR("[CEPH_RGW] rename out#1\n");
		rc = -ENOENT;
		goto out;
	}

	if (how->flags != 0) {
		DBG_ERR("[CEPH_RGW] rename out#2. how->flags=%u\n", how->flags);
		rc = -EINVAL;
		goto out;
	}

	rc = vfs_ceph_rgw_fetch_fh(handle, src_dirfsp, &src_dircfh);
	if (rc != 0) {
		DBG_NOTICE("[CEPH_RGW] failed to fetch file handle for [%s]\n",
			   smb_fname_src->base_name);
		goto out;
	}

	rc = vfs_ceph_rgw_fetch_fh(handle, dst_dirfsp, &dst_dircfh);
	if (rc != 0) {
		DBG_NOTICE("[CEPH_RGW] failed to fetch file handle for [%s]\n",
			   smb_fname_dst->base_name);
		goto out;
	}

	/* Dir names must end with '/' */
	src_abs_path = normalise_name(ctx, fsp_name(src_dirfsp));
	dst_abs_path = normalise_name(ctx, fsp_name(dst_dirfsp));
	if (src_abs_path == NULL || dst_abs_path == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory\n");
		rc = -ENOMEM;
		goto out;
	}

	if (src_dirfsp->fsp_flags.is_directory) {
		if (strlen(src_abs_path) != 0) {
			src_name = talloc_asprintf(ctx,
						   "%s/%s/",
						   src_abs_path,
						   smb_fname_src->base_name);
		} else {
			src_name = talloc_asprintf(ctx,
						   "%s/",
						   smb_fname_src->base_name);
		}
	} else {
		if (strlen(src_abs_path) != 0) {
			src_name = talloc_asprintf(ctx,
					"%s/%s",
					src_abs_path,
					smb_fname_src->base_name);
		} else {
			src_name = talloc_asprintf(ctx,
					"%s",
					smb_fname_src->base_name);
		}
	}

	if (dst_dirfsp->fsp_flags.is_directory) {
		if (strlen(dst_abs_path) != 0) {
			dst_name = talloc_asprintf(ctx,
					"%s/%s/",
					dst_abs_path,
					smb_fname_dst->base_name);
		} else {
			dst_name = talloc_asprintf(ctx,
					"%s/",
					smb_fname_dst->base_name);
		}
	} else {
		if (strlen(dst_abs_path) != 0) {
		dst_name = talloc_asprintf(ctx,
					   "%s/%s",
					   dst_abs_path,
					   smb_fname_dst->base_name);
		} else {
			dst_name = talloc_asprintf(ctx,
					"%s",
					smb_fname_dst->base_name);
		}
	}

	if (src_name == NULL || dst_name == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for filenames\n");
		rc = -ENOMEM;
		goto out;
	}

	rc = rgw_rename(config->rgw_root_fs,
			config->rgw_root_fh,
			src_name,
			config->rgw_root_fh,
			dst_name,
			RGW_RENAME_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW]: Unable to rename [%s] to [%s]. rc=%d\n",
			smb_fname_src->base_name,
			smb_fname_dst->base_name,
			rc);
		goto out;
	}

	DBG_NOTICE("[CEPH_RGW]: rename [%s]->[%s] success\n",
		   smb_fname_src->base_name,
		   smb_fname_dst->base_name);
out:
	TALLOC_FREE(ctx);
	END_PROFILE_X(syscall_renameat);
	return status_code(rc);
}

static int vfs_ceph_rgw_unlinkat(struct vfs_handle_struct *handle,
				 struct files_struct *dirfsp,
				 const struct smb_filename *smb_fname,
				 int flags)
{
	int rc = -ENOMEM;
	struct vfs_ceph_rgw_fh *dircfh = NULL;
	struct vfs_ceph_rgw_config *config = NULL;
	const char *name = smb_fname_str_dbg(smb_fname);

	START_PROFILE_X(SNUM(handle->conn), syscall_unlinkat);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);

	if (smb_fname->stream_name) {
		DBG_ERR("[CEPH_RGW] unlinkat out#1\n");
		rc = -ENOENT;
		goto out;
	}

	rc = vfs_ceph_rgw_fetch_fh(handle, dirfsp, &dircfh);
	if (rc != 0) {
		DBG_ERR("Unable to get handle for [%s]\n", fsp_name(dirfsp));
		goto out;
	}

	rc = rgw_unlink(config->rgw_root_fs,
			dircfh->rgw_fh,
			name,
			RGW_UNLINK_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("Unable to unlink [%s]. rc = %d\n", name, rc);
		goto out;
	}
	DBG_NOTICE("[CEPH_RGW] unlinkat: name=%s success\n", name);
out:
	END_PROFILE_X(syscall_unlinkat);
	return status_code(rc);
}

static ssize_t vfs_ceph_rgw_pread(struct vfs_handle_struct *handle,
				  files_struct *fsp,
				  void *data,
				  size_t n,
				  off_t offset)
{
	int rc;
	ssize_t bytes_read = -1;
	struct vfs_ceph_rgw_config *config = NULL;
	struct vfs_ceph_rgw_fh *cfh = NULL;

	START_PROFILE_BYTES_X(SNUM(handle->conn), syscall_pread, n);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);

	rc = vfs_ceph_rgw_fetch_fh(handle, fsp, &cfh);
	if (rc != 0) {
		DBG_ERR("[CEPH_RGW] Unable to fetch handle for [%s]\n",
			fsp_name(fsp));
		goto out;
	}

	rc = rgw_read(config->rgw_root_fs,
		      cfh->rgw_fh,
		      offset,
		      n,
		      (size_t *)&bytes_read,
		      data,
		      RGW_READ_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Read failed for [%s]. rc = %d\n",
			fsp_name(fsp),
			rc);
		goto out;
	}
out:
	DBG_DEBUG("[CEPH] pread: handle=%p name=%s n=%" PRIu64 "offset=%" PRIu64
		  " bytes_read=%" PRIu64 "\n",
		  handle,
		  fsp_str_dbg(fsp),
		  n,
		  (intmax_t)offset,
		  bytes_read);
	END_PROFILE_BYTES_X(syscall_pread);
	return lstatus_code(bytes_read);
}

static ssize_t vfs_ceph_rgw_pwrite(struct vfs_handle_struct *handle,
				   files_struct *fsp,
				   const void *data,
				   size_t n,
				   off_t offset)
{
	int rc = 0;
	ssize_t bytes_written = -1;
	struct vfs_ceph_rgw_fh *cfh = NULL;
	struct vfs_ceph_rgw_config *config = NULL;
	void *buffer = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	START_PROFILE_BYTES_X(SNUM(handle->conn), syscall_pwrite, n);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);

	DBG_NOTICE("[CEPH_RGW] write: [%s]\n", fsp_name(fsp));

	rc = vfs_ceph_rgw_fetch_fh(handle, fsp, &cfh);
	if (rc != 0) {
		DBG_ERR("[CEPH_RGW] Unable to fetch hande for [%s]\n",
			fsp_name(fsp));
		goto out;
	}

	buffer = talloc_memdup(ctx, data, n);
	if (buffer == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for write op\n");
		goto out;
	}

	rc = rgw_open(config->rgw_root_fs,
		      cfh->rgw_fh,
		      cfh->o_flags,
		      RGW_OPEN_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to open %s for write\n",
			fsp_name(fsp));
		goto out;
	}

	rc = rgw_write(config->rgw_root_fs,
		       cfh->rgw_fh,
		       offset,
		       n,
		       (size_t *)&bytes_written,
		       buffer,
		       RGW_OPEN_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Error writing to [%s]. rc = %d\n",
			fsp_name(fsp),
			rc);
		goto out;
	}
out:
	TALLOC_FREE(ctx);
	DBG_NOTICE("[CEPH_RGW] pwrite: name=%s "
		   "n=%" PRIu64 " offset=%" PRIu64 " bytes_written=%" PRIu64
		   "\n",
		   fsp_str_dbg(fsp),
		   n,
		   (intmax_t)offset,
		   bytes_written);
	END_PROFILE_BYTES_X(syscall_pwrite);
	return lstatus_code(bytes_written);
}

static int vfs_ceph_rgw_ftruncate(struct vfs_handle_struct *handle,
				  files_struct *fsp,
				  off_t len)
{
	int rc = -ENOMEM;
	struct vfs_ceph_rgw_fh *fh = NULL;
	struct vfs_ceph_rgw_config *config = NULL;

	START_PROFILE_X(SNUM(handle->conn), syscall_ftruncate);

	DBG_DEBUG("[CEPH_RGW] ftruncate: name='%s' len=%zd\n",
		  fsp_str_dbg(fsp),
		  (intmax_t)len);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);

	rc = vfs_ceph_rgw_fetch_fh(handle, fsp, &fh);
	if (rc != 0) {
		goto out;
	}

	rc = rgw_truncate(config->rgw_root_fs,
			  fh->rgw_fh,
			  (uint64_t)len,
			  RGW_TRUNCATE_FLAG_NONE);
out:
	DBG_DEBUG("[CEPH_RGW] ftruncate done: name=%s len=%zd rc=%d\n",
		  fsp_str_dbg(fsp),
		  (intmax_t)len,
		  rc);
	END_PROFILE_X(syscall_ftruncate);
	return status_code(rc);
}

struct vfs_ceph_rgw_aio_state {
	struct vfs_ceph_rgw_config *config;
	struct vfs_ceph_rgw_fh *fh;
	size_t len;
	off_t off;
	struct timespec start_time;
	struct timespec finish_time;
	ssize_t result;
	struct vfs_aio_state vfs_aio_state;
	SMBPROFILE_BYTES_ASYNC_STATE_X(profile_bytes, profile_bytes_x);
};

static void vfs_ceph_rgw_aio_start(struct vfs_ceph_rgw_aio_state *state)
{
	SMBPROFILE_BYTES_ASYNC_SET_BUSY_X(state->profile_bytes,
					  state->profile_bytes_x);
	PROFILE_TIMESTAMP(&state->start_time);
}

static void vfs_ceph_rgw_aio_finish(struct vfs_ceph_rgw_aio_state *state,
				    ssize_t result)
{
	PROFILE_TIMESTAMP(&state->finish_time);
	state->vfs_aio_state.duration = nsec_time_diff(&state->finish_time,
						       &state->start_time);
	if (result < 0) {
		state->vfs_aio_state.error = (int)result;
	}

	state->result = result;
	SMBPROFILE_BYTES_ASYNC_SET_IDLE_X(state->profile_bytes,
					  state->profile_bytes_x);
}

static void vfs_ceph_rgw_aio_prepare(struct vfs_handle_struct *handle,
				     struct tevent_req *req,
				     struct tevent_context *ev,
				     struct files_struct *fsp)
{
	struct vfs_ceph_rgw_config *config = NULL;
	struct vfs_ceph_rgw_aio_state *state = NULL;
	int ret = -1;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				(void)0);
	if (config == NULL) {
		tevent_req_error(req, EINVAL);
		return;
	}

	state = tevent_req_data(req, struct vfs_ceph_rgw_aio_state);
	state->config = config;

	ret = vfs_ceph_rgw_fetch_io_fh(handle, fsp, &state->fh);
	if (ret != 0) {
		tevent_req_error(req, -ret);
	}
}

static struct tevent_req *vfs_ceph_rgw_fsync_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	files_struct *fsp)
{
	int rc = -1;
	struct tevent_req *req = NULL;
	struct vfs_ceph_rgw_aio_state *state = NULL;

	DBG_DEBUG("[CEPH_RGW] fsync_send: name=%s\n", fsp_str_dbg(fsp));

	req = tevent_req_create(mem_ctx, &state, struct vfs_ceph_rgw_aio_state);
	if (req == NULL) {
		return NULL;
	}

	vfs_ceph_rgw_aio_prepare(handle, req, ev, fsp);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	SMBPROFILE_BYTES_ASYNC_START_X(SNUM(handle->conn),
				       syscall_asys_fsync,
				       state->profile_bytes,
				       state->profile_bytes_x,
				       0);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE_X(state->profile_bytes,
					  state->profile_bytes_x);

	vfs_ceph_rgw_aio_start(state);
	rc = rgw_fsync(state->config->rgw_root_fs, state->fh->rgw_fh, 0);
	vfs_ceph_rgw_aio_finish(state, rc);
	if (rc != 0) {
		tevent_req_error(req, -rc);
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static int vfs_ceph_rgw_fsync_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_ceph_rgw_aio_state *state = tevent_req_data(
		req, struct vfs_ceph_rgw_aio_state);
	ssize_t res = -1;

	DBG_DEBUG("[CEPH_RGW] fsync_recv: error=%d duration=%" PRIu64
		  " fd=%d off=%jd len=%ju result=%ld\n",
		  state->vfs_aio_state.error,
		  state->vfs_aio_state.duration,
		  state->fh->fd,
		  state->off,
		  state->len,
		  state->result);

	SMBPROFILE_BYTES_ASYNC_END_X(state->profile_bytes,
				     state->profile_bytes_x);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		goto out;
	}

	*vfs_aio_state = state->vfs_aio_state;
	res = state->result;
out:
	tevent_req_received(req);
	return res;
}

static struct vfs_fn_pointers ceph_rgw_fns = {
	/* Disk operations */

	.connect_fn = vfs_ceph_rgw_connect,
	.disconnect_fn = vfs_ceph_rgw_disconnect,
	.disk_free_fn = vfs_not_implemented_disk_free,
	.get_quota_fn = vfs_not_implemented_get_quota,
	.set_quota_fn = vfs_not_implemented_set_quota,
	.statvfs_fn = vfs_not_implemented_statvfs,
	.fs_capabilities_fn = vfs_not_implemented_fs_capabilities,

	/* Directory operations */

	.fdopendir_fn = vfs_ceph_rgw_fdopendir,
	.readdir_fn = vfs_ceph_rgw_readdir,
	.rewind_dir_fn = vfs_ceph_rgw_rewinddir,
	.mkdirat_fn = vfs_ceph_rgw_mkdirat,
	.closedir_fn = vfs_ceph_rgw_closedir,

	/* File operations */

	.create_dfs_pathat_fn = vfs_not_implemented_create_dfs_pathat,
	.read_dfs_pathat_fn = vfs_not_implemented_read_dfs_pathat,
	.openat_fn = vfs_ceph_rgw_openat,
	.close_fn = vfs_ceph_rgw_close,
	.pread_fn = vfs_ceph_rgw_pread,
	.pread_send_fn = vfs_not_implemented_pread_send,
	.pread_recv_fn = vfs_not_implemented_pread_recv,
	.pwrite_fn = vfs_ceph_rgw_pwrite,
	.pwrite_send_fn = vfs_not_implemented_pwrite_send,
	.pwrite_recv_fn = vfs_not_implemented_pwrite_recv,
	.lseek_fn = vfs_not_implemented_lseek,
	.sendfile_fn = vfs_not_implemented_sendfile,
	.recvfile_fn = vfs_not_implemented_recvfile,
	.renameat_fn = vfs_ceph_rgw_renameat,
	.fsync_send_fn = vfs_ceph_rgw_fsync_send,
	.fsync_recv_fn = vfs_ceph_rgw_fsync_recv,
	.stat_fn = vfs_ceph_rgw_stat,
	.fstat_fn = vfs_ceph_rgw_fstat,
	.lstat_fn = vfs_not_implemented_lstat,
	.fstatat_fn = vfs_not_implemented_fstatat,
	.unlinkat_fn = vfs_ceph_rgw_unlinkat,
	.fchmod_fn = vfs_not_implemented_fchmod,
	.fchown_fn = vfs_not_implemented_fchown,
	.lchown_fn = vfs_not_implemented_lchown,
	.chdir_fn = vfs_ceph_rgw_chdir,
	.getwd_fn = vfs_ceph_rgw_getwd,
	.fntimes_fn = vfs_not_implemented_fntimes,
	.ftruncate_fn = vfs_ceph_rgw_ftruncate,
	.fallocate_fn = vfs_not_implemented_fallocate,
	.lock_fn = vfs_not_implemented_lock,
	.filesystem_sharemode_fn = vfs_not_implemented_filesystem_sharemode,
	.fcntl_fn = vfs_ceph_rgw_fcntl,
	.linux_setlease_fn = vfs_not_implemented_linux_setlease,
	.getlock_fn = vfs_not_implemented_getlock,
	.symlinkat_fn = vfs_not_implemented_symlinkat,
	.readlinkat_fn = vfs_not_implemented_vfs_readlinkat,
	.linkat_fn = vfs_not_implemented_linkat,
	.mknodat_fn = vfs_not_implemented_mknodat,
	.realpath_fn = vfs_ceph_rgw_realpath,
	.fchflags_fn = vfs_not_implemented_fchflags,
	.get_real_filename_at_fn = vfs_ceph_rgw_get_real_filename_at,
	.fget_dos_attributes_fn = vfs_not_implemented_fget_dos_attributes,
	.fset_dos_attributes_fn = vfs_not_implemented_fset_dos_attributes,

	/* EA operations. */
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.fgetxattr_fn = vfs_not_implemented_fgetxattr,
	.flistxattr_fn = vfs_not_implemented_flistxattr,
	.fremovexattr_fn = vfs_not_implemented_fremovexattr,
	.fsetxattr_fn = vfs_not_implemented_fsetxattr,

	/* Posix ACL Operations */
	.sys_acl_get_fd_fn = vfs_not_implemented_sys_acl_get_fd,
	.sys_acl_blob_get_fd_fn = vfs_not_implemented_sys_acl_blob_get_fd,
	.sys_acl_set_fd_fn = vfs_not_implemented_sys_acl_set_fd,
	.sys_acl_delete_def_fd_fn = vfs_not_implemented_sys_acl_delete_def_fd,

	/* aio operations */
	.aio_force_fn = vfs_not_implemented_aio_force,
};

NTSTATUS vfs_ceph_rgw_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"ceph_rgw",
				&ceph_rgw_fns);
}

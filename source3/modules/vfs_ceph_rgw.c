/*
   Unix SMB/CIFS implementation.
   Wrap disk only vfs functions to sidestep dodgy compilers.
   Copyright (C) Tim Potter 1998
   Copyright (C) Jeremy Allison 2007
   Copyright (C) Brian Chrisman 2011 <bchrisman@gmail.com>
   Copyright (C) Richard Sharpe 2011 <realrichardsharpe@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

#define RGW_FN(_name) typeof(_name) *_name ## _fn

#define CHECK_RGW_FN(hnd, func) \
	do { \
		config->func ## _fn = dlsym(hnd, #func); \
		if (config->func ## _fn == NULL) { \
			if (dlclose(hnd)) { \
				DBG_ERR("[CEPH_RGW] %s\n", dlerror()); \
			} \
			errno = ENOSYS; \
			return false; \
		} \
	} while(0);

#define TIME_T_TO_TIMESPEC(tt, ts) \
	do { \
		(ts).tv_sec = (tt); \
		(ts).tv_nsec = 0; \
	} while(0);

#define FSP_NAME(fsp) ((fsp)->fsp_name->base_name)

struct vfs_ceph_rgw_config {

	/* Module parameters */
	const char *bkt_name;
	const char *user_id;
	const char *access_key;
	const char *secret_access_key;
	const char *config_file;
	const char *keyring_file;

	/* rgw objects */
	librgw_t rgw_lib_handle;
	struct rgw_fs *rgw_root_fs;
	struct rgw_file_handle *rgw_root_fh;

	/* rgw library handle */
	void *libhandle;

	/* rgw library functions */
	RGW_FN(librgw_create);
	RGW_FN(librgw_shutdown);
	RGW_FN(rgw_lookup);
	RGW_FN(rgw_lookup_handle);
	RGW_FN(rgw_fh_rele);
	RGW_FN(rgw_mount);
	RGW_FN(rgw_mount2);
	RGW_FN(rgw_register_invalidate);
	RGW_FN(rgw_umount);
	RGW_FN(rgw_statfs);
	RGW_FN(rgw_create);
	RGW_FN(rgw_symlink);
	RGW_FN(rgw_mkdir);
	RGW_FN(rgw_rename);
	RGW_FN(rgw_unlink);
	RGW_FN(rgw_readdir);
	RGW_FN(rgw_readdir2);
	RGW_FN(rgw_dirent_offset);
	RGW_FN(rgw_getattr);
	RGW_FN(rgw_setattr);
	RGW_FN(rgw_truncate);
	RGW_FN(rgw_open);
	RGW_FN(rgw_close);
	RGW_FN(rgw_read);
	RGW_FN(rgw_readlink);
	RGW_FN(rgw_write);
	RGW_FN(rgw_readv);
	RGW_FN(rgw_writev);
	RGW_FN(rgw_fsync);
	RGW_FN(rgw_commit);
	RGW_FN(rgw_getxattrs);
	RGW_FN(rgw_lsxattrs);
	RGW_FN(rgw_setxattrs);
	RGW_FN(rgw_rmxattrs);
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

static bool vfs_ceph_rgw_mount_bucket(struct connection_struct *conn,
				      struct vfs_ceph_rgw_config *config)
{
	int rc = 0;
	int nparams = 0;
	int  i = 0;

	char *librgw_params[] = {
				NULL,		/* program name="vfs_ceph_rgw" */
				NULL,		/* --name: Must be client.admin */
				NULL,		/* --cluster: Must be ceph */
				NULL,		/* cluster config file */
				NULL,		/* keyring file */
				NULL		/* Last param must be NULL */
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

	for (i = 0; i < nparams; i++) {
		if (librgw_params[i] == NULL) {
			DBG_ERR("[CEPH_RGW] Not enough memory for librgw params\n");
			return false;
		}
	}

	rc = config->librgw_create_fn(&config->rgw_lib_handle,
				      nparams,
				      librgw_params);
	if (rc != 0) {
		DBG_ERR("[CEPH_RGW] Failed to init librgw. rc=%d\n", rc);
		return false;
	}

	rc = config->rgw_mount2_fn(
				config->rgw_lib_handle,
				config->user_id,
				config->access_key,
				config->secret_access_key,
				config->bkt_name,
				&config->rgw_root_fs,
				RGW_MOUNT_FLAG_NONE);
	if (rc != 0) {
		DBG_ERR("[CEPH_ERR] Unable to mount bucket=%s.Err=%d\n",
			config->bkt_name, rc);
		if (rc == -EINVAL) {
			DBG_ERR("[CEPH_RGW]Unable to authorise user=%s\n",
				config->user_id);
		}
		return false;
	}

	config->rgw_root_fh = config->rgw_root_fs->root_fh;

	return true;
};

static bool vfs_ceph_rgw_load_lib(struct vfs_ceph_rgw_config *config)
{
	void *libhandle = NULL;
	const char *libname = "librgw.so.2";

	libhandle = dlopen(libname, RTLD_LAZY);
	if (libhandle == NULL) {
		DBG_ERR("[CEPH_RGW] %s\n", dlerror());
		return false;
	}

	CHECK_RGW_FN(libhandle, librgw_create);
	CHECK_RGW_FN(libhandle, librgw_shutdown);
	CHECK_RGW_FN(libhandle, rgw_lookup);
	CHECK_RGW_FN(libhandle, rgw_lookup_handle);
	CHECK_RGW_FN(libhandle, rgw_fh_rele);
	CHECK_RGW_FN(libhandle, rgw_mount);
	CHECK_RGW_FN(libhandle, rgw_mount2);
	CHECK_RGW_FN(libhandle, rgw_register_invalidate);
	CHECK_RGW_FN(libhandle, rgw_umount);
	CHECK_RGW_FN(libhandle, rgw_statfs);
	CHECK_RGW_FN(libhandle, rgw_create);
	CHECK_RGW_FN(libhandle, rgw_symlink);
	CHECK_RGW_FN(libhandle, rgw_mkdir);
	CHECK_RGW_FN(libhandle, rgw_rename);
	CHECK_RGW_FN(libhandle, rgw_unlink);
	CHECK_RGW_FN(libhandle, rgw_readdir);
	CHECK_RGW_FN(libhandle, rgw_readdir2);
	CHECK_RGW_FN(libhandle, rgw_dirent_offset);
	CHECK_RGW_FN(libhandle, rgw_getattr);
	CHECK_RGW_FN(libhandle, rgw_setattr);
	CHECK_RGW_FN(libhandle, rgw_truncate);
	CHECK_RGW_FN(libhandle, rgw_open);
	CHECK_RGW_FN(libhandle, rgw_close);
	CHECK_RGW_FN(libhandle, rgw_read);
	CHECK_RGW_FN(libhandle, rgw_readlink);
	CHECK_RGW_FN(libhandle, rgw_write);
	CHECK_RGW_FN(libhandle, rgw_readv);
	CHECK_RGW_FN(libhandle, rgw_writev);
	CHECK_RGW_FN(libhandle, rgw_fsync);
	CHECK_RGW_FN(libhandle, rgw_commit);
	CHECK_RGW_FN(libhandle, rgw_getxattrs);
	CHECK_RGW_FN(libhandle, rgw_lsxattrs);
	CHECK_RGW_FN(libhandle, rgw_setxattrs);
	CHECK_RGW_FN(libhandle, rgw_rmxattrs);

	config->libhandle = libhandle;
	return true;
}

static int vfs_ceph_rgw_config_destructor(struct vfs_ceph_rgw_config *config)
{
	if (config->libhandle) {
		if (dlclose(config->libhandle)) {
			DBG_ERR("[CEPH_RGW] %s\n", dlerror());
		}
	}

	return 0;
}

static bool vfs_ceph_rgw_load_config(struct vfs_handle_struct *handle,
				     struct vfs_ceph_rgw_config **config)
{
	struct vfs_ceph_rgw_config *config_tmp = NULL;
	int snum = SNUM(handle->conn);
	const char *module_name = "ceph_rgw";

	if (SMB_VFS_HANDLE_TEST_DATA(handle)) {
		SMB_VFS_HANDLE_GET_DATA(handle, config_tmp,
					struct vfs_ceph_rgw_config,
					return false);
		goto done;
	}

	config_tmp = talloc_zero(handle->conn, struct vfs_ceph_rgw_config);
	if (config_tmp == NULL) {
		errno = ENOMEM;
		return false;
	}
	talloc_set_destructor(config_tmp, vfs_ceph_rgw_config_destructor);

	config_tmp->config_file		= lp_parm_const_string(
						snum,
						module_name,
						"config_file",
						"/etc/ceph/ceph.conf");
	config_tmp->keyring_file	= lp_parm_const_string(
						snum,
						module_name,
						"keyring_file",
						"/etc/ceph/ceph.client.admin.keyring");
	config_tmp->user_id		= lp_parm_const_string(
						snum,
						module_name,
						"user_id",
						"");
	config_tmp->access_key		= lp_parm_const_string(
						snum,
						module_name,
						"access_key",
						"");
	config_tmp->secret_access_key	= lp_parm_const_string(
						snum,
						module_name,
						"secret_access_key",
						"");
	config_tmp->bkt_name		= lp_parm_const_string(
						snum,
						module_name,
						"bucket",
						"");

	if ((strlen(config_tmp->user_id) == 0) ||
	    (strlen(config_tmp->access_key) == 0) ||
	    (strlen(config_tmp->secret_access_key) == 0) ||
	    (strlen(config_tmp->bkt_name) == 0)) {
		DBG_ERR("[CEPH_RGW] user_id / access_key / secret_access_key\
 / bucket can't be empty\n");
		return false;
	}

	SMB_VFS_HANDLE_SET_DATA(handle, config_tmp, NULL,
				struct vfs_ceph_rgw_config, return false);

done:
	*config = config_tmp;
	return true;
}

static int vfs_ceph_rgw_connect(struct vfs_handle_struct *handle,
			    const char *service, const char *user)
{
	struct vfs_ceph_rgw_config *config = NULL;

	bool ok = false;

	ok = vfs_ceph_rgw_load_config(handle, &config);
	if (!ok) {
		return -1;
	}

	ok = vfs_ceph_rgw_load_lib(config);
	if (!ok) {
		return false;
	}

	ok = vfs_ceph_rgw_mount_bucket(handle->conn, config);
	if (!ok) {
		return false;
	}

	return 0;
}

static void vfs_ceph_rgw_disconnect(struct vfs_handle_struct *handle)
{
	int ret = 0;
	struct vfs_ceph_rgw_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_rgw_config, return);

	ret = config->rgw_umount_fn(config->rgw_root_fs, RGW_UMOUNT_FLAG_NONE);
	if (ret < 0) {
		DBG_ERR("[CEPH_RGW] failed to unmount: snum=%d %s\n",
			SNUM(handle->conn),
			strerror(-ret));
	}

	config->librgw_shutdown_fn(config->rgw_lib_handle);

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

	DBG_DEBUG("[CEPH_RGW] realpath(%p, %s) = %s\n", handle, path, result);
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

	if(!null_timespec(ret1)) {
		return ret1;
	}

	/*
	 * One of ctime, mtime or atime was zero (probably atime).
	 * Just return MIN(ctime, mtime).
	 */
	return ret;
}

static void make_create_timespec(const struct stat *pst, struct stat_ex *dst,
				 bool fake_dir_create_times)
{
	if (S_ISDIR(pst->st_mode) && fake_dir_create_times) {
		dst->st_ex_btime.tv_sec = 315493200L;          /* 1/1/1980 */
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
	TIME_T_TO_TIMESPEC(st_rgw->st_atime, st->st_ex_atime);
	TIME_T_TO_TIMESPEC(st_rgw->st_ctime, st->st_ex_ctime);
	TIME_T_TO_TIMESPEC(st_rgw->st_mtime, st->st_ex_mtime);
	make_create_timespec(st_rgw, st, false);
	st->st_ex_blksize = st_rgw->st_blksize;
	st->st_ex_blocks = st_rgw->st_blocks;
}

static int vfs_ceph_rgw_stat(
			struct vfs_handle_struct *handle,
			struct smb_filename *smb_fname)
{
	int result = -1;
	struct vfs_ceph_rgw_config *config = NULL;
	struct stat st = {0};

	START_PROFILE_X(SNUM(handle->conn), syscall_stat);

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_rgw_config, return -1);

	if (strlen(smb_fname->base_name) == 1) {
		if ((strncmp(smb_fname->base_name, ".", 1) == 0) ||
		    (strncmp(smb_fname->base_name, "/", 1) == 0)) {
			result = config->rgw_getattr_fn(config->rgw_root_fs,
					config->rgw_root_fh,
					&st,
					RGW_GETATTR_FLAG_NONE);
			if (result < 0) {
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

	result = config->rgw_getattr_fn(config->rgw_root_fs,
				 config->rgw_root_fh,
				 &st,
				 RGW_GETATTR_FLAG_NONE);
	if (result < 0) {
		goto out;
	}

	smb_stat_from_ceph_rgw_stat(&smb_fname->st, &st);

out:
	DBG_DEBUG("[CEPH_RGW] stat: name=%s rc=%d\n", smb_fname->base_name, result);
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
	DBG_NOTICE("[CEPH_RGW] chdir is for %s\n",
		   smb_fname->base_name);
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

	rc = config->rgw_lookup_fn(config->rgw_root_fs,
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
		(void)config->rgw_fh_rele_fn(config->rgw_root_fs,
					     rgw_fh,
					     RGW_FH_RELE_FLAG_NONE);
	}

out:
	END_PROFILE_X(syscall_chdir);
	return status_code(rc);
#endif
}

static struct smb_filename *vfs_ceph_rgw_getwd(
			struct vfs_handle_struct *handle,
			TALLOC_CTX *ctx)
{
	const char *cwd = "/";
	struct vfs_ceph_rgw_config *config = NULL;

	START_PROFILE_X(SNUM(handle->conn), syscall_getwd);
	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_rgw_config,
				return NULL);

	END_PROFILE_X(syscall_getwd);
	return cp_smb_basename(ctx, cwd);
}


static void vfs_ceph_rgw_put_fh_dirent(struct vfs_ceph_rgw_fh *cfh)
{
	TALLOC_FREE(cfh->dirp);
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
	int ret = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_rgw_config,
				return -ENOMEM);

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
out:
	DBG_NOTICE("[CEPH_RGW] vfs_ceph_add_fh: name = %s ret = %d\n",
		  FSP_NAME(fsp),
		  ret);
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
		  FSP_NAME(fsp),
		  ret);
	return ret;
}

static int vfs_ceph_rgw_openat(
			struct vfs_handle_struct *handle,
			const struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			files_struct *fsp,
			const struct vfs_open_how *how)
{
	int rc = 0;
	static int ceph_rgw_fd = 10000;
	struct vfs_ceph_rgw_fh *newfh = NULL;
	struct rgw_file_handle *rgw_fh = NULL;
	struct vfs_ceph_rgw_config *config = NULL;
	struct stat st = {0};
	int flags = how->flags;
	mode_t mode = how->mode;
	/* TODO: Figure out what to do with mask */
	uint32_t mask = RGW_SETATTR_UID | RGW_SETATTR_GID | RGW_SETATTR_MODE;
	bool skip_open = false;
	uint32_t file_type = 0;

	START_PROFILE_X(SNUM(handle->conn), syscall_openat);

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_rgw_config,
				return -ENOMEM);
	DBG_NOTICE("[CEPH_RGW] smb_fname->base_name=%s dirfsp->name=%s fsp->name=%s flags=%d mode=%d\n",
		  smb_fname->base_name, FSP_NAME(dirfsp), FSP_NAME(fsp), flags, mode);

#if 0
	if (strlen(FSP_NAME(fsp)) == 1) {
		if ((strncmp(FSP_NAME(fsp), ".", 1) == 0) ||
		    (strncmp(FSP_NAME(fsp), "/", 1) == 0)) {
			rc = ceph_rgw_fd;
			ceph_rgw_fd++;
			return rc;
		}
	}
#endif

	if (strlen(FSP_NAME(fsp)) == 1) {
		if ((strncmp(FSP_NAME(fsp), ".", 1) == 0) ||
		    (strncmp(FSP_NAME(fsp), "/", 1) == 0)) {
			skip_open = true;
		}
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
		newfh->fd = ceph_rgw_fd;
		ceph_rgw_fd++;
	}

	if (skip_open) {
		DBG_NOTICE("[CEPH_RGW] Skipping open\n");
		newfh->rgw_fh = config->rgw_root_fh;
		rc = newfh->fd;
		goto out;
	}

	if (flags & O_CREAT) {
		rc = config->rgw_create_fn(config->rgw_root_fs,
					   config->rgw_root_fh,
					   FSP_NAME(fsp),
					   &st,
					   mask,
					   &rgw_fh,
					   flags,
					   RGW_CREATE_FLAG_NONE);
		if (rc < 0) {
			vfs_ceph_rgw_remove_fh(handle, fsp);
			DBG_ERR("[CEPH_RGW] Error creating [%s]. rc = %d\n",
				FSP_NAME(fsp), rc);
			goto out;
		}
		newfh->rgw_fh = rgw_fh;
		DBG_NOTICE("[CEPH_RGW] In create [%s]. rgw_fh=%p\n",
			   FSP_NAME(fsp), rgw_fh);
	} else {
		DBG_NOTICE("[CEPH_RGW] Before lookup [%s]. newfh->rgw_fh=%p\n",
			   FSP_NAME(fsp), newfh->rgw_fh);
		rc = config->rgw_lookup_fn(config->rgw_root_fs,
					   config->rgw_root_fh,
					   FSP_NAME(fsp),
					   &rgw_fh,
					   &st,
					   flags,
					   RGW_LOOKUP_TYPE_FLAGS);
		if (rc < 0) {
			vfs_ceph_rgw_remove_fh(handle, fsp);
			DBG_ERR("[CEPH_RGW] Error looking up [%s]. rc = %d\n",
				FSP_NAME(fsp), rc);
			goto out;
		}
		DBG_NOTICE("[CEPH_RGW] After lookup [%s]. rgw_fh=%p\n",
			   FSP_NAME(fsp), rgw_fh);
		file_type = st.st_mode & S_IFMT;
		if (file_type == S_IFREG) {
			rc = config->rgw_open_fn(config->rgw_root_fs,
						 rgw_fh,
						 flags,
						 RGW_OPEN_FLAG_NONE);
			if (rc < 0) {
				vfs_ceph_rgw_remove_fh(handle, fsp);
				DBG_ERR("[CEPH_RGW] Unable to open [%s]. rc = %d\n",
					 FSP_NAME(fsp), rc);
				goto out;
			}
			DBG_NOTICE("[CEPH_RGW] After open [%s]. rgw_fh=%p\n",
					FSP_NAME(fsp), rgw_fh);
		}
		newfh->rgw_fh = rgw_fh;

		rc = config->rgw_fh_rele_fn(config->rgw_root_fs,
					    rgw_fh,
					    RGW_FH_RELE_FLAG_NONE);
		if (rc < 0) {
			vfs_ceph_rgw_remove_fh(handle, fsp);
			DBG_ERR("[CEPH_RGW] Error releasing handle [%s]. rc = %d\n",
				FSP_NAME(fsp), rc);
			goto out;
		}
		rc = newfh->fd;
	}
out:
	END_PROFILE_X(syscall_openat);
	return status_code(rc);
}

static int vfs_ceph_rgw_close(
			struct vfs_handle_struct *handle,
			files_struct *fsp)
{
	int rc = 0;
	struct vfs_ceph_rgw_fh *openfh = NULL;
	struct vfs_ceph_rgw_config *config = NULL;
	START_PROFILE_X(SNUM(handle->conn), syscall_close);

	if (strlen(FSP_NAME(fsp)) == 1) {
		if ((strncmp(FSP_NAME(fsp), ".", 1) == 0) ||
		    (strncmp(FSP_NAME(fsp), "/", 1) == 0)) {
			rc = 0;
			goto out;
		}
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_rgw_config,
				return -ENOMEM);
	DBG_NOTICE("[CEPH_RGW] close is for [%s]\n", FSP_NAME(fsp));
	rc = vfs_ceph_rgw_fetch_fh(handle, fsp, &openfh);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to find open handle for %s. rc=%d\n",
			FSP_NAME(fsp), rc);
		goto out;
	}

	rc = config->rgw_close_fn(config->rgw_root_fs, openfh->rgw_fh, RGW_CLOSE_FLAG_NONE);
	vfs_ceph_rgw_remove_fh(handle, fsp);
out:
	END_PROFILE_X(syscall_close);
	return status_code(rc);
}

static int vfs_ceph_rgw_fstat(struct vfs_handle_struct *handle,
			  files_struct *fsp,
			  SMB_STRUCT_STAT *sbuf)
{
	int rc = 0;
	struct vfs_ceph_rgw_fh *openfh = NULL;
	struct vfs_ceph_rgw_config *config = NULL;
	struct stat st = {0};

	START_PROFILE_X(SNUM(handle->conn), syscall_fstatat);

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_rgw_config,
				return -ENOMEM);
#if 0
	if (strlen(FSP_NAME(fsp)) == 1) {
		if ((strncmp(FSP_NAME(fsp), ".", 1) == 0) ||
		    (strncmp(FSP_NAME(fsp), "/", 1) == 0)) {
			rc = config->rgw_getattr_fn(config->rgw_root_fs,
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

	DBG_DEBUG("[CEPH_RGW] fstatat: name [%s]\n", FSP_NAME(fsp));

	rc = vfs_ceph_rgw_fetch_fh(handle, fsp, &openfh);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to find open handle for %s. rc=%d\n",
			FSP_NAME(fsp), rc);
		goto out;
	}

	rc = config->rgw_getattr_fn(config->rgw_root_fs,
				    openfh->rgw_fh,
				    &st,
				    RGW_GETATTR_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to stat [%s]. rc=%d\n",
			FSP_NAME(fsp), rc);
		goto out;
	}

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
		   name, offset, mask, flags);

	if (cb_arg->eof == true) {
		/* Its end of dir listing, return 0 */
		return 0;
	}

	d = talloc_zero(cb_arg->ctx, struct dirent);
	if (d == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for dir entry\n");
		return 0;
	}

	/* prepare dentry */
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
	strncpy(d->d_name, name, sizeof(d->d_name)-1);

	dirp->dirs = talloc_realloc(cb_arg->ctx, dirp->dirs, struct dirent, dirp->num+1);
	if (dirp->dirs == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for dir entries\n");
		return 0;
	}

	dirp->dirs[dirp->num++] = *d;

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

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct vfs_ceph_rgw_config,
				return NULL);

	DBG_DEBUG("[CEPH_RGW] fdopendir: name [%s]\n", FSP_NAME(fsp));

	rc = vfs_ceph_rgw_fetch_fh(handle, fsp, &openfh);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to find open handle for %s. rc=%d\n",
			FSP_NAME(fsp), rc);
		goto out;
	}

	/* We might not need this */
#if 0
	rc = config->rgw_getattr_fn(config->rgw_root_fs,
				    openfh,
				    &st,
				    RGW_GETATTR_FLAG_NONE);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to get attr for [%s]. rc = %d\n",
			FSP_NAME(fsp), rc);
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

	rc = config->rgw_readdir2_fn(config->rgw_root_fs,
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

out:
	END_PROFILE_X(syscall_fdopendir);
	return (DIR *)dirp;
}

static int vfs_ceph_rgw_closedir(struct vfs_handle_struct *handle, DIR *dirp)
{
	int rc = 0;
	struct vfs_ceph_rgw_fh *cfh = (struct vfs_ceph_rgw_fh *)dirp;

	START_PROFILE_X(SNUM(handle->conn), syscall_closedir);
	DBG_NOTICE("[CEPH_RGW] closedir: handle=%p dirp=%p\n", handle, dirp);
	TALLOC_FREE(cfh->dirp);
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

	DBG_DEBUG("[CEPH_RGW] readdir: name [%s]\n", FSP_NAME(dirfsp));

	if (rgw_dirp->pos < rgw_dirp->num) {
		ret = (struct dirent *)&rgw_dirp->dirs[rgw_dirp->pos++];
	}
	END_PROFILE_X(syscall_readdir);
	return ret;
}

static void vfs_ceph_rgw_rewinddir(struct vfs_handle_struct *handle, DIR *dirp)
{
	struct vfs_ceph_rgw_dir *rgw_dirp = (struct vfs_ceph_rgw_dir *)dirp;
	START_PROFILE_X(SNUM(handle->conn), syscall_rewinddir);
	rgw_dirp->pos = 0;
	END_PROFILE_X(syscall_rewinddir);
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
	.mkdirat_fn = vfs_not_implemented_mkdirat,
	.closedir_fn = vfs_ceph_rgw_closedir,

	/* File operations */

	.create_dfs_pathat_fn = vfs_not_implemented_create_dfs_pathat,
	.read_dfs_pathat_fn = vfs_not_implemented_read_dfs_pathat,
	.openat_fn = vfs_ceph_rgw_openat,
	.close_fn = vfs_ceph_rgw_close,
	.pread_fn = vfs_not_implemented_pread,
	.pread_send_fn = vfs_not_implemented_pread_send,
	.pread_recv_fn = vfs_not_implemented_pread_recv,
	.pwrite_fn = vfs_not_implemented_pwrite,
	.pwrite_send_fn = vfs_not_implemented_pwrite_send,
	.pwrite_recv_fn = vfs_not_implemented_pwrite_recv,
	.lseek_fn = vfs_not_implemented_lseek,
	.sendfile_fn = vfs_not_implemented_sendfile,
	.recvfile_fn = vfs_not_implemented_recvfile,
	.renameat_fn = vfs_not_implemented_renameat,
	.fsync_send_fn = vfs_not_implemented_fsync_send,
	.fsync_recv_fn = vfs_not_implemented_fsync_recv,
	.stat_fn = vfs_ceph_rgw_stat,
	.fstat_fn = vfs_ceph_rgw_fstat,
	.lstat_fn = vfs_not_implemented_lstat,
	.fstatat_fn = vfs_not_implemented_fstatat,
	.unlinkat_fn = vfs_not_implemented_unlinkat,
	.fchmod_fn = vfs_not_implemented_fchmod,
	.fchown_fn = vfs_not_implemented_fchown,
	.lchown_fn = vfs_not_implemented_lchown,
	.chdir_fn = vfs_ceph_rgw_chdir,
	.getwd_fn = vfs_ceph_rgw_getwd,
	.fntimes_fn = vfs_not_implemented_fntimes,
	.ftruncate_fn = vfs_not_implemented_ftruncate,
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
				"ceph_rgw", &ceph_rgw_fns);
}

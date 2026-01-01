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
	uint64_t ceph_rgw_fd;
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

	DBG_DEBUG("[CEPH_RGW] realpath (%s) = %s\n", path, result);
	result_fname = cp_smb_basename(ctx, result);
	TALLOC_FREE(result);
out:
	END_PROFILE_X(syscall_realpath);
	return result_fname;
}

/*
 * Return the best approximation to a 'create time' under UNIX from a stat
 * structure.
 */
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
	struct rgw_file_handle *rgw_fh = NULL;
	struct stat st = {0};

	START_PROFILE_X(SNUM(handle->conn), syscall_stat);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);

	if (smb_fname->stream_name) {
		result = -ENOENT;
		goto out;
	}

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

	result = rgw_lookup(config->rgw_root_fs,
			    config->rgw_root_fh,
			    smb_fname->base_name,
			    &rgw_fh,
			    &st,
			    0,
			    RGW_LOOKUP_TYPE_FLAGS);
	if (result < 0) {
		DBG_ERR("[CEPH_RGW] Unable to lookup [%s]. rc = %d\n",
			smb_fname->base_name,
			result);
		goto out;
	}

	(void)rgw_fh_rele(config->rgw_root_fs,
			  rgw_fh,
			  RGW_FH_RELE_FLAG_NONE);

	smb_stat_from_ceph_rgw_stat(&smb_fname->st, &st);
out:
	END_PROFILE_X(syscall_stat);
	return status_code(result);
}

static int vfs_ceph_rgw_lstat(struct vfs_handle_struct *handle,
			      struct smb_filename *smb_fname)
{
	int rc = -ENOMEM;
	struct vfs_ceph_rgw_config *config = NULL;
	struct rgw_file_handle *rgw_fh = NULL;
	struct stat st = {0};

	START_PROFILE_X(SNUM(handle->conn), syscall_lstat);

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				goto out);

	if (smb_fname->stream_name) {
		rc = -ENOENT;
		goto out;
	}

	if (strlen(smb_fname->base_name) == 1) {
		if ((strncmp(smb_fname->base_name, ".", 1) == 0) ||
		    (strncmp(smb_fname->base_name, "/", 1) == 0))
		{
			rc = rgw_getattr(config->rgw_root_fs,
					     config->rgw_root_fh,
					     &st,
					     RGW_GETATTR_FLAG_NONE);
			if (rc < 0) {
				DBG_ERR("[CEPH_RGW] Unable to get attr for "
					"[%s]. "
					"rc = %d\n",
					smb_fname->base_name,
					rc);
				goto out;
			}
			smb_stat_from_ceph_rgw_stat(&smb_fname->st, &st);
			goto out;
		}
	}

	rc = rgw_lookup(config->rgw_root_fs,
			config->rgw_root_fh,
			smb_fname->base_name,
			&rgw_fh,
			&st,
			0,
			RGW_LOOKUP_TYPE_FLAGS);
	if (rc < 0) {
		DBG_ERR("[CEPH_RGW] Unable to lookup [%s]. rc = %d\n",
			smb_fname->base_name,
			rc);
		goto out;
	}

	(void)rgw_fh_rele(config->rgw_root_fs,
			  rgw_fh,
			  RGW_FH_RELE_FLAG_NONE);

	smb_stat_from_ceph_rgw_stat(&smb_fname->st, &st);
out:
	END_PROFILE_X(syscall_lstat);
	return status_code(rc);
}

/*
 * librgw do not have concept of current working directory.
 * Therefore chdir, getwd methods are sort of no-op.
 */
static int vfs_ceph_rgw_chdir(struct vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname)
{
	int rc = 0;
	START_PROFILE_X(SNUM(handle->conn), syscall_chdir);
	END_PROFILE_X(syscall_chdir);
	return status_code(rc);
}

static struct smb_filename *vfs_ceph_rgw_getwd(struct vfs_handle_struct *handle,
					       TALLOC_CTX *ctx)
{
	const char *cwd = "/";

	START_PROFILE_X(SNUM(handle->conn), syscall_getwd);
	END_PROFILE_X(syscall_getwd);
	return cp_smb_basename(ctx, cwd);
}

static bool vfs_ceph_rgw_mount_bucket(struct connection_struct *conn,
				      struct vfs_ceph_rgw_config *config)
{
	int rc = 0;
	int nparams = 0;
	int i = 0;
	bool ret = false;
	char *librgw_params[] = {
		NULL, /* program name="vfs_ceph_rgw" */
		NULL, /* --name: Must be client.admin */
		NULL, /* --cluster: Must be ceph */
		NULL, /* cluster config file */
		NULL, /* keyring file */
		NULL, /* ceph debug param */
		NULL  /* Last param must be NULL */
	};

	/* Prepare parameters */
	librgw_params[nparams] = talloc_asprintf(talloc_tos(), "vfs_ceph_rgw");
	nparams++;

	librgw_params[nparams] = talloc_asprintf(talloc_tos(),
						 "--name=client.admin");
	nparams++;

	librgw_params[nparams] = talloc_asprintf(talloc_tos(),
						 "--cluster=ceph");
	nparams++;

	librgw_params[nparams] = talloc_asprintf(talloc_tos(),
						 "--conf=%s",
						 config->config_file);
	nparams++;

	librgw_params[nparams] = talloc_asprintf(talloc_tos(),
						 "--keyring=%s",
						 config->keyring_file);
	nparams++;

	if (config->debug_enable) {
		librgw_params[nparams] = talloc_strdup(talloc_tos(),
						       "-d --debug-rgw=20");
		nparams++;
	}

	for (i = 0; i < nparams; i++) {
		if (librgw_params[i] == NULL) {
			DBG_ERR("[CEPH_RGW] Not enough memory for librgw "
				"params\n");
			goto out_fail;
		}
	}

	rc = librgw_create(&config->rgw_lib_handle,
			   nparams,
			   librgw_params);
	if (rc != 0) {
		DBG_ERR("[CEPH_RGW] Failed to init librgw. rc=%d\n", rc);
		goto out_fail;
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
		goto out_fail;
	}

	config->rgw_root_fh = config->rgw_root_fs->root_fh;
	config->ceph_rgw_fd = 0;
	ret = true;

out_fail:
	for (i = 0; i < nparams; i++) {
		if (librgw_params[i] != NULL) {
			TALLOC_FREE(librgw_params[i]);
		}
	}
	return ret;
};

static const char *vfs_ceph_rgw_parm(const struct vfs_handle_struct *handle,
				     const char *opt, const char *def)
{
	const int snum = SNUM(handle->conn);
	const char *parm = NULL;

	parm = lp_parm_const_string(snum, "ceph_rgw", opt, def);
	if ((parm == NULL) || !strlen(parm)) {
		DBG_ERR("[CEPH_RGW] missing config: '%s' for snum=%d\n",
			opt, snum);
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

	/*
	 * librgw do not support directory renaming.
	 * This option ensures that samba do not use temporary names for
	 * directory creation and thereby preventing rename while creating
	 * directory.
	 */
	lp_do_parameter(SNUM(handle->conn), "vfs mkdir use tmp name", "no");

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
		DBG_ERR("[CEPH_RGW] failed to unmount: snum=%d Err=%d\n",
			SNUM(handle->conn),
			ret);
	}

	librgw_shutdown(config->rgw_lib_handle);

	TALLOC_FREE(config);
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

	.fdopendir_fn = vfs_not_implemented_fdopendir,
	.readdir_fn = vfs_not_implemented_readdir,
	.rewind_dir_fn = vfs_not_implemented_rewind_dir,
	.mkdirat_fn = vfs_not_implemented_mkdirat,
	.closedir_fn = vfs_not_implemented_closedir,

	/* File operations */

	.create_dfs_pathat_fn = vfs_not_implemented_create_dfs_pathat,
	.read_dfs_pathat_fn = vfs_not_implemented_read_dfs_pathat,
	.openat_fn = vfs_not_implemented_openat,
	.close_fn = vfs_not_implemented_close_fn,
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
	.fstat_fn = vfs_not_implemented_fstat,
	.lstat_fn = vfs_ceph_rgw_lstat,
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
	.fcntl_fn = vfs_not_implemented_fcntl,
	.linux_setlease_fn = vfs_not_implemented_linux_setlease,
	.getlock_fn = vfs_not_implemented_getlock,
	.symlinkat_fn = vfs_not_implemented_symlinkat,
	.readlinkat_fn = vfs_not_implemented_vfs_readlinkat,
	.linkat_fn = vfs_not_implemented_linkat,
	.mknodat_fn = vfs_not_implemented_mknodat,
	.realpath_fn = vfs_ceph_rgw_realpath,
	.fchflags_fn = vfs_not_implemented_fchflags,
	.get_real_filename_at_fn = vfs_not_implemented_get_real_filename_at,
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

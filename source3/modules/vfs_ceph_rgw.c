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
	.stat_fn = vfs_not_implemented_stat,
	.fstat_fn = vfs_not_implemented_fstat,
	.lstat_fn = vfs_not_implemented_lstat,
	.fstatat_fn = vfs_not_implemented_fstatat,
	.unlinkat_fn = vfs_not_implemented_unlinkat,
	.fchmod_fn = vfs_not_implemented_fchmod,
	.fchown_fn = vfs_not_implemented_fchown,
	.lchown_fn = vfs_not_implemented_lchown,
	.chdir_fn = vfs_not_implemented_chdir,
	.getwd_fn = vfs_not_implemented_getwd,
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
	.realpath_fn = vfs_not_implemented_realpath,
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
				"ceph_rgw", &ceph_rgw_fns);
}

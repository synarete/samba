/*
 * VFS module to bridge Samba with CephFS, using libcephfs low-level APIs.
 *
 * Copyright (C) 2024, Shachar Sharon <ssharon@redhat.com>
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
#include "auth.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "modules/posixacl_xattr.h"
#include "lib/util/tevent_unix.h"
#include <cephfs/libcephfs.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

/* Ceph wrapper over debug macros */
#define CEPH_DBG(fmt_, ...) DBG_DEBUG("[ceph] " fmt_ "\n", __VA_ARGS__)

#define CEPH_DBGRET(ret_)                                  \
	do {                                               \
		if ((ret_) < -1)                           \
			CEPH_DBG("ret=%ld", (long)(ret_)); \
	} while (0)

#define CEPH_ERR(fmt_, ...) DBG_ERR("[ceph] " fmt_ "\n", __VA_ARGS__)

/* Convenience helpers */
static void update_errno(int errcode)
{
	errno = abs(errcode);
}

static int status_code(int ret)
{
	if (ret < 0) {
		update_errno(ret);
		ret = -1;
	}
	return ret;
}

/* Ceph parameters */
static const char *vfs_ceph_param_of(int snum,
				     const char *option,
				     const char *default_value)
{
	return lp_parm_const_string(snum, "ceph", option, default_value);
}

static const char *vfs_ceph_param_conf_file(int snum, const char *def)
{
	return vfs_ceph_param_of(snum, "config_file", def);
}

static const char *vfs_ceph_param_user_id(int snum, const char *def)
{
	return vfs_ceph_param_of(snum, "user_id", def);
}

static const char *vfs_ceph_param_fsname(int snum, const char *def)
{
	return vfs_ceph_param_of(snum, "filesystem", def);
}

/* Ceph's inode + ino-number */
struct vfs_ceph_iref {
	struct Inode *inode;
	long ino; /* for debug printing */
};

/* Ceph mounts */

struct vfs_ceph_mnt_entry {
	struct vfs_ceph_mnt_entry *next;
	struct vfs_ceph_mnt_entry *prev;
	char *cookie;
	struct ceph_mount_info *cmount;
	struct vfs_ceph_iref rootdir;
	uint64_t fd_index;
	int snum;
	int count;
	bool strict_allocate;
};

static struct vfs_ceph_mnt_entry *vfs_ceph_mnt_list;

static struct vfs_ceph_mnt_entry *vfs_ceph_mnt_new_entry(int snum,
							 const char *cookie)
{
	struct vfs_ceph_mnt_entry *cme = NULL;

	cme = talloc_zero(NULL, struct vfs_ceph_mnt_entry);
	if (cme == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	cme->cookie = talloc_strdup(cme, cookie);
	if (cme->cookie == NULL) {
		TALLOC_FREE(cme);
		errno = ENOMEM;
		return NULL;
	}
	cme->snum = snum;
	cme->fd_index = 1;
	return cme;
}

static struct vfs_ceph_mnt_entry *vfs_ceph_mnt_lookup(const char *cookie)
{
	struct vfs_ceph_mnt_entry *cme = NULL;

	for (cme = vfs_ceph_mnt_list; cme != NULL; cme = cme->next) {
		if ((cme->cookie == cookie) ||
		    (strcmp(cme->cookie, cookie) == 0))
		{
			return cme;
		}
	}
	return NULL;
}

static void vfs_ceph_mnt_update(struct vfs_ceph_mnt_entry *cme, int n)
{
	cme->count += n;
	CEPH_DBG("update: count=%d cookie=%s", cme->count, cme->cookie);

	if (cme->count == 1) {
		/* first entry-ref */
		DLIST_ADD(vfs_ceph_mnt_list, cme);
	} else if (cme->count == 0) {
		/* last entry-ref */
		DLIST_REMOVE(vfs_ceph_mnt_list, cme);
	}
}

static char *vfs_ceph_mnt_cookie(TALLOC_CTX *mem_ctx, int snum)
{
	return talloc_asprintf(mem_ctx,
			       "(%s/%s/%s)",
			       vfs_ceph_param_conf_file(snum, "."),
			       vfs_ceph_param_user_id(snum, ""),
			       vfs_ceph_param_fsname(snum, ""));
}

static int vfs_ceph_mount_fs(struct vfs_ceph_mnt_entry *cme)
{
	char buf[256];
	struct ceph_mount_info *cmount = NULL;
	const char *user_id = NULL;
	const char *conf_file = NULL;
	const char *fsname = NULL;
	const char *option = NULL;
	const char *value = NULL;
	int ret = -1;

	user_id = vfs_ceph_param_user_id(cme->snum, NULL);
	CEPH_DBG("ceph_create: user_id=%s", user_id);
	ret = ceph_create(&cmount, user_id);
	if (ret) {
		goto mount_fail;
	}

	conf_file = vfs_ceph_param_conf_file(cme->snum, NULL);
	CEPH_DBG("ceph_conf_read_file: conf_file=%s", conf_file);
	ret = ceph_conf_read_file(cmount, conf_file);
	if (ret) {
		goto mount_fail;
	}

	/* require libcephfs 'log file' enabled */
	option = "log file";
	CEPH_DBG("ceph_conf_get: option=%s", option);
	ret = ceph_conf_get(cmount, option, buf, sizeof(buf));
	if (ret < 0) {
		goto mount_fail;
	}

	/* libcephfs disables POSIX ACL support by default, enable it... */
	option = "client_acl_type";
	value = "posix_acl";
	CEPH_DBG("ceph_conf_set: option=%s value=%s", option, value);
	ret = ceph_conf_set(cmount, option, value);
	if (ret != 0) {
		goto mount_fail;
	}

	/* tell libcephfs to perform local permission checks */
	option = "fuse_default_permissions";
	value = "false";
	CEPH_DBG("ceph_conf_set: option=%s value=%s", option, value);
	ret = ceph_conf_set(cmount, option, value);
	if (ret != 0) {
		goto mount_fail;
	}

	/* explicit init */
	CEPH_DBG("ceph_init: cmount=%p", cmount);
	ret = ceph_init(cmount);
	if (ret != 0) {
		goto mount_fail;
	}

	/* select a cephfs file system to use */
	fsname = vfs_ceph_param_fsname(cme->snum, NULL);
	if (fsname != NULL) {
		CEPH_DBG("ceph_select_filesystem: fsname=%s", fsname);
		ret = ceph_select_filesystem(cmount, fsname);
		if (ret != 0) {
			goto mount_fail;
		}
	}

	/* do mount (NULL is synonym to "/") */
	CEPH_DBG("ceph_mount: cmount=%p", cmount);
	ret = ceph_mount(cmount, NULL);
	if (ret < 0) {
		goto mount_fail;
	}

	/* bind local root-dir */
	CEPH_DBG("ceph_ll_lookup_root: cmount=%p", cmount);
	cme->rootdir.ino = CEPH_INO_ROOT;
	ret = ceph_ll_lookup_root(cmount, &cme->rootdir.inode);
	if (ret != 0) {
		goto mount_fail;
	}
	cme->cmount = cmount;
	cme->strict_allocate = lp_strict_allocate(cme->snum);

	return 0;

mount_fail:
	if (cmount != NULL) {
		ceph_release(cmount);
	}
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static struct ceph_mount_info *cmount_of(const struct vfs_handle_struct *handle)
{
	const struct vfs_ceph_mnt_entry *cme = handle->data;

	return cme->cmount;
}

static int snum_of(const struct vfs_handle_struct *handle)
{
	const struct vfs_ceph_mnt_entry *cme = handle->data;

	return cme->snum;
}

/* Ceph low-level wrappers */

static int vfs_ceph_ll_statfs(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_iref *iref,
			      struct statvfs *stbuf)
{
	return ceph_ll_statfs(cmount_of(handle), iref->inode, stbuf);
}

/* Disk operations */
static int vfs_ceph_connect(struct vfs_handle_struct *handle,
			    const char *service,
			    const char *user)
{
	struct vfs_ceph_mnt_entry *cme = NULL;
	char *mnt_cookie = NULL;
	int snum = SNUM(handle->conn);
	int ret = -1;

	mnt_cookie = vfs_ceph_mnt_cookie(handle, snum);
	if (mnt_cookie == NULL) {
		goto connect_fail;
	}
	cme = vfs_ceph_mnt_lookup(mnt_cookie);
	if (cme != NULL) {
		goto connect_ok;
	}
	cme = vfs_ceph_mnt_new_entry(snum, mnt_cookie);
	if (cme == NULL) {
		goto connect_fail;
	}
	ret = vfs_ceph_mount_fs(cme);
	if (ret != 0) {
		goto connect_fail;
	}

connect_ok:
	vfs_ceph_mnt_update(cme, 1);
	handle->data = cme;
	/* fore non-async dosmod (no async implementation of getxattrat) */
	lp_do_parameter(SNUM(handle->conn), "smbd async dosmode", "false");
	TALLOC_FREE(mnt_cookie);
	return 0;

connect_fail:
	TALLOC_FREE(mnt_cookie);
	TALLOC_FREE(cme);
	return ret;
}

static int vfs_ceph_unmount(struct vfs_handle_struct *handle)
{
	int ret = -1;

	CEPH_DBG("unmount: snum=%d", snum_of(handle));
	ret = ceph_unmount(cmount_of(handle));
	CEPH_DBGRET(ret);

	return ret;
}

static int vfs_ceph_release(struct vfs_handle_struct *handle)
{
	int ret = -1;

	CEPH_DBG("release: snum=%d", snum_of(handle));
	ret = ceph_release(cmount_of(handle));
	CEPH_DBGRET(ret);

	return ret;
}

static void vfs_ceph_disconnect(struct vfs_handle_struct *handle)
{
	struct vfs_ceph_mnt_entry *cme = handle->data;

	vfs_ceph_mnt_update(cme, -1);
	if (cme->count > 0) {
		CEPH_DBG("in-use: snum=%d count=%d", cme->snum, cme->count);
	} else {
		CEPH_DBG("mnt-done: snum=%d", cme->snum);
		vfs_ceph_unmount(handle);
		vfs_ceph_release(handle);
		TALLOC_FREE(cme);
		handle->data = NULL;
	}
}

static uint64_t vfs_ceph_disk_free(struct vfs_handle_struct *handle,
				   const struct smb_filename *smb_fname,
				   uint64_t *bsize,
				   uint64_t *dfree,
				   uint64_t *dsize)
{
	struct statvfs stv = {0};
	const struct vfs_ceph_mnt_entry *cme = handle->data;
	int ret = -1;

	CEPH_DBG("disk_free: rootdir-ino=%ld", cme->rootdir.ino);
	ret = vfs_ceph_ll_statfs(handle, &cme->rootdir, &stv);
	if (ret != 0) {
		update_errno(ret);
		return (uint64_t)(-1);
	}
	*bsize = (uint64_t)stv.f_bsize;
	*dfree = (uint64_t)stv.f_bavail;
	*dsize = (uint64_t)stv.f_blocks;
	return *dfree;
}

static uint32_t vfs_ceph_fs_capabilities(struct vfs_handle_struct *handle,
					 enum timestamp_set_resolution *res)
{
	*res = TIMESTAMP_SET_NT_OR_BETTER;

	return FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;
}

/* VFS ceph_ll hooks */
static struct vfs_fn_pointers vfs_ceph_fns = {
	/* Disk operations */
	.connect_fn = vfs_ceph_connect,
	.disconnect_fn = vfs_ceph_disconnect,
	.disk_free_fn = vfs_ceph_disk_free,
	.fs_capabilities_fn = vfs_ceph_fs_capabilities,
};

static_decl_vfs;
NTSTATUS vfs_ceph_ll_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"ceph_ll",
				&vfs_ceph_fns);
}

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

// XXX RM
#define _GNU_SOURCE 1

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

static DIR *dstatus_code(struct ceph_dir_result *cdir_res, int ret)
{
	DIR *dirp = NULL;

	if (ret < 0) {
		update_errno(ret);
	} else {
		dirp = (DIR *)cdir_res;
	}
	return dirp;
}

static long lstatus_code(long ret)
{
	if (ret < 0) {
		update_errno((int)ret);
		ret = -1;
	}
	return ret;
}

static long xstatus_code(long ret)
{
	if (ret < 0) {
		update_errno((int)ret);
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

/* Ceph mounts */

struct vfs_ceph_mnt_entry {
	struct vfs_ceph_mnt_entry *next;
	struct vfs_ceph_mnt_entry *prev;
	char *cookie;
	struct ceph_mount_info *cmount;
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

static int vfs_ceph_mnt_next_fd(struct vfs_ceph_mnt_entry *cme)
{
	/*
	 * The file-descriptor numbering which are reported back to VFS layer
	 * are nothing but debug-hints. Using numbers within a large range of
	 * [1000, 1001000], thus the chances of (annoying but harmless)
	 * collision are low.
	 */
	uint64_t next;

	next = (cme->fd_index++ % 1000000) + 1000;
	return (int)next;
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

/* Reference to libcephfs low-level elements, cached via fsp-extension */
struct vfs_ceph_fe {
	/* current active mount */
	struct vfs_ceph_mnt_entry *cme;
	/* libcephfs' low-level (opaque) inode pointer */
	struct Inode *inode;
	/* libcephfs' low-level (opaque) file-handle (by open/create) */
	struct Fh *fh;
	/* inode-number correlating to Inode (cached) */
	long ino;
	/* vfs_ceph's "pseudo" file-descriptor number (debug only) */
	int fd;
};

static int vfs_ceph_release_fe(struct vfs_ceph_fe *cfe)
{
	int ret = 0;

	if (cfe->fh != NULL) {
		CEPH_DBG("close: ino=%ld fd=%d", cfe->ino, cfe->fd);
		ret = ceph_ll_close(cfe->cme->cmount, cfe->fh);
		CEPH_DBGRET(ret);
		cfe->fh = NULL;
		cfe->fd = -1;
	}
	if (cfe->inode != NULL) {
		CEPH_DBG("put: ino=%ld", cfe->ino);
		ceph_ll_put(cfe->cme->cmount, cfe->inode);
		cfe->inode = NULL;
	}
	return ret;
}

static void vfs_ceph_fsp_ext_destroy_cb(void *p_data)
{
	vfs_ceph_release_fe((struct vfs_ceph_fe *)p_data);
}

static int vfs_ceph_add_fe(struct vfs_handle_struct *handle,
			   files_struct *fsp,
			   struct vfs_ceph_fe **out_cfe)
{
	*out_cfe = VFS_ADD_FSP_EXTENSION(handle,
					 fsp,
					 struct vfs_ceph_fe,
					 vfs_ceph_fsp_ext_destroy_cb);
	if (*out_cfe == NULL) {
		return -ENOMEM;
	}

	(*out_cfe)->inode = NULL;
	(*out_cfe)->ino = 0;
	(*out_cfe)->fh = NULL;
	(*out_cfe)->fd = -1;
	(*out_cfe)->cme = handle->data;
	return 0;
}

static void vfs_ceph_remove_fe(struct vfs_handle_struct *handle,
			       files_struct *fsp)
{
	CEPH_DBG("remove_fh: %s", fsp->fsp_name->base_name);
	VFS_REMOVE_FSP_EXTENSION(handle, fsp);
}

static int vfs_ceph_fetch_fe(struct vfs_handle_struct *handle,
			     const struct files_struct *fsp,
			     struct vfs_ceph_fe **out_cfe)
{
	CEPH_DBG("fetch_fh: %s", fsp->fsp_name->base_name);
	*out_cfe = VFS_FETCH_FSP_EXTENSION(handle, fsp);
	return (*out_cfe == NULL) ? -EBADF : 0;
}

static int vfs_ceph_require_fe(struct vfs_handle_struct *handle,
			       files_struct *fsp,
			       struct vfs_ceph_fe **out_cfe)
{
	int ret = 0;

	*out_cfe = VFS_FETCH_FSP_EXTENSION(handle, fsp);
	if (*out_cfe == NULL) {
		ret = vfs_ceph_add_fe(handle, fsp, out_cfe);
	}
	return ret;
}

/* Ceph user-credentials */
static struct UserPerm *vfs_ceph_userperm_new(
	const struct vfs_handle_struct *handle)
{
	const struct security_unix_token *unix_token = NULL;

	unix_token = handle->conn->session_info->unix_token;
	return ceph_userperm_new(unix_token->uid,
				 unix_token->gid,
				 unix_token->ngroups,
				 unix_token->groups);
}

static void vfs_ceph_userperm_del(struct UserPerm *perms)
{
	if (perms != NULL) {
		ceph_userperm_destroy(perms);
	}
}

/* Ceph low-level wrappers */
static int vfs_ceph_ll_lookup_inode(const struct vfs_handle_struct *handle,
				    ino_t inoval,
				    Inode **pout)
{
	struct inodeno_t ino = {.val = inoval};

	return ceph_ll_lookup_inode(cmount_of(handle), ino, pout);
}

static int vfs_ceph_ll_walk(const struct vfs_handle_struct *handle,
			    const char *name,
			    struct Inode **pin,
			    struct ceph_statx *stx,
			    unsigned int want,
			    unsigned int flags)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_walk(cmount_of(handle),
			   name,
			   pin,
			   stx,
			   want,
			   flags,
			   perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_mkdir(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_fe *parent_dircfe,
			     const char *name,
			     mode_t mode,
			     struct vfs_ceph_fe *dircfe)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct UserPerm *perms = NULL;
	struct Inode *inode = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_mkdir(cmount_of(handle),
			    parent_dircfe->inode,
			    name,
			    mode,
			    &inode,
			    &stx,
			    CEPH_STATX_INO,
			    0,
			    perms);
	if (ret == 0) {
		dircfe->inode = inode;
		dircfe->ino = (long)stx.stx_ino;
	}
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_link(const struct vfs_handle_struct *handle,
			    const struct vfs_ceph_fe *dircfe,
			    const char *name,
			    const struct vfs_ceph_fe *cfe)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_link(cmount_of(handle),
			   cfe->inode,
			   dircfe->inode,
			   name,
			   perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_opendir(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_fe *dircfe,
			       struct ceph_dir_result **dirpp)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_opendir(cmount_of(handle), dircfe->inode, dirpp, perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static struct dirent *vfs_ceph_ll_readdir(const struct vfs_handle_struct *hndl,
					  struct ceph_dir_result *dirp)
{
	return ceph_readdir(cmount_of(hndl), dirp);
}

static void vfs_ceph_ll_rewinddir(const struct vfs_handle_struct *handle,
				  struct ceph_dir_result *dirp)
{
	ceph_rewinddir(cmount_of(handle), dirp);
}

static int vfs_ceph_ll_releasedir(const struct vfs_handle_struct *handle,
				  struct ceph_dir_result *dirp)
{
	return ceph_ll_releasedir(cmount_of(handle), dirp);
}

static int vfs_ceph_ll_rename(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_fe *parent,
			      const char *name,
			      const struct vfs_ceph_fe *newparent,
			      const char *newname)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_rename(cmount_of(handle),
			     parent->inode,
			     name,
			     parent->inode,
			     newname,
			     perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_statfs(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_fe *cfe,
			      struct statvfs *stbuf)
{
	return ceph_ll_statfs(cmount_of(handle), cfe->inode, stbuf);
}

static int vfs_ceph_ll_readlink(const struct vfs_handle_struct *handle,
				const struct vfs_ceph_fe *cfe,
				char *buf,
				size_t bsz)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_readlink(cmount_of(handle), cfe->inode, buf, bsz, perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_symlink(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_fe *dircfe,
			       const char *name,
			       const char *value,
			       struct vfs_ceph_fe *cfe)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct UserPerm *perms = NULL;
	struct Inode *inode = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_symlink(cmount_of(handle),
			      dircfe->inode,
			      name,
			      value,
			      &inode,
			      &stx,
			      CEPH_STATX_INO,
			      0,
			      perms);
	if (ret == 0) {
		cfe->inode = inode;
		cfe->ino = (long)stx.stx_ino;
	}
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_lookup(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_fe *dircfe,
			      const char *name,
			      struct vfs_ceph_fe *cfe)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct UserPerm *perms = NULL;
	struct Inode *inode = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_lookup(cmount_of(handle),
			     dircfe->inode,
			     name,
			     &inode,
			     &stx,
			     CEPH_STATX_INO,
			     0,
			     perms);
	if (ret == 0) {
		cfe->inode = inode;
		cfe->ino = (long)stx.stx_ino;
	}
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_create(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_fe *dircfe,
			      const char *name,
			      mode_t mode,
			      int oflags,
			      struct vfs_ceph_fe *cfe)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct UserPerm *perms = NULL;
	struct Inode *inode = NULL;
	struct Fh *fh = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_create(cmount_of(handle),
			     dircfe->inode,
			     name,
			     mode,
			     oflags,
			     &inode,
			     &fh,
			     &stx,
			     CEPH_STATX_INO,
			     0,
			     perms);
	if (ret == 0) {
		cfe->inode = inode;
		cfe->ino = (long)stx.stx_ino;
		cfe->fh = fh;
		cfe->fd = vfs_ceph_mnt_next_fd(cfe->cme);
	}
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_open(const struct vfs_handle_struct *handle,
			    struct vfs_ceph_fe *cfe,
			    int flags)
{
	struct ceph_mount_info *cmount = cmount_of(handle);
	struct UserPerm *perms = NULL;
	struct Fh *fh = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_open(cmount, cfe->inode, flags, &fh, perms);
	if (ret == 0) {
		cfe->fh = fh;
		cfe->fd = vfs_ceph_mnt_next_fd(cfe->cme);
	}
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_mknod(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_fe *parent,
			     const char *name,
			     mode_t mode,
			     dev_t rdev,
			     struct vfs_ceph_fe *cfe)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct UserPerm *perms = NULL;
	struct Inode *inode = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_mknod(cmount_of(handle),
			    parent->inode,
			    name,
			    mode,
			    rdev,
			    &inode,
			    &stx,
			    CEPH_STATX_INO,
			    0,
			    perms);
	if (ret == 0) {
		cfe->inode = inode;
		cfe->ino = (long)stx.stx_ino;
	}
	vfs_ceph_userperm_del(perms);
	return ret;
}

static off_t vfs_ceph_ll_lseek(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_fe *cfe,
			       off_t offset,
			       int whence)
{
	return ceph_ll_lseek(cmount_of(handle), cfe->fh, offset, whence);
}

static int vfs_ceph_ll_read(const struct vfs_handle_struct *handle,
			    const struct vfs_ceph_fe *cfe,
			    int64_t off,
			    uint64_t len,
			    char *buf)
{
	return ceph_ll_read(cmount_of(handle), cfe->fh, off, len, buf);
}

static int vfs_ceph_ll_write(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_fe *cfe,
			     int64_t off,
			     uint64_t len,
			     const char *data)
{
	return ceph_ll_write(cmount_of(handle), cfe->fh, off, len, data);
}

static int vfs_ceph_ll_fsync(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_fe *cfe,
			     int syncdataonly)
{
	return ceph_ll_fsync(cmount_of(handle), cfe->fh, syncdataonly);
}

static int vfs_ceph_ll_getattr(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_fe *cfe,
			       struct ceph_statx *stx,
			       unsigned int want,
			       unsigned int flags)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_getattr(cmount_of(handle),
			      cfe->inode,
			      stx,
			      want,
			      flags,
			      perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

#define SAMBA_STATX_ATTR_MASK (CEPH_STATX_BASIC_STATS | CEPH_STATX_BTIME)

static void smb_stat_from_ceph_statx(SMB_STRUCT_STAT *st,
				     const struct ceph_statx *stx)
{
	ZERO_STRUCTP(st);

	st->st_ex_dev = stx->stx_dev;
	st->st_ex_rdev = stx->stx_rdev;
	st->st_ex_ino = stx->stx_ino;
	st->st_ex_mode = stx->stx_mode;
	st->st_ex_uid = stx->stx_uid;
	st->st_ex_gid = stx->stx_gid;
	st->st_ex_size = stx->stx_size;
	st->st_ex_nlink = stx->stx_nlink;
	st->st_ex_atime = stx->stx_atime;
	st->st_ex_btime = stx->stx_btime;
	st->st_ex_ctime = stx->stx_ctime;
	st->st_ex_mtime = stx->stx_mtime;
	st->st_ex_blksize = stx->stx_blksize;
	st->st_ex_blocks = stx->stx_blocks;
}

static int vfs_ceph_ll_stat(struct vfs_handle_struct *handle,
			    const struct vfs_ceph_fe *cfe,
			    SMB_STRUCT_STAT *st)
{
	struct ceph_statx stx = {0};
	int ret = -1;

	ret = vfs_ceph_ll_getattr(handle, cfe, &stx, SAMBA_STATX_ATTR_MASK, 0);
	if (ret == 0) {
		smb_stat_from_ceph_statx(st, &stx);
	}
	return ret;
}

static int vfs_ceph_ll_setattr(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_fe *cfe,
			       struct ceph_statx *stx,
			       int mask)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_setattr(cmount_of(handle), cfe->inode, stx, mask, perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_chmod(struct vfs_handle_struct *handle,
			     const struct vfs_ceph_fe *cfe,
			     mode_t mode)
{
	struct ceph_statx stx = {.stx_mode = mode};

	return vfs_ceph_ll_setattr(handle, cfe, &stx, CEPH_STATX_MODE);
}

static int vfs_ceph_ll_chown(struct vfs_handle_struct *handle,
			     const struct vfs_ceph_fe *cfe,
			     uid_t uid,
			     gid_t gid)
{
	struct ceph_statx stx = {.stx_uid = uid, .stx_gid = gid};

	return vfs_ceph_ll_setattr(handle,
				   cfe,
				   &stx,
				   CEPH_STATX_UID | CEPH_STATX_GID);
}

static int vfs_ceph_ll_utimes(struct vfs_handle_struct *handle,
			      const struct vfs_ceph_fe *cfe,
			      const struct smb_file_time *ft)
{
	struct ceph_statx stx = {0};
	int mask = 0;

	if (!is_omit_timespec(&ft->atime)) {
		stx.stx_atime = ft->atime;
		mask |= CEPH_SETATTR_ATIME;
	}
	if (!is_omit_timespec(&ft->mtime)) {
		stx.stx_mtime = ft->mtime;
		mask |= CEPH_SETATTR_MTIME;
	}
	if (!is_omit_timespec(&ft->ctime)) {
		stx.stx_ctime = ft->ctime;
		mask |= CEPH_SETATTR_CTIME;
	}
	if (!is_omit_timespec(&ft->create_time)) {
		stx.stx_btime = ft->create_time;
		mask |= CEPH_SETATTR_BTIME;
	}
	return mask ? vfs_ceph_ll_setattr(handle, cfe, &stx, mask) : 0;
}

static int vfs_ceph_ll_truncate(struct vfs_handle_struct *handle,
				const struct vfs_ceph_fe *cfe,
				uint64_t size)
{
	struct ceph_statx stx = {.stx_size = size};

	return vfs_ceph_ll_setattr(handle, cfe, &stx, CEPH_SETATTR_SIZE);
}

static int vfs_ceph_ll_fallocate(const struct vfs_handle_struct *handle,
				 const struct vfs_ceph_fe *cfe,
				 int mode,
				 int64_t off,
				 int64_t len)
{
	return ceph_ll_fallocate(cmount_of(handle), cfe->fh, mode, off, len);
}

static int vfs_ceph_ll_rmdir(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_fe *dircfe,
			     const char *name)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_rmdir(cmount_of(handle), dircfe->inode, name, perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_unlink(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_fe *dircfe,
			      const char *name)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_unlink(cmount_of(handle), dircfe->inode, name, perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_getxattr(const struct vfs_handle_struct *handle,
				const struct vfs_ceph_fe *cfe,
				const char *name,
				void *value,
				size_t size)
{
	struct ceph_mount_info *cmount = cmount_of(handle);
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_getxattr(cmount, cfe->inode, name, value, size, perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_setxattr(const struct vfs_handle_struct *handle,
				const struct vfs_ceph_fe *cfe,
				const char *name,
				const void *value,
				size_t size,
				int flags)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_setxattr(cmount_of(handle),
			       cfe->inode,
			       name,
			       value,
			       size,
			       flags,
			       perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_listxattr(const struct vfs_handle_struct *handle,
				 const struct vfs_ceph_fe *cfe,
				 char *list,
				 size_t buf_size,
				 size_t *list_size)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_listxattr(cmount_of(handle),
				cfe->inode,
				list,
				buf_size,
				list_size,
				perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_removexattr(const struct vfs_handle_struct *handle,
				   const struct vfs_ceph_fe *cfe,
				   const char *name)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_removexattr(cmount_of(handle), cfe->inode, name, perms);
	vfs_ceph_userperm_del(perms);
	return ret;
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

static int vfs_ceph_iget(struct vfs_handle_struct *handle,
			 const char *name,
			 unsigned int flags,
			 struct vfs_ceph_fe *cfe)
{
	struct Inode *inode = NULL;
	int ret = 0;

	/* already hold reference to libcephfs Inode -- no op */
	if (cfe->inode != NULL) {
		goto out;
	}

	if (cfe->ino != 0) {
		/* fast: ino is known, but does not hold in-memroy reference
		 * to libcephfs Inode. Resolve by lookup */
		CEPH_DBG("lookup_inode: ino=%ld", (long)cfe->ino);
		ret = vfs_ceph_ll_lookup_inode(handle, cfe->ino, &inode);
		if (ret != 0) {
			goto out;
		}
	} else {
		/* slow: full resolve by name (ino + Inode reference) */
		struct ceph_statx stx = {.stx_ino = 0};

		CEPH_DBG("walk: %s", name);
		ret = vfs_ceph_ll_walk(handle,
				       name,
				       &inode,
				       &stx,
				       CEPH_STATX_INO,
				       flags);
		if (ret != 0) {
			goto out;
		}
		cfe->ino = (long)stx.stx_ino;
	}
	cfe->inode = inode;
out:
	CEPH_DBGRET(ret);
	return ret;
}

static int vfs_ceph_iget_by_fname(struct vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname,
				  struct vfs_ceph_fe *cfe)
{
	const char *name = smb_fname->base_name;
	const char *cwd = ceph_getcwd(cmount_of(handle));
	int ret = -1;

	if (!strcmp(name, cwd)) {
		ret = vfs_ceph_iget(handle, "./", 0, cfe);
	} else {
		ret = vfs_ceph_iget(handle, name, 0, cfe);
	}
	return ret;
}

static int vfs_ceph_igetf(struct vfs_handle_struct *handle,
			  const struct files_struct *fsp,
			  struct vfs_ceph_fe *cfe)
{
	return vfs_ceph_iget(handle, fsp->fsp_name->base_name, 0, cfe);
}

static int vfs_ceph_igetl(struct vfs_handle_struct *handle,
			  const struct smb_filename *smb_fname,
			  struct vfs_ceph_fe *cfe)
{
	return vfs_ceph_iget(handle,
			     smb_fname->base_name,
			     AT_SYMLINK_NOFOLLOW,
			     cfe);
}

static int vfs_ceph_igetd(struct vfs_handle_struct *handle,
			  const struct files_struct *dirfsp,
			  struct vfs_ceph_fe *dircfe)
{
	int ret = -1;

	if (fsp_get_pathref_fd(dirfsp) == AT_FDCWD) {
		CEPH_DBG("igetd: AT_FDCWD: %s",
			 handle->conn->cwd_fsp->fsp_name->base_name);
		ret = vfs_ceph_iget(handle, ".", 0, dircfe);
	} else {
		ret = vfs_ceph_iget(handle,
				    dirfsp->fsp_name->base_name,
				    0,
				    dircfe);
	}
	return ret;
}

static void vfs_ceph_iput(struct vfs_handle_struct *handle,
			  struct vfs_ceph_fe *cfe)
{
	if ((cfe != NULL) && (cfe->inode != NULL)) {
		CEPH_DBG("put: ino=%ld", cfe->ino);
		ceph_ll_put(cmount_of(handle), cfe->inode);
		cfe->inode = NULL;
	}
}

static uint64_t vfs_ceph_disk_free(struct vfs_handle_struct *handle,
				   const struct smb_filename *smb_fname,
				   uint64_t *bsize,
				   uint64_t *dfree,
				   uint64_t *dsize)
{
	struct statvfs stv = {0};
	struct ceph_mount_info *cmount = cmount_of(handle);
	struct Inode *inode = NULL;
	int ret = -1;

	ret = ceph_ll_lookup_root(cmount, &inode);
	if (ret == 0) {
		ret = ceph_ll_statfs(cmount, inode, &stv);
		ceph_ll_put(cmount, inode);
	}
	if (ret != 0) {
		update_errno(ret);
		return (uint64_t)(-1);
	}
	*bsize = (uint64_t)stv.f_bsize;
	*dfree = (uint64_t)stv.f_bavail;
	*dsize = (uint64_t)stv.f_blocks;
	return *dfree;
}

static void statvfs_to_smb(const struct statvfs *stvfs,
			   struct vfs_statvfs_struct *out_stvfs)
{
	out_stvfs->OptimalTransferSize = stvfs->f_frsize;
	out_stvfs->BlockSize = stvfs->f_bsize;
	out_stvfs->TotalBlocks = stvfs->f_blocks;
	out_stvfs->BlocksAvail = stvfs->f_bfree;
	out_stvfs->UserBlocksAvail = stvfs->f_bavail;
	out_stvfs->TotalFileNodes = stvfs->f_files;
	out_stvfs->FreeFileNodes = stvfs->f_ffree;
	out_stvfs->FsIdentifier = stvfs->f_fsid;
}

static int vfs_ceph_statvfs(struct vfs_handle_struct *handle,
			    const struct smb_filename *smb_fname,
			    struct vfs_statvfs_struct *out_stvfs)
{
	struct statvfs stvfs = {0};
	struct vfs_ceph_fe cfe = {.cme = handle->data};
	int ret = -1;

	ret = vfs_ceph_iget_by_fname(handle, smb_fname, &cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("statvfs: %s ino=%ld", smb_fname->base_name, cfe.ino);
	ret = vfs_ceph_ll_statfs(handle, &cfe, &stvfs);
	if (ret != 0) {
		goto out;
	}
	statvfs_to_smb(&stvfs, out_stvfs);
out:
	vfs_ceph_iput(handle, &cfe);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static uint32_t vfs_ceph_fs_capabilities(struct vfs_handle_struct *handle,
					 enum timestamp_set_resolution *res)
{
	*res = TIMESTAMP_SET_NT_OR_BETTER;

	return FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;
}

/* Directory operations */
static DIR *vfs_ceph_fdopendir(struct vfs_handle_struct *handle,
			       struct files_struct *dirfsp,
			       const char *mask,
			       uint32_t attributes)
{
	struct vfs_ceph_fe *dircfe = NULL;
	struct ceph_dir_result *dirp = NULL;
	int ret = 0;

	ret = vfs_ceph_require_fe(handle, dirfsp, &dircfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetd(handle, dirfsp, dircfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("opendir: %s ino=%ld",
		 dirfsp->fsp_name->base_name,
		 dircfe->ino);
	ret = vfs_ceph_ll_opendir(handle, dircfe, &dirp);
	vfs_ceph_iput(handle, dircfe);
out:
	CEPH_DBGRET(ret);
	return dstatus_code(dirp, ret);
}

static struct dirent *vfs_ceph_readdir(struct vfs_handle_struct *handle,
				       struct files_struct *dirfsp,
				       DIR *dirp)
{
	struct dirent *de = NULL;

	CEPH_DBG("readdir: %s", dirfsp->fsp_name->base_name);
	de = vfs_ceph_ll_readdir(handle, (struct ceph_dir_result *)dirp);
	return de;
}

static void vfs_ceph_rewinddir(struct vfs_handle_struct *handle, DIR *dirp)
{
	vfs_ceph_ll_rewinddir(handle, (struct ceph_dir_result *)dirp);
}

static int vfs_ceph_mkdirat(struct vfs_handle_struct *handle,
			    files_struct *dirfsp,
			    const struct smb_filename *smb_fname,
			    mode_t mode)
{
	struct vfs_ceph_fe *dircfe = NULL;
	struct vfs_ceph_fe cfe = {.cme = handle->data};
	int ret = -1;

	ret = vfs_ceph_require_fe(handle, dirfsp, &dircfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetd(handle, dirfsp, dircfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("mkdirat: %s dino=%ld name=%s mode=0%o",
		 dirfsp->fsp_name->base_name,
		 dircfe->ino,
		 smb_fname->base_name,
		 mode);
	ret = vfs_ceph_ll_mkdir(handle,
				dircfe,
				smb_fname->base_name,
				mode,
				&cfe);
	vfs_ceph_iput(handle, &cfe);
	vfs_ceph_iput(handle, dircfe);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_closedir(struct vfs_handle_struct *handle, DIR *dirp)
{
	int ret = -1;

	CEPH_DBG("releasedir: dirp=%p", dirp);
	ret = vfs_ceph_ll_releasedir(handle, (struct ceph_dir_result *)dirp);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

/* File operations */
static int vfs_ceph_openat(struct vfs_handle_struct *handle,
			   const struct files_struct *dirfsp,
			   const struct smb_filename *smb_fname,
			   files_struct *fsp,
			   const struct vfs_open_how *how)
{
	struct vfs_ceph_fe *dircfe = NULL;
	struct vfs_ceph_fe *cfe = NULL;
	int o_flags = how->flags;
	int mode = how->mode;
	bool have_opath = false;
	bool became_root = false;
	int ret = -ENOMEM;

	if (how->resolve != 0) {
		return status_code(-ENOSYS);
	}
	if (smb_fname->stream_name) {
		return status_code(-ENOENT);
	}
	ret = vfs_ceph_fetch_fe(handle, dirfsp, &dircfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_add_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}

#ifdef O_PATH
	have_opath = true;
	if (fsp->fsp_flags.is_pathref) {
		o_flags |= O_PATH;
	}
#endif

	if (fsp->fsp_flags.is_pathref && !have_opath) {
		become_root();
		became_root = true;
	}

	ret = vfs_ceph_igetd(handle, dirfsp, dircfe);
	if (ret != 0) {
		goto out;
	}

	if (o_flags & O_CREAT) {
		CEPH_DBG("create: dino=%ld name=%s mode=%o o_flags=0%o",
			 dircfe->ino,
			 smb_fname->base_name,
			 mode,
			 o_flags);
		ret = vfs_ceph_ll_create(handle,
					 dircfe,
					 smb_fname->base_name,
					 mode,
					 o_flags,
					 cfe);
		if (ret < 0) {
			goto out;
		}
		CEPH_DBG("create-ok: ino=%ld fd=%d", cfe->ino, cfe->fd);

	} else {
		CEPH_DBG("lookup: dino=%ld name=%s",
			 dircfe->ino,
			 smb_fname->base_name);
		ret = vfs_ceph_ll_lookup(handle,
					 dircfe,
					 smb_fname->base_name,
					 cfe);
		if (ret != 0) {
			goto out;
		}

		CEPH_DBG("open: ino=%ld o_flags=0%o", cfe->ino, o_flags);
		ret = vfs_ceph_ll_open(handle, cfe, o_flags);
		if (ret < 0) {
			goto out;
		}
		CEPH_DBG("open-ok: ino=%ld fd=%d", cfe->ino, cfe->fd);
	}
	ret = cfe->fd;
out:
	if (became_root) {
		unbecome_root();
	}
	vfs_ceph_iput(handle, cfe);
	vfs_ceph_iput(handle, dircfe);
	fsp->fsp_flags.have_proc_fds = false;
	if (ret < 0) {
		vfs_ceph_remove_fe(handle, fsp);
	}
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_close(struct vfs_handle_struct *handle, files_struct *fsp)
{
	struct vfs_ceph_fe *cfe = NULL;
	int ret = -1;

	CEPH_DBG("close: %s", fsp->fsp_name->base_name);
	ret = vfs_ceph_fetch_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_release_fe(cfe);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static ssize_t vfs_ceph_pread(struct vfs_handle_struct *handle,
			      files_struct *fsp,
			      void *data,
			      size_t len,
			      off_t off)
{
	struct vfs_ceph_fe *cfe = NULL;
	int ret = -1;

	ret = vfs_ceph_fetch_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("read: ino=%ld fd=%d off=%jd len=%zu",
		 cfe->ino,
		 cfe->fd,
		 (intmax_t)off,
		 len);
	ret = vfs_ceph_ll_read(handle, cfe, off, len, data);
out:
	CEPH_DBGRET(ret);
	return lstatus_code(ret);
}

/* Fake up an async ceph read by calling the synchronous API */
struct vfs_ceph_pread_state {
	struct vfs_aio_state vfs_aio_state;
	ssize_t bytes_read;
};

static struct tevent_req *vfs_ceph_pread_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      void *data,
					      size_t len,
					      off_t off)
{
	struct vfs_ceph_fe *cfe = NULL;
	struct tevent_req *req = NULL;
	struct vfs_ceph_pread_state *state = NULL;
	int ret = -1;

	ret = vfs_ceph_fetch_fe(handle, fsp, &cfe);
	if (ret != 0) {
		update_errno(ret);
		return NULL;
	}
	req = tevent_req_create(mem_ctx, &state, struct vfs_ceph_pread_state);
	if (req == NULL) {
		return NULL;
	}

	CEPH_DBG("read: ino=%ld fd=%d off=%jd len=%zu",
		 cfe->ino,
		 cfe->fd,
		 (intmax_t)off,
		 len);
	ret = vfs_ceph_ll_read(handle, cfe, off, len, data);
	if (ret < 0) {
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}
	state->bytes_read = ret;
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static ssize_t vfs_ceph_pread_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_ceph_pread_state *state = NULL;

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	state = tevent_req_data(req, struct vfs_ceph_pread_state);
	CEPH_DBG("bytes_read=%zd error=%d",
		 state->bytes_read,
		 state->vfs_aio_state.error);
	*vfs_aio_state = state->vfs_aio_state;
	return state->bytes_read;
}

static ssize_t vfs_ceph_pwrite(struct vfs_handle_struct *handle,
			       files_struct *fsp,
			       const void *data,
			       size_t len,
			       off_t off)
{
	struct vfs_ceph_fe *cfe = NULL;
	int ret = -1;

	ret = vfs_ceph_fetch_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("write: ino=%ld fd=%d len=%zu off=%jd",
		 cfe->ino,
		 cfe->fd,
		 len,
		 (intmax_t)off);
	ret = vfs_ceph_ll_write(handle, cfe, off, len, data);
out:
	CEPH_DBGRET(ret);
	return lstatus_code(ret);
}

/* Fake up an async ceph write by calling the synchronous API */

struct vfs_ceph_pwrite_state {
	struct vfs_aio_state vfs_aio_state;
	ssize_t bytes_written;
};

static struct tevent_req *vfs_ceph_pwrite_send(struct vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct files_struct *fsp,
					       const void *data,
					       size_t len,
					       off_t off)
{
	struct vfs_ceph_fe *cfe = NULL;
	struct tevent_req *req = NULL;
	struct vfs_ceph_pwrite_state *state = NULL;
	int ret = -1;

	ret = vfs_ceph_fetch_fe(handle, fsp, &cfe);
	if (ret != 0) {
		update_errno(ret);
		return NULL;
	}
	req = tevent_req_create(mem_ctx, &state, struct vfs_ceph_pwrite_state);
	if (req == NULL) {
		return NULL;
	}
	CEPH_DBG("write: ino=%ld fd=%d len=%zu off=%jd",
		 cfe->ino,
		 cfe->fd,
		 len,
		 (intmax_t)off);
	ret = vfs_ceph_ll_write(handle, cfe, off, len, data);
	if (ret < 0) {
		update_errno(ret);
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}
	state->bytes_written = ret;
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static ssize_t vfs_ceph_pwrite_recv(struct tevent_req *req,
				    struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_ceph_pwrite_state *state = NULL;

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	state = tevent_req_data(req, struct vfs_ceph_pwrite_state);
	*vfs_aio_state = state->vfs_aio_state;
	return state->bytes_written;
}

static off_t vfs_ceph_lseek(struct vfs_handle_struct *handle,
			    files_struct *fsp,
			    off_t offset,
			    int whence)
{
	struct vfs_ceph_fe *cfe = NULL;
	int64_t ret = -1;

	ret = vfs_ceph_fetch_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("lseek: ino=%ld fd=%d offset=%jd whence=%d",
		 cfe->ino,
		 cfe->fd,
		 (intmax_t)offset,
		 whence);
	ret = vfs_ceph_ll_lseek(handle, cfe, offset, whence);
out:
	CEPH_DBGRET(ret);
	return lstatus_code(ret);
}

static int vfs_ceph_renameat(struct vfs_handle_struct *handle,
			     files_struct *dirfsp_src,
			     const struct smb_filename *smb_fname_src,
			     files_struct *dirfsp_dst,
			     const struct smb_filename *smb_fname_dst)
{
	struct vfs_ceph_fe *dircfe_src = NULL;
	struct vfs_ceph_fe *dircfe_dst = NULL;
	int ret = -1;

	if (smb_fname_src->stream_name || smb_fname_dst->stream_name) {
		return status_code(-ENOENT);
	}
	ret = vfs_ceph_require_fe(handle, dirfsp_src, &dircfe_src);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetd(handle, dirfsp_src, dircfe_src);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_require_fe(handle, dirfsp_dst, &dircfe_dst);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetd(handle, dirfsp_dst, dircfe_dst);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("rename: dino=%ld name=%s new-dino=%ld newname=%s",
		 dircfe_src->ino,
		 smb_fname_src->base_name,
		 dircfe_dst->ino,
		 smb_fname_dst->base_name);
	ret = vfs_ceph_ll_rename(handle,
				 dircfe_src,
				 smb_fname_src->base_name,
				 dircfe_dst,
				 smb_fname_dst->base_name);
out:
	vfs_ceph_iput(handle, dircfe_src);
	vfs_ceph_iput(handle, dircfe_dst);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static struct tevent_req *vfs_ceph_fsync_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      files_struct *fsp)
{
	struct vfs_ceph_fe *cfe = NULL;
	struct tevent_req *req = NULL;
	struct vfs_aio_state *state = NULL;
	int ret = -1;

	ret = vfs_ceph_fetch_fe(handle, fsp, &cfe);
	if (ret != 0) {
		update_errno(ret);
		return NULL;
	}
	req = tevent_req_create(mem_ctx, &state, struct vfs_aio_state);
	if (req == NULL) {
		return NULL;
	}
	CEPH_DBG("fsync: ino=%ld fd=%d", cfe->ino, cfe->fd);
	ret = vfs_ceph_ll_fsync(handle, cfe, 0);
	if (ret != 0) {
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static int vfs_ceph_fsync_recv(struct tevent_req *req,
			       struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_aio_state *state = tevent_req_data(req,
						      struct vfs_aio_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = *state;
	return 0;
}

static int vfs_ceph_stat(struct vfs_handle_struct *handle,
			 struct smb_filename *smb_fname)
{
	struct vfs_ceph_fe cfe = {.cme = handle->data};
	int ret = -1;

	if (smb_fname->stream_name) {
		return status_code(-ENOENT);
	}
	ret = vfs_ceph_iget_by_fname(handle, smb_fname, &cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("stat: ino=%ld", cfe.ino);
	ret = vfs_ceph_ll_stat(handle, &cfe, &smb_fname->st);
	vfs_ceph_iput(handle, &cfe);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_fstat(struct vfs_handle_struct *handle,
			  files_struct *fsp,
			  SMB_STRUCT_STAT *st)
{
	struct vfs_ceph_fe *cfe = NULL;
	int ret = -1;

	ret = vfs_ceph_fetch_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("stat: ino=%ld fd=%d", cfe->ino, cfe->fd);
	ret = vfs_ceph_ll_stat(handle, cfe, st);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_lstat(struct vfs_handle_struct *handle,
			  struct smb_filename *smb_fname)
{
	struct vfs_ceph_fe cfe = {.cme = handle->data};
	int ret = -1;

	if (smb_fname->stream_name) {
		return status_code(-ENOENT);
	}
	ret = vfs_ceph_igetl(handle, smb_fname, &cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("stat: ino=%ld", cfe.ino);
	ret = vfs_ceph_ll_stat(handle, &cfe, &smb_fname->st);
	vfs_ceph_iput(handle, &cfe);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_fstatat(struct vfs_handle_struct *handle,
			    const struct files_struct *dirfsp,
			    const struct smb_filename *smb_fname,
			    SMB_STRUCT_STAT *st,
			    int flags)
{
	struct vfs_ceph_fe *dircfe = NULL;
	struct vfs_ceph_fe cfe = {.cme = handle->data};
	int ret = -1;

	if (dirfsp->fsp_name->stream_name || smb_fname->stream_name) {
		return status_code(-ENOENT);
	}
	ret = vfs_ceph_fetch_fe(handle, dirfsp, &dircfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetd(handle, dirfsp, dircfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("lookup: dino=%ld name=%s", dircfe->ino, smb_fname->base_name);
	ret = vfs_ceph_ll_lookup(handle, dircfe, smb_fname->base_name, &cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("stat: ino=%ld", cfe.ino);
	ret = vfs_ceph_ll_stat(handle, &cfe, st);
out:
	vfs_ceph_iput(handle, &cfe);
	vfs_ceph_iput(handle, dircfe);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_unlinkat(struct vfs_handle_struct *handle,
			     struct files_struct *dirfsp,
			     const struct smb_filename *smb_fname,
			     int flags)
{
	struct vfs_ceph_fe *dircfe = NULL;
	int ret = -1;

	if (smb_fname->stream_name) {
		return status_code(-ENOENT);
	}
	ret = vfs_ceph_require_fe(handle, dirfsp, &dircfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetd(handle, dirfsp, dircfe);
	if (ret != 0) {
		goto out;
	}
	if (flags & AT_REMOVEDIR) {
		CEPH_DBG("rmdir: dino=%ld name=%s",
			 dircfe->ino,
			 smb_fname->base_name);
		ret = vfs_ceph_ll_rmdir(handle, dircfe, smb_fname->base_name);
	} else {
		CEPH_DBG("unlink: dino=%ld name=%s",
			 dircfe->ino,
			 smb_fname->base_name);
		ret = vfs_ceph_ll_unlink(handle, dircfe, smb_fname->base_name);
	}
	vfs_ceph_iput(handle, dircfe);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_fchmod(struct vfs_handle_struct *handle,
			   files_struct *fsp,
			   mode_t mode)
{
	struct vfs_ceph_fe *cfe = NULL;
	int ret = -1;

	ret = vfs_ceph_require_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetf(handle, fsp, cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("chmod: ino=%ld fd=%d mode=%o", cfe->ino, cfe->fd, mode);
	ret = vfs_ceph_ll_chmod(handle, cfe, mode);
	vfs_ceph_iput(handle, cfe);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_fchown(struct vfs_handle_struct *handle,
			   files_struct *fsp,
			   uid_t uid,
			   gid_t gid)
{
	struct vfs_ceph_fe *cfe = NULL;
	int ret = -1;

	ret = vfs_ceph_require_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetf(handle, fsp, cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("chown: ino=%ld fd=%d uid=%d gid=%d",
		 cfe->ino,
		 cfe->fd,
		 uid,
		 gid);
	ret = vfs_ceph_ll_chown(handle, cfe, uid, gid);
	vfs_ceph_iput(handle, cfe);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_lchown(struct vfs_handle_struct *handle,
			   const struct smb_filename *smb_fname,
			   uid_t uid,
			   gid_t gid)
{
	struct vfs_ceph_fe cfe = {.cme = handle->data};
	int ret = -1;

	ret = vfs_ceph_igetl(handle, smb_fname, &cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("chown: ino=%ld uid=%d gid=%d", cfe.ino, uid, gid);
	ret = vfs_ceph_ll_chown(handle, &cfe, uid, gid);
	vfs_ceph_iput(handle, &cfe);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_fntimes(struct vfs_handle_struct *handle,
			    files_struct *fsp,
			    struct smb_file_time *ft)
{
	struct vfs_ceph_fe *cfe = NULL;
	int ret = -1;

	ret = vfs_ceph_require_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetf(handle, fsp, cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("utimes: ino=%ld fd=%d", cfe->ino, cfe->fd);
	ret = vfs_ceph_ll_utimes(handle, cfe, ft);
	vfs_ceph_iput(handle, cfe);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_chdir(struct vfs_handle_struct *handle,
			  const struct smb_filename *smb_fname)
{
	int ret = -1;

	CEPH_DBG("chdir: %s", smb_fname->base_name);
	ret = ceph_chdir(cmount_of(handle), smb_fname->base_name);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static struct smb_filename *vfs_ceph_getwd(struct vfs_handle_struct *handle,
					   TALLOC_CTX *ctx)
{
	const char *cwd = NULL;

	cwd = ceph_getcwd(cmount_of(handle));
	CEPH_DBG("getwd: %s", cwd);
	return synthetic_smb_fname(ctx, cwd, NULL, NULL, 0, 0);
}

static int vfs_ceph_ftruncate_allocate(struct vfs_handle_struct *handle,
				       files_struct *fsp,
				       off_t len)
{
	struct vfs_ceph_fe *cfe = NULL;
	SMB_STRUCT_STAT *pst = &fsp->fsp_name->st;
	off_t size = 0;
	int ret = -1;

	ret = vfs_ceph_fetch_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_ll_stat(handle, cfe, pst);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("stat-ret: ino=%ld mode=0%o",
		 (long)pst->st_ex_ino,
		 pst->st_ex_mode);

#ifdef S_ISFIFO
	if (S_ISFIFO(pst->st_ex_mode)) {
		return 0;
	}
#endif
	size = pst->st_ex_size;
	if (size > len) {
		CEPH_DBG("truncate: ino=%ld fd=%d len=%jd",
			 cfe->ino,
			 cfe->fd,
			 (intmax_t)len);
		ret = vfs_ceph_ll_truncate(handle, cfe, len);
	} else if (size < len) {
		len = len - size;
		CEPH_DBG("fallocate: ino=%ld fd=%d off=%jd len=%jd",
			 cfe->ino,
			 cfe->fd,
			 (intmax_t)size,
			 (intmax_t)len);
		ret = vfs_ceph_ll_fallocate(handle, cfe, 0, size, len);
	}
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_ftruncate(struct vfs_handle_struct *handle,
			      files_struct *fsp,
			      off_t off)
{
	const struct vfs_ceph_mnt_entry *cme = handle->data;
	struct vfs_ceph_fe *cfe = NULL;
	int ret = -1;

	if (cme->strict_allocate) {
		return vfs_ceph_ftruncate_allocate(handle, fsp, off);
	}
	ret = vfs_ceph_fetch_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("truncate: ino=%ld fd=%d off=%jd",
		 cfe->ino,
		 cfe->fd,
		 (intmax_t)off);
	ret = vfs_ceph_ll_truncate(handle, cfe, (uint64_t)off);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_fallocate(struct vfs_handle_struct *handle,
			      struct files_struct *fsp,
			      uint32_t mode,
			      off_t off,
			      off_t len)
{
	struct vfs_ceph_fe *cfe = NULL;
	int ret = -1;

	ret = vfs_ceph_fetch_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("fallocate: ino=%ld fd=%d mode=%x off=%jd len=%jd",
		 cfe->ino,
		 cfe->fd,
		 mode,
		 (intmax_t)off,
		 (intmax_t)len);
	ret = vfs_ceph_ll_fallocate(handle, cfe, mode, off, len);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_linkat(struct vfs_handle_struct *handle,
			   files_struct *srcfsp,
			   const struct smb_filename *cur_smb_fname,
			   files_struct *dstfsp,
			   const struct smb_filename *new_smb_fname,
			   int flags)
{
	struct vfs_ceph_fe *cur_dircfe = NULL;
	struct vfs_ceph_fe *new_dircfe = NULL;
	struct vfs_ceph_fe cfe = {.cme = handle->data};
	int ret = -1;

	if (cur_smb_fname->stream_name || new_smb_fname->stream_name) {
		return status_code(-ENOENT);
	}
	ret = vfs_ceph_require_fe(handle, srcfsp, &cur_dircfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetd(handle, srcfsp, cur_dircfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_require_fe(handle, dstfsp, &new_dircfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetd(handle, dstfsp, new_dircfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("lookup: dino=%ld name=%s",
		 cur_dircfe->ino,
		 cur_smb_fname->base_name);
	ret = vfs_ceph_ll_lookup(handle,
				 cur_dircfe,
				 cur_smb_fname->base_name,
				 &cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("link: dino=%ld name=%s ino=%ld",
		 new_dircfe->ino,
		 new_smb_fname->base_name,
		 cfe.ino);
	ret = vfs_ceph_ll_link(handle,
			       new_dircfe,
			       new_smb_fname->base_name,
			       &cfe);
	if (ret != 0) {
		goto out;
	}
out:
	vfs_ceph_iput(handle, &cfe);
	vfs_ceph_iput(handle, new_dircfe);
	vfs_ceph_iput(handle, cur_dircfe);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_mknodat(struct vfs_handle_struct *handle,
			    files_struct *dirfsp,
			    const struct smb_filename *smb_fname,
			    mode_t mode,
			    SMB_DEV_T dev)
{
	struct vfs_ceph_fe *dircfe = NULL;
	struct vfs_ceph_fe cfe = {.cme = handle->data};
	int ret = -1;

	ret = vfs_ceph_require_fe(handle, dirfsp, &dircfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetd(handle, dirfsp, dircfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("mknod: dino=%ld name=%s mode=%o dev=%ld",
		 dircfe->ino,
		 smb_fname->base_name,
		 mode,
		 (long)dev);
	ret = vfs_ceph_ll_mknod(handle,
				dircfe,
				smb_fname->base_name,
				mode,
				dev,
				&cfe);
	vfs_ceph_iput(handle, &cfe);
	vfs_ceph_iput(handle, dircfe);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_symlinkat(struct vfs_handle_struct *handle,
			      const struct smb_filename *link_target,
			      struct files_struct *dirfsp,
			      const struct smb_filename *new_smb_fname)
{
	struct vfs_ceph_fe *dircfe = NULL;
	struct vfs_ceph_fe cfe = {.cme = handle->data};
	int ret = -1;

	ret = vfs_ceph_require_fe(handle, dirfsp, &dircfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetd(handle, dirfsp, dircfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("symlink: dino=%ld name=%s target=%s",
		 dircfe->ino,
		 new_smb_fname->base_name,
		 link_target->base_name);
	ret = vfs_ceph_ll_symlink(handle,
				  dircfe,
				  new_smb_fname->base_name,
				  link_target->base_name,
				  &cfe);
out:
	vfs_ceph_iput(handle, &cfe);
	vfs_ceph_iput(handle, dircfe);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_readlinkat(struct vfs_handle_struct *handle,
			       const struct files_struct *dirfsp,
			       const struct smb_filename *smb_fname,
			       char *buf,
			       size_t bufsz)
{
	struct vfs_ceph_fe *dircfe = NULL;
	struct vfs_ceph_fe cfe = {.cme = handle->data};
	int ret = -1;

	ret = vfs_ceph_fetch_fe(handle, dirfsp, &dircfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetd(handle, dirfsp, dircfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("lookup: dino=%ld name=%s", dircfe->ino, smb_fname->base_name);
	ret = vfs_ceph_ll_lookup(handle, dircfe, smb_fname->base_name, &cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("readlink: ino=%ld bufsz=%zu", cfe.ino, bufsz);
	ret = vfs_ceph_ll_readlink(handle, &cfe, buf, bufsz);
out:
	vfs_ceph_iput(handle, &cfe);
	vfs_ceph_iput(handle, dircfe);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static bool vfs_ceph_lock(struct vfs_handle_struct *handle,
			  files_struct *fsp,
			  int op,
			  off_t off,
			  off_t len,
			  int type)
{
	/* TODO: is it possible to map to ceph_ll_getlk/ceph_ll_setlk ? */
	CEPH_DBG("%s op=%d off=%jd len=%jd type=%d",
		 fsp->fsp_name->base_name,
		 op,
		 (intmax_t)off,
		 (intmax_t)len,
		 type);
	return true;
}

static int vfs_ceph_fcntl(vfs_handle_struct *handle,
			  files_struct *fsp,
			  int cmd,
			  va_list cmd_arg)
{
	int ret = 0;

	/*
	 * SMB_VFS_FCNTL() is currently only called by vfs_set_blocking() to
	 * clear O_NONBLOCK, etc for LOCK_MAND and FIFOs. Ignore it.
	 */
	if (cmd == F_GETFL) {
		ret = 0;
	} else if (cmd == F_SETFL) {
		va_list dup_cmd_arg;
		int opt;

		va_copy(dup_cmd_arg, cmd_arg);
		opt = va_arg(dup_cmd_arg, int);
		va_end(dup_cmd_arg);
		if (opt != 0) {
			CEPH_ERR("unexpected fcntl SETFL: opt=%d", opt);
			ret = -EINVAL;
		}
	} else {
		CEPH_ERR("unexpected fcntl: cmd=%d", cmd);
		ret = -EINVAL;
	}
	CEPH_DBGRET(ret);
	return status_code(ret);
}

/*
 * This is a simple version of real-path ... a better version is needed to
 * ask libcephfs about symbolic links.
 */
static struct smb_filename *vfs_ceph_realpath(struct vfs_handle_struct *handle,
					      TALLOC_CTX *ctx,
					      const struct smb_filename *fname)
{
	const struct smb_filename *fsp_name = handle->conn->cwd_fsp->fsp_name;
	const char *path = fname->base_name;
	const size_t len = strlen(path);
	char *rpath = NULL;
	struct smb_filename *result_fname = NULL;

	if (len && (path[0] == '/')) {
		rpath = talloc_asprintf(ctx, "%s", path);
	} else if ((len >= 2) && (path[0] == '.') && (path[1] == '/')) {
		if (len == 2) {
			rpath = talloc_asprintf(ctx, "%s", fsp_name->base_name);
		} else {
			rpath = talloc_asprintf(ctx,
						"%s/%s",
						fsp_name->base_name,
						path + 2);
		}
	} else {
		rpath = talloc_asprintf(ctx,
					"%s/%s",
					fsp_name->base_name,
					path);
	}

	if (rpath == NULL) {
		return NULL;
	}

	CEPH_DBG("path=%s rpath=%s", path, rpath);
	result_fname = synthetic_smb_fname(ctx, rpath, NULL, NULL, 0, 0);
	TALLOC_FREE(rpath);
	return result_fname;
}

static const char *vfs_ceph_connectpath(struct vfs_handle_struct *handle,
					const struct files_struct *dirfsp,
					const struct smb_filename *smb_fname)
{
	return handle->conn->connectpath;
}

/* Extended-attributes operations */

static ssize_t vfs_ceph_fgetxattr(struct vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  const char *name,
				  void *val,
				  size_t size)
{
	struct vfs_ceph_fe *cfe = NULL;
	int ret = -1;

	ret = vfs_ceph_require_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetf(handle, fsp, cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("getxattr: ino=%ld name=%s", cfe->ino, name);
	ret = vfs_ceph_ll_getxattr(handle, cfe, name, val, size);
	if (ret >= 0) {
		CEPH_DBG("getxattr: in-size=%zu out-size=%d", size, ret);
	}
	vfs_ceph_iput(handle, cfe);
out:
	CEPH_DBGRET(ret);
	return xstatus_code(ret);
}

static ssize_t vfs_ceph_flistxattr(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   char *list,
				   size_t size)
{
	struct vfs_ceph_fe *cfe = NULL;
	size_t list_size = 0;
	int ret = -1;

	ret = vfs_ceph_require_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetf(handle, fsp, cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("listxattr: ino=%ld", cfe->ino);
	ret = vfs_ceph_ll_listxattr(handle, cfe, list, size, &list_size);
	if (ret >= 0) {
		CEPH_DBG("listxattr: size=%zu list_size=%zu", size, list_size);
	}
	vfs_ceph_iput(handle, cfe);
out:
	CEPH_DBGRET(ret);
	return lstatus_code(ret ? ret : (ssize_t)list_size);
}

static int vfs_ceph_fremovexattr(struct vfs_handle_struct *handle,
				 struct files_struct *fsp,
				 const char *name)
{
	struct vfs_ceph_fe *cfe = NULL;
	int ret = -1;

	ret = vfs_ceph_require_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetf(handle, fsp, cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("removexattr: ino=%ld name=%s", cfe->ino, name);
	ret = vfs_ceph_ll_removexattr(handle, cfe, name);
	vfs_ceph_iput(handle, cfe);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_fsetxattr(struct vfs_handle_struct *handle,
			      struct files_struct *fsp,
			      const char *name,
			      const void *value,
			      size_t size,
			      int flags)
{
	struct vfs_ceph_fe *cfe = NULL;
	int ret = -1;

	ret = vfs_ceph_require_fe(handle, fsp, &cfe);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_igetf(handle, fsp, cfe);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("setxattr: ino=%ld name=%s size=%zu flags=%x",
		 cfe->ino,
		 name,
		 size,
		 flags);
	ret = vfs_ceph_ll_setxattr(handle, cfe, name, value, size, flags);
	vfs_ceph_iput(handle, cfe);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

/* VFS ceph_ll hooks */
static struct vfs_fn_pointers vfs_ceph_fns = {
	/* Disk operations */
	.connect_fn = vfs_ceph_connect,
	.disconnect_fn = vfs_ceph_disconnect,
	.disk_free_fn = vfs_ceph_disk_free,
	.statvfs_fn = vfs_ceph_statvfs,
	.fs_capabilities_fn = vfs_ceph_fs_capabilities,
	/* Directory operations */
	.fdopendir_fn = vfs_ceph_fdopendir,
	.readdir_fn = vfs_ceph_readdir,
	.rewind_dir_fn = vfs_ceph_rewinddir,
	.mkdirat_fn = vfs_ceph_mkdirat,
	.closedir_fn = vfs_ceph_closedir,
	/* File operations */
	.openat_fn = vfs_ceph_openat,
	.close_fn = vfs_ceph_close,
	.pread_fn = vfs_ceph_pread,
	.pread_send_fn = vfs_ceph_pread_send,
	.pread_recv_fn = vfs_ceph_pread_recv,
	.pwrite_fn = vfs_ceph_pwrite,
	.pwrite_send_fn = vfs_ceph_pwrite_send,
	.pwrite_recv_fn = vfs_ceph_pwrite_recv,
	.lseek_fn = vfs_ceph_lseek,
	.renameat_fn = vfs_ceph_renameat,
	.fsync_send_fn = vfs_ceph_fsync_send,
	.fsync_recv_fn = vfs_ceph_fsync_recv,
	.stat_fn = vfs_ceph_stat,
	.fstat_fn = vfs_ceph_fstat,
	.lstat_fn = vfs_ceph_lstat,
	.fstatat_fn = vfs_ceph_fstatat,
	.unlinkat_fn = vfs_ceph_unlinkat,
	.fchmod_fn = vfs_ceph_fchmod,
	.fchown_fn = vfs_ceph_fchown,
	.lchown_fn = vfs_ceph_lchown,
	.chdir_fn = vfs_ceph_chdir,
	.getwd_fn = vfs_ceph_getwd,
	.fntimes_fn = vfs_ceph_fntimes,
	.ftruncate_fn = vfs_ceph_ftruncate,
	.fallocate_fn = vfs_ceph_fallocate,
	.lock_fn = vfs_ceph_lock,
	.fcntl_fn = vfs_ceph_fcntl,
	.symlinkat_fn = vfs_ceph_symlinkat,
	.readlinkat_fn = vfs_ceph_readlinkat,
	.linkat_fn = vfs_ceph_linkat,
	.mknodat_fn = vfs_ceph_mknodat,
	.realpath_fn = vfs_ceph_realpath,
	.connectpath_fn = vfs_ceph_connectpath,
	/* Extended-attributes operations. */
	.fgetxattr_fn = vfs_ceph_fgetxattr,
	.flistxattr_fn = vfs_ceph_flistxattr,
	.fremovexattr_fn = vfs_ceph_fremovexattr,
	.fsetxattr_fn = vfs_ceph_fsetxattr,
};

static_decl_vfs;
NTSTATUS vfs_ceph_ll_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"ceph_ll",
				&vfs_ceph_fns);
}

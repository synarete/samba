#define _GNU_SOURCE 1
#include <stdlib.h>
#include <stdint.h>

#include <cephfs/libcephfs.h>
#include "includes.h"
#include "auth.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "modules/posixacl_xattr.h"
#include "lib/util/tevent_unix.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

/* Ceph wrapper over debug macros */
#define CEPH_DBG_(hook_, fmt_, ...) \
	DBG_DEBUG("[ceph:%s] " fmt_ "\n", hook_, __VA_ARGS__)

#define CEPH_DBG(fmt_, ...) \
	CEPH_DBG_(exclude_prefix(__func__), fmt_, __VA_ARGS__)

#define CEPH_DBGRET(ret_)                                  \
	do {                                               \
		if ((ret_) < -1)                           \
			CEPH_DBG("ret=%ld", (long)(ret_)); \
	} while (0)

#define CEPH_ERR(fmt_, ...) DBG_ERR("[ceph] " fmt_ "\n", __VA_ARGS__)

/* Common helpers */
static const char *exclude_prefix(const char *fn)
{
	const char *pre = "vfs_ceph_";

	if (!strncmp(fn, pre, 9)) {
		fn += 9;
	}
	return fn;
}

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

/* Ceph's input credentials */
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
	ino_t ino;
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

/* Ceph file-handles via fsp-extension */
struct vfs_ceph_fh {
	const struct vfs_ceph_mnt_entry *cme;
	struct vfs_ceph_iref iref;
	struct Fh *fh;
	int fd;
};

static int vfs_ceph_release_fh(struct vfs_ceph_fh *cfh)
{
	int ret = 0;

	if (cfh->fh != NULL) {
		ret = ceph_ll_close(cfh->cme->cmount, cfh->fh);
		CEPH_DBG("close: ino=%ld fd=%d ret=%d",
			 cfh->iref.ino,
			 cfh->fd,
			 ret);
		cfh->fh = NULL;
		cfh->fd = -1;
	}
	if (cfh->iref.inode != NULL) {
		ceph_ll_put(cfh->cme->cmount, cfh->iref.inode);
		CEPH_DBG("put: ino=%ld", cfh->iref.ino);
		cfh->iref.inode = NULL;
		cfh->iref.ino = 0;
	}
	return ret;
}

static void vfs_ceph_fsp_ext_destroy_cb(void *p_data)
{
	vfs_ceph_release_fh((struct vfs_ceph_fh *)p_data);
}

static struct vfs_ceph_fh *vfs_ceph_add_fh(struct vfs_handle_struct *handle,
					   files_struct *fsp)
{
	struct vfs_ceph_mnt_entry *cme = handle->data;
	struct vfs_ceph_fh *cfh = NULL;

	cfh = VFS_ADD_FSP_EXTENSION(handle,
				    fsp,
				    struct vfs_ceph_fh,
				    vfs_ceph_fsp_ext_destroy_cb);
	if (cfh != NULL) {
		cfh->fd = vfs_ceph_mnt_next_fd(cme);
		cfh->cme = cme;
	}
	return cfh;
}

static void vfs_ceph_remove_fh(struct vfs_handle_struct *handle,
			       files_struct *fsp)
{
	VFS_REMOVE_FSP_EXTENSION(handle, fsp);
}

static int vfs_ceph_fetch_fh(struct vfs_handle_struct *handle,
			     files_struct *fsp,
			     struct vfs_ceph_fh **out_cfh)
{
	*out_cfh = VFS_FETCH_FSP_EXTENSION(handle, fsp);
	return (*out_cfh == NULL) ? -EBADF : 0;
}

/* Ceph low-level wrappers */

static struct ceph_mount_info *cmount_of(const struct vfs_handle_struct *handle)
{
	const struct vfs_ceph_mnt_entry *cme = handle->data;

	return cme->cmount;
}

static int vfs_ceph_ll_walk(const struct vfs_handle_struct *handle,
			    const char *name,
			    struct Inode **pin,
			    struct ceph_statx *stx,
			    unsigned int want,
			    unsigned int flags)
{
	struct ceph_mount_info *cmount = cmount_of(handle);
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_walk(cmount, name, pin, stx, want, flags, perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_mkdir(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_iref *diref,
			     const char *name,
			     mode_t mode,
			     struct vfs_ceph_iref *iref)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_mkdir(cmount_of(handle),
			    diref->inode,
			    name,
			    mode,
			    &iref->inode,
			    &stx,
			    CEPH_STATX_INO,
			    0,
			    perms);
	iref->ino = stx.stx_ino;
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_link(const struct vfs_handle_struct *handle,
			    const struct vfs_ceph_iref *diref,
			    const char *name,
			    const struct vfs_ceph_iref *iref)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_link(cmount_of(handle),
			   iref->inode,
			   diref->inode,
			   name,
			   perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_opendir(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_iref *iref,
			       struct ceph_dir_result **dirpp)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_opendir(cmount_of(handle), iref->inode, dirpp, perms);
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
			      const struct vfs_ceph_iref *parent,
			      const char *name,
			      const struct vfs_ceph_iref *newparent,
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

static int vfs_ceph_ll_getattr(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_iref *iref,
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
			      iref->inode,
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
			    const struct vfs_ceph_iref *iref,
			    SMB_STRUCT_STAT *st)
{
	struct ceph_statx stx = {0};
	int ret = -1;

	ret = vfs_ceph_ll_getattr(handle, iref, &stx, SAMBA_STATX_ATTR_MASK, 0);
	if (ret == 0) {
		smb_stat_from_ceph_statx(st, &stx);
	}
	return ret;
}

static int vfs_ceph_ll_setattr(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_iref *iref,
			       struct ceph_statx *stx,
			       int mask)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_setattr(cmount_of(handle), iref->inode, stx, mask, perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_chmod(struct vfs_handle_struct *handle,
			     const struct vfs_ceph_iref *iref,
			     mode_t mode)
{
	struct ceph_statx stx = {.stx_mode = mode};

	return vfs_ceph_ll_setattr(handle, iref, &stx, CEPH_STATX_MODE);
}

static int vfs_ceph_ll_chown(struct vfs_handle_struct *handle,
			     const struct vfs_ceph_iref *iref,
			     uid_t uid,
			     gid_t gid)
{
	struct ceph_statx stx = {.stx_uid = uid, .stx_gid = gid};

	return vfs_ceph_ll_setattr(handle,
				   iref,
				   &stx,
				   CEPH_STATX_UID | CEPH_STATX_GID);
}

static int vfs_ceph_ll_utimes(struct vfs_handle_struct *handle,
			      const struct vfs_ceph_iref *iref,
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
	if (!is_omit_timespec(&ft->create_time)) {
		stx.stx_btime = ft->create_time;
		mask |= CEPH_SETATTR_BTIME;
	}
	return mask ? vfs_ceph_ll_setattr(handle, iref, &stx, mask) : 0;
}

static int vfs_ceph_ll_truncate(struct vfs_handle_struct *handle,
				const struct vfs_ceph_iref *iref,
				uint64_t size)
{
	struct ceph_statx stx = {.stx_size = size};

	return vfs_ceph_ll_setattr(handle, iref, &stx, CEPH_SETATTR_SIZE);
}

static int vfs_ceph_ll_fallocate(const struct vfs_handle_struct *handle,
				 const struct vfs_ceph_fh *cfh,
				 int mode,
				 int64_t off,
				 int64_t len)
{
	return ceph_ll_fallocate(cmount_of(handle), cfh->fh, mode, off, len);
}

static int vfs_ceph_ll_statfs(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_iref *iref,
			      struct statvfs *stbuf)
{
	return ceph_ll_statfs(cmount_of(handle), iref->inode, stbuf);
}

static int vfs_ceph_ll_readlink(const struct vfs_handle_struct *handle,
				const struct vfs_ceph_iref *iref,
				char *buf,
				size_t bsz)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_readlink(cmount_of(handle), iref->inode, buf, bsz, perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_symlink(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_iref *iref,
			       const char *name,
			       const char *value,
			       struct vfs_ceph_iref *out_iref)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_symlink(cmount_of(handle),
			      iref->inode,
			      name,
			      value,
			      &out_iref->inode,
			      &stx,
			      CEPH_STATX_INO,
			      0,
			      perms);
	out_iref->ino = stx.stx_ino;
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_rmdir(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_iref *diref,
			     const char *name)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_rmdir(cmount_of(handle), diref->inode, name, perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_create(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_iref *parent,
			      const char *name,
			      mode_t mode,
			      int oflags,
			      struct vfs_ceph_fh *cfh)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_create(cmount_of(handle),
			     parent->inode,
			     name,
			     mode,
			     oflags,
			     &cfh->iref.inode,
			     &cfh->fh,
			     &stx,
			     CEPH_STATX_INO,
			     0,
			     perms);
	cfh->iref.ino = stx.stx_ino;
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_mknod(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_iref *parent,
			     const char *name,
			     mode_t mode,
			     dev_t rdev,
			     struct vfs_ceph_iref *iref)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct UserPerm *perms = NULL;
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
			    &iref->inode,
			    &stx,
			    CEPH_STATX_INO,
			    0,
			    perms);
	iref->ino = stx.stx_ino;
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_lookup(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_iref *parent,
			      const char *name,
			      struct vfs_ceph_iref *iref)
{
	struct ceph_statx stx = {.stx_ino = 0};
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_lookup(cmount_of(handle),
			     parent->inode,
			     name,
			     &iref->inode,
			     &stx,
			     CEPH_STATX_INO,
			     0,
			     perms);
	iref->ino = stx.stx_ino;
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_open(const struct vfs_handle_struct *handle,
			    const struct vfs_ceph_iref *iref,
			    int flags,
			    struct vfs_ceph_fh *cfh)
{
	struct ceph_mount_info *cmount = cmount_of(handle);
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_open(cmount, iref->inode, flags, &cfh->fh, perms);
	cfh->iref.ino = iref->ino;
	vfs_ceph_userperm_del(perms);
	return ret;
}

static off_t vfs_ceph_ll_lseek(const struct vfs_handle_struct *handle,
			       const struct vfs_ceph_fh *cfh,
			       off_t offset,
			       int whence)
{
	return ceph_ll_lseek(cmount_of(handle), cfh->fh, offset, whence);
}

static int vfs_ceph_ll_read(const struct vfs_handle_struct *handle,
			    const struct vfs_ceph_fh *cfh,
			    int64_t off,
			    uint64_t len,
			    char *buf)
{
	return ceph_ll_read(cmount_of(handle), cfh->fh, off, len, buf);
}

static int vfs_ceph_ll_fsync(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_fh *cfh,
			     int syncdataonly)
{
	return ceph_ll_fsync(cmount_of(handle), cfh->fh, syncdataonly);
}

static int vfs_ceph_ll_write(const struct vfs_handle_struct *handle,
			     const struct vfs_ceph_fh *cfh,
			     int64_t off,
			     uint64_t len,
			     const char *data)
{
	return ceph_ll_write(cmount_of(handle), cfh->fh, off, len, data);
}

static int vfs_ceph_ll_unlink(const struct vfs_handle_struct *handle,
			      const struct vfs_ceph_iref *iref,
			      const char *name)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_unlink(cmount_of(handle), iref->inode, name, perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_getxattr(const struct vfs_handle_struct *handle,
				const struct vfs_ceph_iref *iref,
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
	ret = ceph_ll_getxattr(cmount, iref->inode, name, value, size, perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_setxattr(const struct vfs_handle_struct *handle,
				const struct vfs_ceph_iref *iref,
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
			       iref->inode,
			       name,
			       value,
			       size,
			       flags,
			       perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_listxattr(const struct vfs_handle_struct *handle,
				 const struct vfs_ceph_iref *iref,
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
				iref->inode,
				list,
				buf_size,
				list_size,
				perms);
	vfs_ceph_userperm_del(perms);
	return ret;
}

static int vfs_ceph_ll_removexattr(const struct vfs_handle_struct *handle,
				   const struct vfs_ceph_iref *iref,
				   const char *name)
{
	struct UserPerm *perms = NULL;
	int ret = -1;

	perms = vfs_ceph_userperm_new(handle);
	if (perms == NULL) {
		return -ENOMEM;
	}
	ret = ceph_ll_removexattr(cmount_of(handle), iref->inode, name, perms);
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

static void vfs_ceph_disconnect(struct vfs_handle_struct *handle)
{
	struct vfs_ceph_mnt_entry *cme = handle->data;
	struct ceph_mount_info *cmount = cme->cmount;
	int snum = cme->snum;
	int ret = -1;

	vfs_ceph_mnt_update(cme, -1);
	if (cme->count > 0) {
		CEPH_DBG("still in-use: count=%d", cme->count);
		return;
	}

	CEPH_DBG("ceph_unmount: cmount=%p", cmount);
	ret = ceph_unmount(cmount);
	CEPH_DBG("ceph_unmount: ret=%d", ret);

	CEPH_DBG("ceph_release: cmount=%p", cmount);
	ret = ceph_release(cmount);
	CEPH_DBG("ceph_release: ret=%d", ret);

	cme->cmount = NULL;
	cme->snum = -1;
	TALLOC_FREE(cme);
	handle->data = NULL;
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

	CEPH_DBG("rootdir-ino=%ld", cme->rootdir.ino);
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

static int vfs_ceph_iget(struct vfs_handle_struct *handle,
			 const char *name,
			 unsigned int flags,
			 struct vfs_ceph_iref *iref)
{
	struct ceph_statx stx = {.stx_ino = 0, .stx_mode = 0};
	struct Inode *inode = NULL;
	int ret = -1;

	ret = vfs_ceph_ll_walk(handle,
			       name,
			       &inode,
			       &stx,
			       CEPH_STATX_INO | CEPH_STATX_MODE,
			       flags);
	if (ret != 0) {
		return ret;
	}
	iref->inode = inode;
	iref->ino = stx.stx_ino;
	CEPH_DBG("%s ino=%lu mode=0%o", name, stx.stx_ino, stx.stx_mode);
	return 0;
}

static int vfs_ceph_iget_by_fname(struct vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname,
				  struct vfs_ceph_iref *iref)
{
	const char *name = smb_fname->base_name;
	const char *cwd = ceph_getcwd(cmount_of(handle));

	if (!strcmp(name, cwd)) {
		name = ".";
	}
	return vfs_ceph_iget(handle, name, 0, iref);
}

static int vfs_ceph_igetf(struct vfs_handle_struct *handle,
			  const struct files_struct *fsp,
			  struct vfs_ceph_iref *iref)
{
	return vfs_ceph_iget_by_fname(handle, fsp->fsp_name, iref);
}

static int vfs_ceph_igetl(struct vfs_handle_struct *handle,
			  const struct smb_filename *smb_fname,
			  struct vfs_ceph_iref *iref)
{
	return vfs_ceph_iget(handle,
			     smb_fname->base_name,
			     AT_SYMLINK_NOFOLLOW,
			     iref);
}

static int vfs_ceph_igetd(struct vfs_handle_struct *handle,
			  const struct files_struct *dirfsp,
			  struct vfs_ceph_iref *iref)
{
	const char *name = dirfsp->fsp_name->base_name;

	if (fsp_get_pathref_fd(dirfsp) == AT_FDCWD) {
		name = ".";
	}
	return vfs_ceph_iget(handle, name, 0, iref);
}

static void vfs_ceph_iput(struct vfs_handle_struct *handle,
			  struct vfs_ceph_iref *iref)
{
	if (iref->inode != NULL) {
		CEPH_DBG("ino=%ld", iref->ino);
		ceph_ll_put(cmount_of(handle), iref->inode);
		iref->inode = NULL;
	}
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
	struct vfs_ceph_iref iref = {0};
	int ret = -1;

	CEPH_DBG("%s", smb_fname->base_name);
	ret = vfs_ceph_iget_by_fname(handle, smb_fname, &iref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("ino=%ld", iref.ino);
	ret = vfs_ceph_ll_statfs(handle, &iref, &stvfs);
	if (ret != 0) {
		goto out;
	}
	statvfs_to_smb(&stvfs, out_stvfs);
out:
	vfs_ceph_iput(handle, &iref);
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
			       struct files_struct *fsp,
			       const char *mask,
			       uint32_t attributes)
{
	struct vfs_ceph_iref diref = {0};
	struct ceph_dir_result *dirp = NULL;
	int ret = 0;

	CEPH_DBG("%s", fsp->fsp_name->base_name);
	ret = vfs_ceph_igetd(handle, fsp, &diref);
	if (ret != 0) {
		dstatus_code(NULL, ret);
	}
	CEPH_DBG("ino=%ld", diref.ino);
	ret = vfs_ceph_ll_opendir(handle, &diref, &dirp);
	vfs_ceph_iput(handle, &diref);
	CEPH_DBG("dirp=%p", dirp);
	return dstatus_code(dirp, ret);
}

static struct dirent *vfs_ceph_readdir(struct vfs_handle_struct *handle,
				       struct files_struct *dirfsp,
				       DIR *dirp)
{
	struct dirent *de = NULL;

	CEPH_DBG("%s", dirfsp->fsp_name->base_name);
	de = vfs_ceph_ll_readdir(handle, (struct ceph_dir_result *)dirp);
	if (de == NULL) {
		return NULL;
	}
	CEPH_DBG("ino=%ld off=%ld name=%s", de->d_ino, de->d_off, de->d_name);
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
	struct vfs_ceph_iref diref = {0};
	struct vfs_ceph_iref iref = {0};
	int ret = -1;

	CEPH_DBG("%s", dirfsp->fsp_name->base_name);
	ret = vfs_ceph_igetd(handle, dirfsp, &diref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("dino=%ld name=%s mode=0%o",
		 diref.ino,
		 smb_fname->base_name,
		 mode);
	ret = vfs_ceph_ll_mkdir(handle,
				&diref,
				smb_fname->base_name,
				mode,
				&iref);
	vfs_ceph_iput(handle, &iref);
	vfs_ceph_iput(handle, &diref);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_closedir(struct vfs_handle_struct *handle, DIR *dirp)
{
	int ret = -1;

	CEPH_DBG("dirp=%p", dirp);
	ret = vfs_ceph_ll_releasedir(handle, (struct ceph_dir_result *)dirp);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

/* File operations */
static struct smb_filename *vfs_ceph_getwd(struct vfs_handle_struct *handle,
					   TALLOC_CTX *ctx)
{
	const char *cwd = NULL;

	cwd = ceph_getcwd(cmount_of(handle));
	CEPH_DBG("%s", cwd);
	return synthetic_smb_fname(ctx, cwd, NULL, NULL, 0, 0);
}

static int vfs_ceph_openat(struct vfs_handle_struct *handle,
			   const struct files_struct *dirfsp,
			   const struct smb_filename *smb_fname,
			   files_struct *fsp,
			   const struct vfs_open_how *how)
{
	struct vfs_ceph_iref diref = {0};
	struct vfs_ceph_iref iref = {0};
	struct vfs_ceph_fh *cfh = NULL;
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
	cfh = vfs_ceph_add_fh(handle, fsp);
	if (cfh == NULL) {
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

	CEPH_DBG("%s", dirfsp->fsp_name->base_name);
	ret = vfs_ceph_igetd(handle, dirfsp, &diref);
	if (ret != 0) {
		goto out;
	}

	if (o_flags & O_CREAT) {
		CEPH_DBG("create: dino=%ld name=%s mode=%o o_flags=0x%x",
			 diref.ino,
			 smb_fname->base_name,
			 mode,
			 o_flags);
		ret = vfs_ceph_ll_create(handle,
					 &diref,
					 smb_fname->base_name,
					 mode,
					 o_flags,
					 cfh);
		if (ret < 0) {
			goto out;
		}
		CEPH_DBG("create-ok: %s ino=%ld fd=%d",
			 smb_fname->base_name,
			 cfh->iref.ino,
			 cfh->fd);

	} else {
		CEPH_DBG("lookup: dino=%ld name=%s",
			 diref.ino,
			 smb_fname->base_name);
		ret = vfs_ceph_ll_lookup(handle,
					 &diref,
					 smb_fname->base_name,
					 &iref);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("lookup-ok: dino=%ld name=%s ino=%ld",
			 diref.ino,
			 smb_fname->base_name,
			 iref.ino);

		CEPH_DBG("open: ino=%ld o_flags=0x%x", iref.ino, o_flags);
		ret = vfs_ceph_ll_open(handle, &iref, o_flags, cfh);
		if (ret < 0) {
			goto out;
		}
		/* take ownership on inode */
		cfh->iref.inode = iref.inode;
		cfh->iref.ino = iref.ino;
		iref.inode = NULL;
		CEPH_DBG("open-ok: %s ino=%ld fd=%d",
			 smb_fname->base_name,
			 cfh->iref.ino,
			 cfh->fd);
	}
	ret = cfh->fd;

out:
	if (became_root) {
		unbecome_root();
	}
	vfs_ceph_iput(handle, &iref);
	vfs_ceph_iput(handle, &diref);
	fsp->fsp_flags.have_proc_fds = false;
	if (ret < 0) {
		vfs_ceph_remove_fh(handle, fsp);
	}
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_close(struct vfs_handle_struct *handle, files_struct *fsp)
{
	struct vfs_ceph_fh *cfh = NULL;
	int ret = -1;

	CEPH_DBG("%s", fsp->fsp_name->base_name);
	ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_release_fh(cfh);
	vfs_ceph_remove_fh(handle, fsp);
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
	struct vfs_ceph_fh *cfh = NULL;
	int ret = -1;

	CEPH_DBG("%s", fsp->fsp_name->base_name);
	ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("ino=%ld fd=%d off=%ld len=%zu",
		 cfh->iref.ino,
		 cfh->fd,
		 off,
		 len);
	ret = vfs_ceph_ll_read(handle, cfh, off, len, data);
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
	struct vfs_ceph_fh *cfh = NULL;
	struct tevent_req *req = NULL;
	struct vfs_ceph_pread_state *state = NULL;
	int ret = -1;

	CEPH_DBG("%s", fsp->fsp_name->base_name);
	ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (ret != 0) {
		update_errno(ret);
		return NULL;
	}
	req = tevent_req_create(mem_ctx, &state, struct vfs_ceph_pread_state);
	if (req == NULL) {
		return NULL;
	}

	CEPH_DBG("ino=%ld fd=%d off=%ld len=%zu",
		 cfh->iref.ino,
		 cfh->fd,
		 off,
		 len);
	ret = vfs_ceph_ll_read(handle, cfh, off, len, data);
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
	CEPH_DBG("bytes_read=%ld error=%d",
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
	struct vfs_ceph_fh *cfh = NULL;
	int ret = -1;

	CEPH_DBG("%s", fsp->fsp_name->base_name);
	ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("ino=%ld fd=%d len=%zu off=%ld",
		 cfh->iref.ino,
		 cfh->fd,
		 len,
		 off);
	ret = vfs_ceph_ll_write(handle, cfh, off, len, data);
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
	struct vfs_ceph_fh *cfh = NULL;
	struct tevent_req *req = NULL;
	struct vfs_ceph_pwrite_state *state = NULL;
	int ret = -1;

	CEPH_DBG("%s", fsp->fsp_name->base_name);
	ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (ret != 0) {
		update_errno(ret);
		return NULL;
	}
	req = tevent_req_create(mem_ctx, &state, struct vfs_ceph_pwrite_state);
	if (req == NULL) {
		return NULL;
	}
	CEPH_DBG("ino=%ld fd=%d len=%zu off=%ld",
		 cfh->iref.ino,
		 cfh->fd,
		 len,
		 off);
	ret = vfs_ceph_ll_write(handle, cfh, off, len, data);
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
	struct vfs_ceph_fh *cfh = NULL;
	int64_t ret = -1;

	CEPH_DBG("%s", fsp->fsp_name->base_name);
	ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("ino=%ld fd=%d offset=%ld whence=%d",
		 cfh->iref.ino,
		 cfh->fd,
		 offset,
		 whence);
	ret = vfs_ceph_ll_lseek(handle, cfh, offset, whence);
out:
	CEPH_DBGRET(ret);
	return lstatus_code(ret);
}

static int vfs_ceph_renameat(struct vfs_handle_struct *handle,
			     files_struct *srcfsp,
			     const struct smb_filename *smb_fname_src,
			     files_struct *dstfsp,
			     const struct smb_filename *smb_fname_dst)
{
	struct vfs_ceph_iref src_diref = {0};
	struct vfs_ceph_iref dst_diref = {0};
	int ret = -1;

	if (smb_fname_src->stream_name || smb_fname_dst->stream_name) {
		return status_code(-ENOENT);
	}
	CEPH_DBG("%s", srcfsp->fsp_name->base_name);
	ret = vfs_ceph_igetd(handle, srcfsp, &src_diref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("%s", dstfsp->fsp_name->base_name);
	ret = vfs_ceph_igetd(handle, dstfsp, &dst_diref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("dino=%ld name=%s new-dino=%ld newname=%s",
		 src_diref.ino,
		 smb_fname_src->base_name,
		 dst_diref.ino,
		 smb_fname_dst->base_name);
	ret = vfs_ceph_ll_rename(handle,
				 &src_diref,
				 smb_fname_src->base_name,
				 &dst_diref,
				 smb_fname_dst->base_name);
out:
	vfs_ceph_iput(handle, &src_diref);
	vfs_ceph_iput(handle, &dst_diref);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static struct tevent_req *vfs_ceph_fsync_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      files_struct *fsp)
{
	struct vfs_ceph_fh *cfh = NULL;
	struct tevent_req *req = NULL;
	struct vfs_aio_state *state = NULL;
	int ret = -1;

	CEPH_DBG("%s", fsp->fsp_name->base_name);
	ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (ret != 0) {
		update_errno(ret);
		return NULL;
	}
	req = tevent_req_create(mem_ctx, &state, struct vfs_aio_state);
	if (req == NULL) {
		return NULL;
	}
	CEPH_DBG("ino=%ld fd=%d", cfh->iref.ino, cfh->fd);
	ret = vfs_ceph_ll_fsync(handle, cfh, 0);
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
	struct vfs_ceph_iref iref = {0};
	int ret = -1;

	if (smb_fname->stream_name) {
		return status_code(-ENOENT);
	}
	CEPH_DBG("%s", smb_fname->base_name);
	ret = vfs_ceph_iget_by_fname(handle, smb_fname, &iref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("ino=%ld", iref.ino);
	ret = vfs_ceph_ll_stat(handle, &iref, &smb_fname->st);
	vfs_ceph_iput(handle, &iref);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_fstat(struct vfs_handle_struct *handle,
			  files_struct *fsp,
			  SMB_STRUCT_STAT *st)
{
	struct vfs_ceph_fh *cfh = NULL;
	int ret = -1;

	CEPH_DBG("%s", fsp->fsp_name->base_name);
	ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("ino=%ld fd=%d", cfh->iref.ino, cfh->fd);
	ret = vfs_ceph_ll_stat(handle, &cfh->iref, st);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_lstat(struct vfs_handle_struct *handle,
			  struct smb_filename *smb_fname)
{
	struct vfs_ceph_iref iref = {0};
	int ret = -1;

	if (smb_fname->stream_name) {
		return status_code(-ENOENT);
	}
	CEPH_DBG("%s", smb_fname->base_name);
	ret = vfs_ceph_igetl(handle, smb_fname, &iref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("ino=%ld", iref.ino);

	ret = vfs_ceph_ll_stat(handle, &iref, &smb_fname->st);
	vfs_ceph_iput(handle, &iref);
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
	struct vfs_ceph_iref diref = {0};
	struct vfs_ceph_iref iref = {0};
	int ret = -1;

	if (dirfsp->fsp_name->stream_name || smb_fname->stream_name) {
		return status_code(-ENOENT);
	}
	CEPH_DBG("%s", dirfsp->fsp_name->base_name);
	ret = vfs_ceph_igetd(handle, dirfsp, &diref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("lookup: dino=%ld name=%s", diref.ino, smb_fname->base_name);
	ret = vfs_ceph_ll_lookup(handle, &diref, smb_fname->base_name, &iref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("stat: ino=%ld", iref.ino);
	ret = vfs_ceph_ll_stat(handle, &iref, st);
out:
	vfs_ceph_iput(handle, &iref);
	vfs_ceph_iput(handle, &diref);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_unlinkat(struct vfs_handle_struct *handle,
			     struct files_struct *dirfsp,
			     const struct smb_filename *smb_fname,
			     int flags)
{
	struct vfs_ceph_iref diref = {0};
	int ret = -1;

	if (smb_fname->stream_name) {
		return status_code(-ENOENT);
	}
	CEPH_DBG("%s", dirfsp->fsp_name->base_name);
	ret = vfs_ceph_igetd(handle, dirfsp, &diref);
	if (ret != 0) {
		goto out;
	}
	if (flags & AT_REMOVEDIR) {
		CEPH_DBG("rmdir: dino=%ld name=%s",
			 diref.ino,
			 smb_fname->base_name);
		ret = vfs_ceph_ll_rmdir(handle, &diref, smb_fname->base_name);
	} else {
		CEPH_DBG("unlink: dino=%ld name=%s",
			 diref.ino,
			 smb_fname->base_name);
		ret = vfs_ceph_ll_unlink(handle, &diref, smb_fname->base_name);
	}
	vfs_ceph_iput(handle, &diref);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_fchmod(struct vfs_handle_struct *handle,
			   files_struct *fsp,
			   mode_t mode)
{
	int ret = -1;

	if (!fsp->fsp_flags.is_pathref) {
		struct vfs_ceph_fh *cfh = NULL;

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld fd=%d mode=%o", cfh->iref.ino, cfh->fd, mode);
		ret = vfs_ceph_ll_chmod(handle, &cfh->iref, mode);
	} else {
		struct vfs_ceph_iref iref = {0};

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_igetf(handle, fsp, &iref);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld mode=%o", iref.ino, mode);
		ret = vfs_ceph_ll_chmod(handle, &iref, mode);
		vfs_ceph_iput(handle, &iref);
	}
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_fchown(struct vfs_handle_struct *handle,
			   files_struct *fsp,
			   uid_t uid,
			   gid_t gid)
{
	int ret = -1;

	if (!fsp->fsp_flags.is_pathref) {
		struct vfs_ceph_fh *cfh = NULL;

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld fd=%d uid=%d gid=%d",
			 cfh->iref.ino,
			 cfh->fd,
			 uid,
			 gid);
		ret = vfs_ceph_ll_chown(handle, &cfh->iref, uid, gid);
	} else {
		struct vfs_ceph_iref iref = {0};

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_igetf(handle, fsp, &iref);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld uid=%d gid=%d", iref.ino, uid, gid);
		ret = vfs_ceph_ll_chown(handle, &iref, uid, gid);
		vfs_ceph_iput(handle, &iref);
	}
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_lchown(struct vfs_handle_struct *handle,
			   const struct smb_filename *smb_fname,
			   uid_t uid,
			   gid_t gid)
{
	struct vfs_ceph_iref iref = {0};
	int ret = -1;

	CEPH_DBG("%s", smb_fname->base_name);
	ret = vfs_ceph_igetl(handle, smb_fname, &iref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("ino=%ld uid=%d gid=%d", iref.ino, uid, gid);
	ret = vfs_ceph_ll_chown(handle, &iref, uid, gid);
	vfs_ceph_iput(handle, &iref);
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_chdir(struct vfs_handle_struct *handle,
			  const struct smb_filename *smb_fname)
{
	int ret = -1;

	CEPH_DBG("%s", smb_fname->base_name);
	ret = ceph_chdir(cmount_of(handle), smb_fname->base_name);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_fntimes(struct vfs_handle_struct *handle,
			    files_struct *fsp,
			    struct smb_file_time *ft)
{
	int ret = -1;

	if (!fsp->fsp_flags.is_pathref) {
		struct vfs_ceph_fh *cfh = NULL;

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld fd=%d", cfh->iref.ino, cfh->fd);
		ret = vfs_ceph_ll_utimes(handle, &cfh->iref, ft);
	} else {
		struct vfs_ceph_iref iref = {0};

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_igetf(handle, fsp, &iref);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld", iref.ino);
		ret = vfs_ceph_ll_utimes(handle, &iref, ft);
		vfs_ceph_iput(handle, &iref);
	}
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_ftruncate_allocate(struct vfs_handle_struct *handle,
				       files_struct *fsp,
				       off_t len)
{
	struct vfs_ceph_fh *cfh = NULL;
	SMB_STRUCT_STAT *pst = &fsp->fsp_name->st;
	off_t size = 0;
	int ret = -1;

	CEPH_DBG("%s", fsp->fsp_name->base_name);
	ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (ret != 0) {
		goto out;
	}
	ret = vfs_ceph_ll_stat(handle, &cfh->iref, pst);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("ino=%ld mode=0%o", (long)pst->st_ex_ino, pst->st_ex_mode);

#ifdef S_ISFIFO
	if (S_ISFIFO(pst->st_ex_mode)) {
		return 0;
	}
#endif
	size = pst->st_ex_size;
	if (size > len) {
		CEPH_DBG("truncate: ino=%ld fd=%d len=%ld",
			 cfh->iref.ino,
			 cfh->fd,
			 len);
		ret = vfs_ceph_ll_truncate(handle, &cfh->iref, len);
	} else if (size < len) {
		len = len - size;
		CEPH_DBG("fallocate: ino=%ld fd=%d off=%ld len=%ld",
			 cfh->iref.ino,
			 cfh->fd,
			 size,
			 len);
		ret = vfs_ceph_ll_fallocate(handle, cfh, 0, size, len);
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
	struct vfs_ceph_fh *cfh = NULL;
	int ret = -1;

	if (cme->strict_allocate) {
		return vfs_ceph_ftruncate_allocate(handle, fsp, off);
	}
	CEPH_DBG("%s", fsp->fsp_name->base_name);
	ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("ino=%ld fd=%d off=%ld", cfh->iref.ino, cfh->fd, off);
	ret = vfs_ceph_ll_truncate(handle, &cfh->iref, (uint64_t)off);
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
	struct vfs_ceph_fh *cfh = NULL;
	int ret = -1;

	CEPH_DBG("%s", fsp->fsp_name->base_name);
	ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("ino=%ld fd=%d mode=%x off=%ld len=%ld",
		 cfh->iref.ino,
		 cfh->fd,
		 mode,
		 off,
		 len);
	ret = vfs_ceph_ll_fallocate(handle, cfh, mode, off, len);
out:
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
	CEPH_DBG("%s op=%d off=%ld len=%ld type=%d",
		 fsp->fsp_name->base_name,
		 op,
		 off,
		 len,
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
out:
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_symlinkat(struct vfs_handle_struct *handle,
			      const struct smb_filename *link_target,
			      struct files_struct *dirfsp,
			      const struct smb_filename *new_smb_fname)
{
	struct vfs_ceph_iref diref = {0};
	struct vfs_ceph_iref iref = {0};
	int ret = -1;

	CEPH_DBG("%s", dirfsp->fsp_name->base_name);
	ret = vfs_ceph_igetd(handle, dirfsp, &diref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("dino=%ld name=%s target=%s",
		 diref.ino,
		 new_smb_fname->base_name,
		 link_target->base_name);
	ret = vfs_ceph_ll_symlink(handle,
				  &diref,
				  new_smb_fname->base_name,
				  link_target->base_name,
				  &iref);
out:
	vfs_ceph_iput(handle, &iref);
	vfs_ceph_iput(handle, &diref);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_readlinkat(struct vfs_handle_struct *handle,
			       const struct files_struct *dirfsp,
			       const struct smb_filename *smb_fname,
			       char *buf,
			       size_t bufsz)
{
	struct vfs_ceph_iref diref = {0};
	struct vfs_ceph_iref iref = {0};
	int ret = -1;

	CEPH_DBG("%s", dirfsp->fsp_name->base_name);
	ret = vfs_ceph_igetd(handle, dirfsp, &diref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("lookup: dino=%ld name=%s", diref.ino, smb_fname->base_name);
	ret = vfs_ceph_ll_lookup(handle, &diref, smb_fname->base_name, &iref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("readlink: ino=%ld bufsz=%zu", iref.ino, bufsz);
	ret = vfs_ceph_ll_readlink(handle, &iref, buf, bufsz);
out:
	vfs_ceph_iput(handle, &iref);
	vfs_ceph_iput(handle, &diref);
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
	struct vfs_ceph_iref cur_diref = {0};
	struct vfs_ceph_iref new_diref = {0};
	struct vfs_ceph_iref iref = {0};
	int ret = -1;

	if (cur_smb_fname->stream_name || new_smb_fname->stream_name) {
		return status_code(-ENOENT);
	}
	CEPH_DBG("%s", srcfsp->fsp_name->base_name);
	ret = vfs_ceph_igetd(handle, srcfsp, &cur_diref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("%s", dstfsp->fsp_name->base_name);
	ret = vfs_ceph_igetd(handle, dstfsp, &new_diref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("lookup: dino=%ld name=%s",
		 cur_diref.ino,
		 cur_smb_fname->base_name);
	ret = vfs_ceph_ll_lookup(handle,
				 &cur_diref,
				 cur_smb_fname->base_name,
				 &iref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("link: dino=%ld name=%s ino=%ld",
		 new_diref.ino,
		 new_smb_fname->base_name,
		 iref.ino);
	ret = vfs_ceph_ll_link(handle,
			       &new_diref,
			       new_smb_fname->base_name,
			       &iref);
	if (ret != 0) {
		goto out;
	}
out:
	vfs_ceph_iput(handle, &iref);
	vfs_ceph_iput(handle, &new_diref);
	vfs_ceph_iput(handle, &cur_diref);
	CEPH_DBGRET(ret);
	return status_code(ret);
}

static int vfs_ceph_mknodat(struct vfs_handle_struct *handle,
			    files_struct *dirfsp,
			    const struct smb_filename *smb_fname,
			    mode_t mode,
			    SMB_DEV_T dev)
{
	struct vfs_ceph_iref diref = {0};
	struct vfs_ceph_iref iref = {0};
	int ret = -1;

	CEPH_DBG("%s", dirfsp->fsp_name->base_name);
	ret = vfs_ceph_igetd(handle, dirfsp, &diref);
	if (ret != 0) {
		goto out;
	}
	CEPH_DBG("dino=%ld name=%s mode=%o dev=%d",
		 diref.ino,
		 smb_fname->base_name,
		 mode,
		 dev);
	ret = vfs_ceph_ll_mknod(handle,
				&diref,
				smb_fname->base_name,
				mode,
				dev,
				&iref);
	vfs_ceph_iput(handle, &iref);
	vfs_ceph_iput(handle, &diref);
out:
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
				  size_t sz)
{
	int ret = -1;

	if (!fsp->fsp_flags.is_pathref) {
		struct vfs_ceph_fh *cfh = NULL;

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld fd=%d name=%s", cfh->iref.ino, cfh->fd, name);
		ret = vfs_ceph_ll_getxattr(handle, &cfh->iref, name, val, sz);
	} else {
		struct vfs_ceph_iref iref = {0};

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_igetf(handle, fsp, &iref);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld name=%s", iref.ino, name);
		ret = vfs_ceph_ll_getxattr(handle, &iref, name, val, sz);
		vfs_ceph_iput(handle, &iref);
	}
out:
	CEPH_DBGRET(ret);
	return xstatus_code(ret);
}

static ssize_t vfs_ceph_flistxattr(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   char *list,
				   size_t size)
{
	size_t list_size = 0;
	int ret = -1;

	if (!fsp->fsp_flags.is_pathref) {
		struct vfs_ceph_fh *cfh = NULL;

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld fd=%d", cfh->iref.ino, cfh->fd);
		ret = vfs_ceph_ll_listxattr(handle,
					    &cfh->iref,
					    list,
					    size,
					    &list_size);
	} else {
		struct vfs_ceph_iref iref = {0};

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_igetf(handle, fsp, &iref);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld ", iref.ino);
		ret = vfs_ceph_ll_listxattr(handle,
					    &iref,
					    list,
					    size,
					    &list_size);
		vfs_ceph_iput(handle, &iref);
	}
out:
	CEPH_DBGRET(ret);
	return lstatus_code(ret ? ret : (long)list_size);
}

static int vfs_ceph_fremovexattr(struct vfs_handle_struct *handle,
				 struct files_struct *fsp,
				 const char *name)
{
	int ret = -1;

	if (!fsp->fsp_flags.is_pathref) {
		struct vfs_ceph_fh *cfh = NULL;

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld fd=%d name=%s", cfh->iref.ino, cfh->fd, name);
		ret = vfs_ceph_ll_removexattr(handle, &cfh->iref, name);
	} else {
		struct vfs_ceph_iref iref = {0};

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_igetf(handle, fsp, &iref);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld name=%s", iref.ino, name);
		ret = vfs_ceph_ll_removexattr(handle, &iref, name);
		vfs_ceph_iput(handle, &iref);
	}
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
	int ret = -1;

	if (!fsp->fsp_flags.is_pathref) {
		struct vfs_ceph_fh *cfh = NULL;

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_fetch_fh(handle, fsp, &cfh);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld fd=%d name=%s size=%zu flags=%x",
			 cfh->iref.ino,
			 cfh->fd,
			 name,
			 size,
			 flags);
		ret = vfs_ceph_ll_setxattr(handle,
					   &cfh->iref,
					   name,
					   value,
					   size,
					   flags);
	} else {
		struct vfs_ceph_iref iref = {0};

		CEPH_DBG("%s", fsp->fsp_name->base_name);
		ret = vfs_ceph_igetf(handle, fsp, &iref);
		if (ret != 0) {
			goto out;
		}
		CEPH_DBG("ino=%ld name=%s size=%zu flags=%x",
			 iref.ino,
			 name,
			 size,
			 flags);
		ret = vfs_ceph_ll_setxattr(handle,
					   &iref,
					   name,
					   value,
					   size,
					   flags);
		vfs_ceph_iput(handle, &iref);
	}
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
	.get_quota_fn = vfs_not_implemented_get_quota,
	.set_quota_fn = vfs_not_implemented_set_quota,
	.statvfs_fn = vfs_ceph_statvfs,
	.fs_capabilities_fn = vfs_ceph_fs_capabilities,
	/* Directory operations */
	.fdopendir_fn = vfs_ceph_fdopendir,
	.readdir_fn = vfs_ceph_readdir,
	.rewind_dir_fn = vfs_ceph_rewinddir,
	.mkdirat_fn = vfs_ceph_mkdirat,
	.closedir_fn = vfs_ceph_closedir,
	/* File operations */
	.create_dfs_pathat_fn = NULL,
	.read_dfs_pathat_fn = NULL,
	.openat_fn = vfs_ceph_openat,
	.close_fn = vfs_ceph_close,
	.pread_fn = vfs_ceph_pread,
	.pread_send_fn = vfs_ceph_pread_send,
	.pread_recv_fn = vfs_ceph_pread_recv,
	.pwrite_fn = vfs_ceph_pwrite,
	.pwrite_send_fn = vfs_ceph_pwrite_send,
	.pwrite_recv_fn = vfs_ceph_pwrite_recv,
	.lseek_fn = vfs_ceph_lseek,
	.sendfile_fn = vfs_not_implemented_sendfile,
	.recvfile_fn = vfs_not_implemented_recvfile,
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
	.filesystem_sharemode_fn = vfs_not_implemented_filesystem_sharemode,
	.fcntl_fn = vfs_ceph_fcntl,
	.linux_setlease_fn = vfs_not_implemented_linux_setlease,
	.getlock_fn = vfs_not_implemented_getlock,
	.symlinkat_fn = vfs_ceph_symlinkat,
	.readlinkat_fn = vfs_ceph_readlinkat,
	.linkat_fn = vfs_ceph_linkat,
	.mknodat_fn = vfs_ceph_mknodat,
	.realpath_fn = vfs_ceph_realpath,
	.fchflags_fn = vfs_not_implemented_fchflags,
	.get_real_filename_at_fn = vfs_not_implemented_get_real_filename_at,
	.connectpath_fn = vfs_ceph_connectpath,
	/* Extended-attributes operations. */
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.fgetxattr_fn = vfs_ceph_fgetxattr,
	.flistxattr_fn = vfs_ceph_flistxattr,
	.fremovexattr_fn = vfs_ceph_fremovexattr,
	.fsetxattr_fn = vfs_ceph_fsetxattr,
	/* Posix ACL Operations */
	.sys_acl_get_fd_fn = posixacl_xattr_acl_get_fd,
	.sys_acl_blob_get_fd_fn = posix_sys_acl_blob_get_fd,
	.sys_acl_set_fd_fn = posixacl_xattr_acl_set_fd,
	.sys_acl_delete_def_fd_fn = posixacl_xattr_acl_delete_def_fd,
	/* Async-IO operations */
	.aio_force_fn = vfs_not_implemented_aio_force,

};

static_decl_vfs;
NTSTATUS vfs_ceph_ng_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"ceph_ng",
				&vfs_ceph_fns);
}

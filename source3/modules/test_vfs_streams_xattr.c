/*
 * Unix SMB/CIFS implementation.
 *
 * Verify the on-disk format of vfs_streams_xattr.
 *
 * Copyright (C) Stefan Metzmacher 2026
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

/*
 * Use the default values of the options and store the xattrs
 * in memory.
 */
static size_t test_fraglen;
static ssize_t test_fgetxattr(const char *name, void *value, size_t size);
static int test_fsetxattr(const char *name, const void *value, size_t size);
static int test_fremovexattr(const char *name);

#define lp_parm_const_string(snum, type, option, def) (def)
#define lp_parm_bool(snum, type, option, def) (def)
#define lp_parm_int(snum, type, option, def) (def)
#define lp_smbd_max_xattr_size(snum) (test_fraglen)
#undef SMB_VFS_NEXT_CONNECT
#define SMB_VFS_NEXT_CONNECT(handle, service, user) (0)
#undef SMB_VFS_FGETXATTR
#define SMB_VFS_FGETXATTR(fsp, name, value, size) \
	test_fgetxattr(name, value, size)
#undef SMB_VFS_FSETXATTR
#define SMB_VFS_FSETXATTR(fsp, name, value, size, flags) \
	test_fsetxattr(name, value, size)
#undef SMB_VFS_FREMOVEXATTR
#define SMB_VFS_FREMOVEXATTR(fsp, name) \
	test_fremovexattr(name)

#include "vfs_streams_xattr.c"
#include <setjmp.h>
#include <cmocka.h>

/*
 * The streams of a file are stored in xattrs on the shared
 * filesystem, which is used by all nodes of a cluster, also by
 * different versions:
 *
 * user.DosStream.<name>:$DATA contains the stream data plus a
 * marker byte. If the stream doesn't fit into
 * "smbd max xattr size", the marker byte contains the number of
 * additional extents stored in user.DosStreamExt.<n>.<name>:$DATA.
 */

struct test_xattr {
	char *name;
	DATA_BLOB value;
};

static struct test_xattr test_xattrs[8];

static struct test_xattr *test_find_xattr(const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(test_xattrs); i++) {
		if (test_xattrs[i].name == NULL) {
			continue;
		}
		if (strcmp(test_xattrs[i].name, name) == 0) {
			return &test_xattrs[i];
		}
	}

	return NULL;
}

static ssize_t test_fgetxattr(const char *name, void *value, size_t size)
{
	struct test_xattr *x = test_find_xattr(name);

	if (x == NULL) {
		errno = ENODATA;
		return -1;
	}
	if (x->value.length > size) {
		errno = ERANGE;
		return -1;
	}
	memcpy(value, x->value.data, x->value.length);
	return x->value.length;
}

static int test_fsetxattr(const char *name, const void *value, size_t size)
{
	struct test_xattr *x = test_find_xattr(name);
	size_t i;

	if (x == NULL) {
		for (i = 0; i < ARRAY_SIZE(test_xattrs); i++) {
			if (test_xattrs[i].name == NULL) {
				x = &test_xattrs[i];
				break;
			}
		}
		assert_non_null(x);
		x->name = talloc_strdup(NULL, name);
		assert_non_null(x->name);
	}

	TALLOC_FREE(x->value.data);
	x->value = data_blob_talloc(NULL, value, size);
	assert_non_null(x->value.data);
	return 0;
}

static int test_fremovexattr(const char *name)
{
	struct test_xattr *x = test_find_xattr(name);

	if (x == NULL) {
		errno = ENODATA;
		return -1;
	}
	TALLOC_FREE(x->name);
	TALLOC_FREE(x->value.data);
	*x = (struct test_xattr) { .name = NULL, };
	return 0;
}

static void test_clear_xattrs(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(test_xattrs); i++) {
		TALLOC_FREE(test_xattrs[i].name);
		TALLOC_FREE(test_xattrs[i].value.data);
		test_xattrs[i] = (struct test_xattr) { .name = NULL, };
	}
}

static size_t test_num_xattrs(void)
{
	size_t i, num = 0;

	for (i = 0; i < ARRAY_SIZE(test_xattrs); i++) {
		if (test_xattrs[i].name != NULL) {
			num += 1;
		}
	}

	return num;
}

static void assert_xattr(const char *name, const void *value, size_t size)
{
	struct test_xattr *x = test_find_xattr(name);

	assert_non_null(x);
	assert_int_equal(x->value.length, size);
	assert_memory_equal(x->value.data, value, size);
}

static struct streams_xattr_config *test_connect(
	TALLOC_CTX *mem_ctx,
	struct vfs_handle_struct *handle)
{
	struct streams_xattr_config *config = NULL;
	int ret;

	*handle = (struct vfs_handle_struct) {
		.conn = talloc_zero(mem_ctx, struct connection_struct),
	};
	assert_non_null(handle->conn);

	ret = streams_xattr_connect(handle, "share", "user");
	assert_int_equal(ret, 0);

	config = talloc_get_type_abort(handle->data,
				       struct streams_xattr_config);
	return config;
}

/* the default configuration */
static void test_config(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct vfs_handle_struct handle;
	struct streams_xattr_config *config = test_connect(frame, &handle);

	assert_string_equal(config->prefix, "user.DosStream.");
	assert_string_equal(config->ext_prefix, "user.DosStreamExt.");
	assert_true(config->store_stream_type);
	assert_int_equal(config->max_extents, 0);

	TALLOC_FREE(frame);
}

static void test_get_name(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct vfs_handle_struct handle;
	struct streams_xattr_config *config = test_connect(frame, &handle);
	char *raw_stream_name = NULL;
	char *xattr_name = NULL;
	bool is_default;
	int ret;

	ret = streams_xattr_get_name(&handle, frame, ":foo",
				     &raw_stream_name, &is_default,
				     &xattr_name);
	assert_int_equal(ret, 0);
	assert_false(is_default);
	assert_string_equal(raw_stream_name, "foo:$DATA");
	assert_string_equal(xattr_name, "user.DosStream.foo:$DATA");

	ret = streams_xattr_get_name(&handle, frame, ":foo:$DaTa",
				     &raw_stream_name, &is_default,
				     &xattr_name);
	assert_int_equal(ret, 0);
	assert_false(is_default);
	assert_string_equal(raw_stream_name, "foo:$DATA");
	assert_string_equal(xattr_name, "user.DosStream.foo:$DATA");

	ret = streams_xattr_get_name(&handle, frame, "::$DATA",
				     &raw_stream_name, &is_default,
				     &xattr_name);
	assert_int_equal(ret, 0);
	assert_true(is_default);

	/* streams_xattr:store_stream_type = no */
	config->store_stream_type = false;
	ret = streams_xattr_get_name(&handle, frame, ":foo:$DATA",
				     &raw_stream_name, &is_default,
				     &xattr_name);
	assert_int_equal(ret, 0);
	assert_string_equal(raw_stream_name, "foo");
	assert_string_equal(xattr_name, "user.DosStream.foo");

	TALLOC_FREE(frame);
}

/*
 * A stream spread over multiple xattrs, with
 * "smbd max xattr size = 8" and
 * "streams_xattr:max xattrs per stream = 4".
 */
static void test_multi(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct vfs_handle_struct handle;
	struct streams_xattr_config *config = test_connect(frame, &handle);
	uint8_t value[20];
	uint8_t anchor[8];
	uint8_t buf[64];
	ssize_t nread;
	size_t i;
	int ret;

	config->max_extents = 3;
	test_fraglen = 8;
	test_clear_xattrs();

	/* 19 bytes of data and the marker byte */
	for (i = 0; i < sizeof(value) - 1; i++) {
		value[i] = 0x40 + i;
	}
	value[i] = 0;

	ret = fsetxattr_multi(config, NULL, "s:$DATA",
			      value, sizeof(value), 0);
	assert_int_equal(ret, 0);

	/* 7 bytes of data and the number of extents */
	memcpy(anchor, value, 7);
	anchor[7] = 2;

	assert_int_equal(test_num_xattrs(), 3);
	assert_xattr("user.DosStream.s:$DATA", anchor, sizeof(anchor));
	assert_xattr("user.DosStreamExt.1.s:$DATA", value + 7, 8);
	assert_xattr("user.DosStreamExt.2.s:$DATA", value + 15, 4);

	nread = fgetxattr_multi(config, NULL, "s:$DATA", buf, sizeof(buf));
	assert_int_equal(nread, sizeof(value));
	assert_memory_equal(buf, value, sizeof(value));

	/*
	 * A short stream only uses the anchor xattr with a zero
	 * marker byte, possible leftover extents are ignored.
	 */
	ret = fsetxattr_multi(config, NULL, "s:$DATA", "ab\0", 3, 0);
	assert_int_equal(ret, 0);

	assert_xattr("user.DosStream.s:$DATA", "ab\0", 3);

	nread = fgetxattr_multi(config, NULL, "s:$DATA", buf, sizeof(buf));
	assert_int_equal(nread, 3);
	assert_memory_equal(buf, "ab\0", 3);

	test_clear_xattrs();
	TALLOC_FREE(frame);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_config),
		cmocka_unit_test(test_get_name),
		cmocka_unit_test(test_multi),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}

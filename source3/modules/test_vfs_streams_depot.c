/*
 * Unix SMB/CIFS implementation.
 *
 * Verify the on-disk layout of vfs_streams_depot.
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
 * Use a fixed file_id instead of asking the VFS
 */
static struct file_id test_file_id;
#undef SMB_VFS_FILE_ID_CREATE
#define SMB_VFS_FILE_ID_CREATE(conn, sbuf) test_file_id

#include "vfs_streams_depot.c"
#include <setjmp.h>
#include <cmocka.h>

/*
 * The streams of a file are stored in files on the shared
 * filesystem, which is used by all nodes of a cluster, also
 * by different versions:
 *
 * <directory>/XX/YY/<hex file_id>/<name>:$DATA
 *
 * <directory> defaults to <connectpath>/.streams, XX/YY come from
 * hash_fn() of the 16 bytes of push_file_id_16(), followed by
 * the hex string of these bytes. Files with streams are marked
 * by the SAMBA_XATTR_MARKER xattr with the value '1'.
 */

static void test_hash_fn(void **state)
{
	uint8_t key[16];
	size_t i;

	for (i = 0; i < sizeof(key); i++) {
		key[i] = i;
	}

	assert_int_equal(hash_fn(data_blob_const(key, 0)), 0x00003039);
	assert_int_equal(hash_fn(data_blob_const(key, sizeof(key))),
			 0x9ce93ff7);

	memset(key, 0xff, sizeof(key));
	assert_int_equal(hash_fn(data_blob_const(key, sizeof(key))),
			 0x55d56da4);
}

static void test_dirnames(void **state)
{
	struct streams_depot_dirnames names;
	struct stat_ex sbuf = { 0, };

	test_file_id = (struct file_id) {
		.devid = 0x0102030405060708,
		.inode = 0xa1b2c3d4e5f60718,
		.extid = 0x2122232425262728,
	};

	streams_depot_get_dirnames(NULL, &sbuf, &names);

	assert_string_equal(names.first, "A3");
	assert_string_equal(names.second, "80");
	assert_string_equal(names.id_hex,
			    "08070605040302011807F6E5D4C3B2A1");
	assert_string_equal(names.full,
			    "A3/80/08070605040302011807F6E5D4C3B2A1");
}

static void test_stream_name(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *name = NULL;
	int ret;

	ret = stream_name(frame, ":foo", &name);
	assert_int_equal(ret, 0);
	assert_string_equal(name, ":foo:$DATA");

	ret = stream_name(frame, ":foo:$DATA", &name);
	assert_int_equal(ret, 0);
	assert_string_equal(name, ":foo:$DATA");

	ret = stream_name(frame, ":foo:$data", &name);
	assert_int_equal(ret, 0);
	assert_string_equal(name, ":foo:$DATA");

	ret = stream_name(frame, ":foo:bar", &name);
	assert_int_equal(ret, EINVAL);

	TALLOC_FREE(frame);
}

static void test_marker(void **state)
{
	assert_string_equal(SAMBA_XATTR_MARKER, "user.SAMBA_STREAMS");
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_hash_fn),
		cmocka_unit_test(test_dirnames),
		cmocka_unit_test(test_stream_name),
		cmocka_unit_test(test_marker),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}

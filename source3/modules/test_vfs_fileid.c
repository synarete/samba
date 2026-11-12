/*
 * Unix SMB/CIFS implementation.
 *
 * Verify that vfs_fileid creates the same file_ids for the same
 * input in all versions.
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

/*
 * The hostname and the vnn are inputs of some algorithms,
 * use fixed values.
 */
#define gethostname test_gethostname
#define get_my_vnn test_get_my_vnn

#include "vfs_fileid.c"
#include <setjmp.h>
#include <cmocka.h>

#undef gethostname
#undef get_my_vnn

/*
 * The file_id is part of the keys of locking.tdb, brlock.tdb,
 * leases.tdb and others, which are shared between all nodes of
 * a cluster, also between different versions. With the same
 * configuration and the same input from the filesystem, all
 * versions need to create the same file_id.
 */

int test_gethostname(char *name, size_t len)
{
	strlcpy(name, "node1", len);
	return 0;
}

uint32_t test_get_my_vnn(void)
{
	return 2;
}

static void test_uint64_hash(void **state)
{
	char long_str[301];
	size_t i;

	for (i = 0; i < sizeof(long_str) - 1; i++) {
		long_str[i] = 'a' + (i % 26);
	}
	long_str[i] = '\0';

	assert_int_equal(fileid_uint64_hash((const uint8_t *)"", 0),
			 0x0000000000003039ULL);
	assert_int_equal(fileid_uint64_hash((const uint8_t *)"a", 1),
			 0x0922dfa6094a72e9ULL);
	assert_int_equal(fileid_uint64_hash((const uint8_t *)"gpfs0", 5),
			 0x2e82e33ecbd75bffULL);
	assert_int_equal(fileid_uint64_hash((const uint8_t *)long_str,
					    strlen(long_str)),
			 0x0b059fe6b1df8108ULL);
}

BUILD_ASSERT(sizeof(fsid_t) == 2 * sizeof(uint32_t));

static struct fileid_handle_data *test_data(TALLOC_CTX *mem_ctx)
{
	struct fileid_handle_data *data = NULL;
	uint32_t fsid[2] = { 0x11223344, 0x55667788 };

	data = talloc_zero(mem_ctx, struct fileid_handle_data);
	assert_non_null(data);

	/*
	 * With mount entries, fileid_find_mount_entry() doesn't
	 * load them from /etc/mtab.
	 */
	data->mount_entries = talloc_zero_array(data,
						struct fileid_mount_entry,
						1);
	assert_non_null(data->mount_entries);
	data->num_mount_entries = 1;
	data->mount_entries[0] = (struct fileid_mount_entry) {
		.device = 0x803,
		.mnt_fsname = "gpfs0",
		.devid = UINT64_MAX,
	};
	memcpy(&data->mount_entries[0].fsid, fsid, sizeof(fsid));

	data->nolock.extid = fileid_mapping_nolock_extid(1);

	return data;
}

static void assert_file_id_equal(struct file_id id,
				 uint64_t devid,
				 uint64_t inode,
				 uint64_t extid)
{
	assert_int_equal(id.devid, devid);
	assert_int_equal(id.inode, inode);
	assert_int_equal(id.extid, extid);
}

static void test_mapping_fsname(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct fileid_handle_data *data = test_data(frame);
	SMB_STRUCT_STAT sbuf = {
		.st_ex_dev = 0x803,
		.st_ex_ino = 0x1234,
	};

	assert_file_id_equal(fileid_mapping_fsname(data, &sbuf),
			     0x2e82e33ecbd75bffULL, 0x1234, 0);

	TALLOC_FREE(frame);
}

static void test_mapping_fsid(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct fileid_handle_data *data = test_data(frame);
	SMB_STRUCT_STAT sbuf = {
		.st_ex_dev = 0x803,
		.st_ex_ino = 0x1234,
	};
	uint64_t devid;

#ifdef WORDS_BIGENDIAN
	devid = 0x1122334455667788ULL;
#else
	devid = 0x5566778811223344ULL;
#endif

	assert_file_id_equal(fileid_mapping_fsid(data, &sbuf),
			     devid, 0x1234, 0);

	TALLOC_FREE(frame);
}

static void test_mapping_hostname(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct fileid_handle_data *data = test_data(frame);
	SMB_STRUCT_STAT sbuf = {
		.st_ex_dev = 0x803,
		.st_ex_ino = 0x1234,
	};

	assert_file_id_equal(fileid_mapping_hostname(data, &sbuf),
			     0x531db66bd4e369ecULL, 0x1234, 0);

	TALLOC_FREE(frame);
}

static void test_nolock_extid(void **state)
{
	/*
	 * The buffer contains HOST_NAME_MAX + 1 bytes for the
	 * hostname, the expected value is for Linux.
	 */
	if (HOST_NAME_MAX != 64) {
		skip();
	}

	assert_int_equal(fileid_mapping_nolock_extid(1),
			 0xc624fa38bf41f412ULL);
}

static void test_file_id_create(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct fileid_handle_data *data = test_data(frame);
	struct vfs_handle_struct handle = { .data = data, };
	SMB_STRUCT_STAT file = {
		.st_ex_dev = 0x803,
		.st_ex_ino = 0x1234,
		.st_ex_mode = S_IFREG,
	};
	SMB_STRUCT_STAT dir = {
		.st_ex_dev = 0x803,
		.st_ex_ino = 0x5678,
		.st_ex_mode = S_IFDIR,
	};
	uint64_t devid;

	data->handle = &handle;
	data->mapping_fn = fileid_mapping_fsname;
	devid = fileid_device_mapping_fsname(data, &file);

	/* fileid:algorithm = fsname */
	assert_file_id_equal(fileid_file_id_create(&handle, &file),
			     devid, 0x1234, 0);
	assert_file_id_equal(fileid_file_id_create(&handle, &dir),
			     devid, 0x5678, 0);

	/* fileid:algorithm = fsname_nodirs */
	data->nolock.force_all_dirs = true;
	assert_file_id_equal(fileid_file_id_create(&handle, &file),
			     devid, 0x1234, 0);
	assert_file_id_equal(fileid_file_id_create(&handle, &dir),
			     devid, 0x5678, data->nolock.extid);

	TALLOC_FREE(frame);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_uint64_hash),
		cmocka_unit_test(test_mapping_fsname),
		cmocka_unit_test(test_mapping_fsid),
		cmocka_unit_test(test_mapping_hostname),
		cmocka_unit_test(test_nolock_extid),
		cmocka_unit_test(test_file_id_create),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}

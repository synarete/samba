/*
 * Unix SMB/CIFS implementation.
 *
 * Verify the format of the locking.tdb records.
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

#include "share_mode_lock.c"
#include <setjmp.h>
#include <cmocka.h>

/*
 * locking.tdb is shared between all nodes of a cluster, also
 * between different versions. The NDR structures share_mode_data
 * and share_mode_entry are protected by
 * source3/librpc/idl/ABI/open_files.ndrabi, but the framing of
 * the record and the order of the share mode entries are hand
 * written:
 *
 * uint32_t share_mode_data_len (little endian)
 * uint8_t share_mode_data[share_mode_data_len] (NDR)
 * share_mode_entry[] in fixed SHARE_MODE_ENTRY_SIZE NDR buffers,
 *     sorted in descending order of share_mode_entry_cmp(),
 *     which share_mode_entry_find() relies on for a binary
 *     search.
 */

BUILD_ASSERT(SHARE_MODE_ENTRY_SIZE == 128);

static void test_locking_tdb_data_parse(void **state)
{
	uint8_t buf[4 + 3 + 2 * SHARE_MODE_ENTRY_SIZE] = { 0, };
	struct locking_tdb_data data;
	bool ok;

	/* an empty record */
	ok = locking_tdb_data_parse(&data, buf, 0);
	assert_true(ok);
	assert_int_equal(data.share_mode_data_len, 0);
	assert_int_equal(data.num_share_entries, 0);

	/* 3 bytes of share_mode_data and 2 share mode entries */
	PUSH_LE_U32(buf, 0, 3);
	buf[4] = 0x11;
	buf[5] = 0x22;
	buf[6] = 0x33;
	buf[7] = 0x44;

	ok = locking_tdb_data_parse(&data, buf, sizeof(buf));
	assert_true(ok);
	assert_ptr_equal(data.share_mode_data_buf, buf + 4);
	assert_int_equal(data.share_mode_data_len, 3);
	assert_ptr_equal(data.share_entries, buf + 4 + 3);
	assert_int_equal(data.num_share_entries, 2);

	/* only share_mode_data */
	ok = locking_tdb_data_parse(&data, buf, 4 + 3);
	assert_true(ok);
	assert_int_equal(data.share_mode_data_len, 3);
	assert_int_equal(data.num_share_entries, 0);

	/* incomplete share mode entries */
	ok = locking_tdb_data_parse(&data, buf, sizeof(buf) - 1);
	assert_false(ok);

	/* share_mode_data_len too large */
	PUSH_LE_U32(buf, 0, sizeof(buf));
	ok = locking_tdb_data_parse(&data, buf, sizeof(buf));
	assert_false(ok);
}

/*
 * The order of share_mode_entry_cmp() from the smallest to the
 * largest entry, a change would break the binary search in
 * share_mode_entry_find() for records written by other versions.
 */
static const struct {
	struct server_id pid;
	uint64_t share_file_id;
} sorted_entries[] = {
	{
		.pid = { .vnn = 0, .pid = 2, .task_id = 1, .unique_id = 1, },
		.share_file_id = 1,
	},
	{
		.pid = { .vnn = 0, .pid = 2, .task_id = 1, .unique_id = 1, },
		.share_file_id = 2,
	},
	{
		.pid = { .vnn = 0, .pid = 2, .task_id = 1, .unique_id = 2, },
		.share_file_id = 0,
	},
	{
		.pid = { .vnn = 0, .pid = 2, .task_id = 2, .unique_id = 0, },
		.share_file_id = 0,
	},
	{
		.pid = { .vnn = 0, .pid = 3, .task_id = 0, .unique_id = 0, },
		.share_file_id = 0,
	},
	{
		.pid = { .vnn = 1, .pid = 1, .task_id = 0, .unique_id = 0, },
		.share_file_id = 0,
	},
	{
		.pid = { .vnn = 0xffffffff, .pid = 0, .task_id = 0, },
		.share_file_id = 0,
	},
};

static void test_share_mode_entry_cmp(void **state)
{
	size_t i, j;

	for (i = 0; i < ARRAY_SIZE(sorted_entries); i++) {
		for (j = 0; j < ARRAY_SIZE(sorted_entries); j++) {
			int cmp, expected;

			cmp = share_mode_entry_cmp(
				sorted_entries[i].pid,
				sorted_entries[i].share_file_id,
				sorted_entries[j].pid,
				sorted_entries[j].share_file_id);
			expected = (i < j) ? -1 : (i > j) ? 1 : 0;
			assert_int_equal(cmp, expected);
		}
	}
}

/*
 * share_mode_entry_find() finds the entries in an array sorted
 * in descending order and returns the position for new entries.
 */
static void test_share_mode_entry_find(void **state)
{
	const size_t num = ARRAY_SIZE(sorted_entries);
	uint8_t buf[ARRAY_SIZE(sorted_entries) * SHARE_MODE_ENTRY_SIZE];
	struct share_mode_entry e;
	size_t i, idx;
	bool match;

	for (i = 0; i < num; i++) {
		size_t pos = num - 1 - i;
		struct share_mode_entry_buf ebuf;
		bool ok;

		e = (struct share_mode_entry) {
			.pid = sorted_entries[i].pid,
			.share_file_id = sorted_entries[i].share_file_id,
		};
		ok = share_mode_entry_put(&e, &ebuf);
		assert_true(ok);
		memcpy(buf + pos * SHARE_MODE_ENTRY_SIZE,
		       ebuf.buf,
		       SHARE_MODE_ENTRY_SIZE);
	}

	for (i = 0; i < num; i++) {
		idx = share_mode_entry_find(buf,
					    num,
					    sorted_entries[i].pid,
					    sorted_entries[i].share_file_id,
					    &e,
					    &match);
		assert_true(match);
		assert_int_equal(idx, num - 1 - i);
		assert_true(server_id_equal(&e.pid, &sorted_entries[i].pid));
		assert_int_equal(e.share_file_id,
				 sorted_entries[i].share_file_id);
	}

	/*
	 * between sorted_entries[3] and sorted_entries[4],
	 * which are at the positions 3 and 2.
	 */
	idx = share_mode_entry_find(
		buf,
		num,
		(struct server_id) { .vnn = 0, .pid = 2, .task_id = 3, },
		0,
		&e,
		&match);
	assert_false(match);
	assert_int_equal(idx, 3);

	/* smaller than all entries, so at the end */
	idx = share_mode_entry_find(
		buf,
		num,
		(struct server_id) { .vnn = 0, .pid = 1, },
		0,
		&e,
		&match);
	assert_false(match);
	assert_int_equal(idx, num);

	/* larger than all entries, so at the beginning */
	idx = share_mode_entry_find(
		buf,
		num,
		(struct server_id) { .vnn = UINT32_MAX, .pid = 1, },
		0,
		&e,
		&match);
	assert_false(match);
	assert_int_equal(idx, 0);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_locking_tdb_data_parse),
		cmocka_unit_test(test_share_mode_entry_cmp),
		cmocka_unit_test(test_share_mode_entry_find),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}

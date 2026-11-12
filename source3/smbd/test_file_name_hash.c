/*
 * Unix SMB/CIFS implementation.
 *
 * Verify the name_hash of files.
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

#include "files.c"
#include <setjmp.h>
#include <cmocka.h>

/*
 * The name_hash of a file is stored in the delete tokens and
 * share mode entries in locking.tdb, which is shared between all
 * nodes of a cluster, also between different versions. It's the
 * tdb_jenkins_hash() of the full path including the terminating
 * nul byte.
 */

static uint32_t test_jenkins_hash(const char *path)
{
	TDB_DATA key = {
		.dptr = discard_const_p(uint8_t, path),
		.dsize = strlen(path) + 1,
	};

	return tdb_jenkins_hash(&key);
}

static void test_name_hash(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct connection_struct conn = {
		.connectpath = discard_const_p(char, "/srv/share"),
	};
	uint32_t hash = 0;
	bool ok;

	/* tdb_jenkins_hash() itself */
	assert_int_equal(test_jenkins_hash("/srv/share/dir/file"),
			 0xce12bd8e);

	ok = file_name_hash(&conn, "dir/file", &hash);
	assert_true(ok);
	assert_int_equal(hash, test_jenkins_hash("/srv/share/dir/file"));

	ok = file_name_hash(&conn, "/other/dir/file", &hash);
	assert_true(ok);
	assert_int_equal(hash, test_jenkins_hash("/other/dir/file"));

	/* a stream name is part of the name */
	ok = file_name_hash(&conn, "dir/file:stream", &hash);
	assert_true(ok);
	assert_int_equal(hash,
			 test_jenkins_hash("/srv/share/dir/file:stream"));

	TALLOC_FREE(frame);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_name_hash),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}

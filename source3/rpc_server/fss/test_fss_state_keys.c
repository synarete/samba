/*
 * Unix SMB/CIFS implementation.
 *
 * Verify the keys of the fsrvp server state database.
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

#include "srv_fss_state.c"
#include "lib/util/dlinklist.h"
#include <setjmp.h>
#include <cmocka.h>

/*
 * The fsrvp server state in srv_fss.tdb is shared between all
 * nodes of a cluster, also between different versions. The
 * values are protected by librpc/idl/ABI/fsrvp_state.ndrabi,
 * but the keys are hand written strings:
 *
 * db_version
 * sc_set_count
 * sc_set/<sc_set id>
 * sc_set/<sc_set id>/sc/<sc id>
 * sc_set/<sc_set id>/sc/<sc id>/smap/<sc share name>
 */

static const char *expected_keys[] = {
	"db_version",
	"sc_set_count",
	"sc_set/set-id",
	"sc_set/set-id/sc/sc-id",
	"sc_set/set-id/sc/sc-id/smap/share@sc",
};

struct test_keys_state {
	bool found[ARRAY_SIZE(expected_keys)];
	size_t num;
};

static int test_keys_fn(struct tdb_context *tdb,
			TDB_DATA key,
			TDB_DATA data,
			void *private_data)
{
	struct test_keys_state *state = private_data;
	size_t i;

	state->num += 1;

	for (i = 0; i < ARRAY_SIZE(expected_keys); i++) {
		if (key.dsize != strlen(expected_keys[i]) + 1) {
			continue;
		}
		if (memcmp(key.dptr, expected_keys[i], key.dsize) != 0) {
			continue;
		}
		state->found[i] = true;

		if (i < 2) {
			/* db_version and sc_set_count */
			assert_int_equal(data.dsize, 4);
			assert_int_equal(PULL_LE_U32(data.dptr, 0), 1);
		}
		return 0;
	}

	fail_msg("unexpected key [%.*s]", (int)key.dsize, key.dptr);
	return 0;
}

static void test_keys(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct fss_sc_set sc_set = {
		.id_str = discard_const_p(char, "set-id"),
		.state = FSS_SC_COMMITED,
		.context = 0x01020304,
	};
	struct fss_sc sc = {
		.id_str = discard_const_p(char, "sc-id"),
		.volume_name = discard_const_p(char, "/vol"),
		.sc_path = discard_const_p(char, "/vol/.snap"),
		.create_ts = 1000,
		.sc_set = &sc_set,
	};
	struct fss_sc_smap smap = {
		.share_name = discard_const_p(char, "share"),
		.sc_share_name = discard_const_p(char, "share@sc"),
		.sc_share_comment = discard_const_p(char, "comment"),
	};
	struct test_keys_state kstate = { .num = 0, };
	const char *tmpdir = getenv("TMPDIR");
	char *dir = NULL;
	char *conf_path = NULL;
	char *db_path = NULL;
	FILE *f = NULL;
	struct tdb_context *tdb = NULL;
	NTSTATUS status;
	size_t i;
	bool ok;

	DLIST_ADD(sc.smaps, &smap);
	sc.smaps_count = 1;
	DLIST_ADD(sc_set.scs, &sc);
	sc_set.scs_count = 1;

	dir = talloc_asprintf(frame,
			      "%s/test_fss_state_keys.XXXXXX",
			      tmpdir != NULL ? tmpdir : "/tmp");
	assert_non_null(dir);
	assert_non_null(mkdtemp(dir));

	/* an empty smb.conf, so db_open() doesn't use clustering */
	conf_path = talloc_asprintf(frame, "%s/smb.conf", dir);
	assert_non_null(conf_path);
	f = fopen(conf_path, "w");
	assert_non_null(f);
	fclose(f);
	ok = lp_load_initial_only(conf_path);
	assert_true(ok);

	db_path = talloc_asprintf(frame, "%s/srv_fss.tdb", dir);
	assert_non_null(db_path);

	status = fss_state_store(frame, &sc_set, 1, db_path);
	assert_true(NT_STATUS_IS_OK(status));

	tdb = tdb_open(db_path, 0, TDB_DEFAULT, O_RDONLY, 0);
	assert_non_null(tdb);
	tdb_traverse(tdb, test_keys_fn, &kstate);
	tdb_close(tdb);

	assert_int_equal(kstate.num, ARRAY_SIZE(expected_keys));
	for (i = 0; i < ARRAY_SIZE(expected_keys); i++) {
		if (!kstate.found[i]) {
			fail_msg("missing key [%s]", expected_keys[i]);
		}
	}

	unlink(db_path);
	unlink(conf_path);
	rmdir(dir);
	TALLOC_FREE(frame);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_keys),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}

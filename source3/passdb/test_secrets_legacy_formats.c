/*
 * Unix SMB/CIFS implementation.
 *
 * Verify the hand written records in secrets.tdb.
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
#include "secrets.h"
#include "libcli/security/dom_sid.h"
#include <setjmp.h>
#include <cmocka.h>

/*
 * secrets.tdb is shared between all nodes of a cluster, also
 * between different versions. Most records are NDR, but some
 * legacy records are hand written.
 */

/* the format of an OpenAFS KeyFile, 100 bytes on all platforms */
BUILD_ASSERT(SECRETS_AFS_MAXKEYS == 8);
BUILD_ASSERT(offsetof(struct afs_key, kvno) == 0);
BUILD_ASSERT(offsetof(struct afs_key, key) == 4);
BUILD_ASSERT(sizeof(struct afs_key) == 12);
BUILD_ASSERT(offsetof(struct afs_keyfile, nkeys) == 0);
BUILD_ASSERT(offsetof(struct afs_keyfile, entry) == 4);
BUILD_ASSERT(sizeof(struct afs_keyfile) == 100);

static char *test_dir;
static char *test_conf_path;

static int setup_secrets(void **state)
{
	const char *tmpdir = getenv("TMPDIR");
	FILE *f = NULL;
	bool ok;

	test_dir = talloc_asprintf(NULL,
				   "%s/test_secrets_legacy.XXXXXX",
				   tmpdir != NULL ? tmpdir : "/tmp");
	assert_non_null(test_dir);
	assert_non_null(mkdtemp(test_dir));

	/* an empty smb.conf, so db_open() doesn't use clustering */
	test_conf_path = talloc_asprintf(test_dir, "%s/smb.conf", test_dir);
	assert_non_null(test_conf_path);
	f = fopen(test_conf_path, "w");
	assert_non_null(f);
	fclose(f);
	ok = lp_load_initial_only(test_conf_path);
	assert_true(ok);

	ok = secrets_init_path(test_dir);
	assert_true(ok);

	return 0;
}

static int teardown_secrets(void **state)
{
	char *path = NULL;

	path = talloc_asprintf(test_dir, "%s/secrets.tdb", test_dir);
	assert_non_null(path);
	unlink(path);
	unlink(test_conf_path);
	rmdir(test_dir);
	TALLOC_FREE(test_dir);

	return 0;
}

static void assert_secret(const char *key, const void *value, size_t size)
{
	uint8_t *data = NULL;
	size_t data_size = 0;

	data = secrets_fetch(key, &data_size);
	assert_non_null(data);
	assert_int_equal(data_size, size);
	assert_memory_equal(data, value, size);
	SAFE_FREE(data);
}

static void test_machine_pw_sync(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct dom_sid sid;
	enum netr_SchannelType channel;
	time_t last_set_time = 0;
	char *pw = NULL;
	bool ok;

	ok = string_to_sid(&sid, "S-1-5-21-1-2-3");
	assert_true(ok);

	ok = secrets_store_machine_pw_sync("secret",
					   "old",
					   "dom",
					   NULL,
					   NULL,
					   0,
					   &sid,
					   0x01020304,
					   SEC_CHAN_WKSTA,
					   false);
	assert_true(ok);

	/* nul-terminated strings */
	assert_secret("SECRETS/MACHINE_PASSWORD/DOM", "secret", 7);
	assert_secret("SECRETS/MACHINE_PASSWORD.PREV/DOM", "old", 4);

	/* 32-bit little endian values */
	assert_secret("SECRETS/MACHINE_LAST_CHANGE_TIME/DOM",
		      "\x04\x03\x02\x01", 4);
	assert_secret("SECRETS/MACHINE_SEC_CHANNEL_TYPE/DOM",
		      "\x02\x00\x00\x00", 4);

	pw = secrets_fetch_machine_password("dom", &last_set_time, &channel);
	assert_non_null(pw);
	assert_string_equal(pw, "secret");
	assert_int_equal(last_set_time, 0x01020304);
	assert_int_equal(channel, SEC_CHAN_WKSTA);
	SAFE_FREE(pw);

	TALLOC_FREE(frame);
}

static void test_afs_keyfile(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct afs_keyfile keyfile = {
		.nkeys = htonl(2),
	};
	struct afs_key key;
	uint8_t expected[100] = {
		0x00, 0x00, 0x00, 0x02,		/* nkeys */
		0x00, 0x00, 0x00, 0x01,		/* kvno */
		'k', 'e', 'y', '1', 'k', 'e', 'y', '1',
		0x00, 0x00, 0x00, 0x02,		/* kvno */
		'k', 'e', 'y', '2', 'k', 'e', 'y', '2',
	};
	bool ok;

	keyfile.entry[0].kvno = htonl(1);
	memcpy(keyfile.entry[0].key, "key1key1", 8);
	keyfile.entry[1].kvno = htonl(2);
	memcpy(keyfile.entry[1].key, "key2key2", 8);

	ok = secrets_store_afs_keyfile("cell", &keyfile);
	assert_true(ok);

	assert_secret("SECRETS/AFS_KEYFILE/cell", expected, sizeof(expected));

	/* the last key */
	ok = secrets_fetch_afs_key("cell", &key);
	assert_true(ok);
	assert_int_equal(key.kvno, 2);
	assert_memory_equal(key.key, "key2key2", 8);

	TALLOC_FREE(frame);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_machine_pw_sync),
		cmocka_unit_test(test_afs_keyfile),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, setup_secrets, teardown_secrets);
}

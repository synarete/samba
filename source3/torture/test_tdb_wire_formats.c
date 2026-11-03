/*
 * Unix SMB/CIFS implementation.
 *
 * Verify that the NDR descriptions of hand-marshalled
 * (e.g. tdb_pack()) database records match the real records.
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
#include "torture/proto.h"
#include "system/filesys.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_open.h"
#include "registry.h"
#include "registry/reg_api.h"
#include "registry/reg_api_util.h"
#include "registry/reg_util_token.h"
#include "registry/reg_init_basic.h"
#include "registry/reg_db.h"
#include "librpc/gen_ndr/ndr_regdb.h"

/*
 * Pull the raw record with the NDR description and make sure
 * pushing it again results in exactly the same bytes.
 */
static bool tdb_wire_format_check(struct db_context *db,
				   const char *keystr,
				   void *r,
				   ndr_pull_flags_fn_t pull_fn,
				   ndr_push_flags_fn_t push_fn)
{
	TALLOC_CTX *frame = talloc_stackframe();
	TDB_DATA value = { .dsize = 0, };
	DATA_BLOB blob;
	DATA_BLOB blob2 = { .length = 0, };
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	bool ret = false;

	status = dbwrap_fetch_bystring(db, frame, keystr, &value);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"dbwrap_fetch_bystring(%s) failed: %s\n",
			keystr,
			nt_errstr(status));
		goto fail;
	}
	blob = data_blob_const(value.dptr, value.dsize);

	ndr_err = ndr_pull_struct_blob_all(&blob, frame, r, pull_fn);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		fprintf(stderr,
			"ndr_pull_struct_blob_all(%s) failed: %s\n",
			keystr,
			ndr_errstr(ndr_err));
		dump_data(0, blob.data, blob.length);
		goto fail;
	}

	ndr_err = ndr_push_struct_blob(&blob2, frame, r, push_fn);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		fprintf(stderr,
			"ndr_push_struct_blob(%s) failed: %s\n",
			keystr,
			ndr_errstr(ndr_err));
		goto fail;
	}

	if (data_blob_cmp(&blob, &blob2) != 0) {
		fprintf(stderr, "%s: re-pushed record differs\n", keystr);
		dump_data(0, blob.data, blob.length);
		dump_data(0, blob2.data, blob2.length);
		goto fail;
	}

	ret = true;
fail:
	TALLOC_FREE(frame);
	return ret;
}

#define TDB_WIRE_FORMAT_CHECK(db, keystr, r, type) \
	tdb_wire_format_check(db, \
			      keystr, \
			      r, \
			      (ndr_pull_flags_fn_t)ndr_pull_##type, \
			      (ndr_push_flags_fn_t)ndr_push_##type)

/*
 * registry.tdb, see source3/librpc/idl/regdb.idl
 */
bool run_registry_wire_format(int dummy)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *parent_path = "HKLM\\SOFTWARE";
	const char *test_name = "WireFormatTest";
	const char *test_key = "HKLM\\SOFTWARE\\WIREFORMATTEST";
	const char *subkey_names[] = { "Sub1", "Sub2" };
	uint8_t binary[] = { 0x00, 0x01, 0x02, 0xff };
	struct registry_value values[] = {
		{
			.type = REG_DWORD,
			.data = data_blob_const("\x04\x03\x02\x01", 4),
		},
		{
			.type = REG_BINARY,
			.data = data_blob_const(binary, sizeof(binary)),
		},
		{
			.type = REG_NONE,
			.data = data_blob_null,
		},
	};
	const char *value_names[ARRAY_SIZE(values)] = {
		"dword", "binary", "",
	};
	struct security_token *token = NULL;
	struct registry_key *parent = NULL;
	struct registry_key *key = NULL;
	struct registry_key *subkey = NULL;
	struct db_context *db = NULL;
	char *db_path = NULL;
	char *keystr = NULL;
	struct regdb_version_rec version = { .version = 0, };
	struct regdb_subkey_list subkeys = { .num_subkeys = 0, };
	struct regdb_value_list vals = { .num_values = 0, };
	NTSTATUS status;
	WERROR werr;
	bool ret = false;
	bool ok;
	size_t i;

	status = registry_create_admin_token(frame, &token);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "registry_create_admin_token failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	werr = registry_init_basic();
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr, "registry_init_basic failed: %s\n",
			win_errstr(werr));
		goto fail;
	}

	werr = reg_open_path(frame,
			     parent_path,
			     REG_KEY_ALL,
			     token,
			     &parent);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr, "reg_open_path(%s) failed: %s\n",
			parent_path,
			win_errstr(werr));
		goto fail;
	}

	werr = reg_deletekey_recursive(parent, test_name);
	if (!W_ERROR_IS_OK(werr) && !W_ERROR_EQUAL(werr, WERR_FILE_NOT_FOUND)) {
		fprintf(stderr, "reg_deletekey_recursive failed: %s\n",
			win_errstr(werr));
		goto fail;
	}

	werr = reg_createkey(frame, parent, test_name, REG_KEY_ALL, &key, NULL);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr, "reg_createkey(%s) failed: %s\n",
			test_name,
			win_errstr(werr));
		goto fail;
	}

	for (i = 0; i < ARRAY_SIZE(subkey_names); i++) {
		werr = reg_createkey(frame,
				     key,
				     subkey_names[i],
				     REG_KEY_ALL,
				     &subkey,
				     NULL);
		if (!W_ERROR_IS_OK(werr)) {
			fprintf(stderr, "reg_createkey(%s) failed: %s\n",
				subkey_names[i],
				win_errstr(werr));
			goto fail;
		}
	}

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		werr = reg_setvalue(key, value_names[i], &values[i]);
		if (!W_ERROR_IS_OK(werr)) {
			fprintf(stderr, "reg_setvalue(%s) failed: %s\n",
				value_names[i],
				win_errstr(werr));
			goto fail;
		}
	}

	/*
	 * This shares the tdb with the registry code
	 */
	db_path = state_path(frame, "registry.tdb");
	if (db_path == NULL) {
		fprintf(stderr, "state_path failed\n");
		goto fail;
	}
	db = db_open(frame, db_path, 0,
		     REG_TDB_FLAGS, O_RDONLY, 0600,
		     DBWRAP_LOCK_ORDER_1, REG_DBWRAP_FLAGS);
	if (db == NULL) {
		fprintf(stderr, "db_open(%s) failed\n", db_path);
		goto fail;
	}

	ok = TDB_WIRE_FORMAT_CHECK(db,
				   "INFO/version",
				   &version,
				   regdb_version_rec);
	if (!ok) {
		goto fail;
	}
	if (version.version != REGDB_CODE_VERSION) {
		fprintf(stderr, "version %d expected %d\n",
			version.version,
			REGDB_CODE_VERSION);
		goto fail;
	}

	ok = TDB_WIRE_FORMAT_CHECK(db,
				   test_key,
				   &subkeys,
				   regdb_subkey_list);
	if (!ok) {
		goto fail;
	}
	if (subkeys.num_subkeys != ARRAY_SIZE(subkey_names)) {
		fprintf(stderr, "num_subkeys %"PRIu32" expected %zu\n",
			subkeys.num_subkeys,
			ARRAY_SIZE(subkey_names));
		goto fail;
	}
	for (i = 0; i < ARRAY_SIZE(subkey_names); i++) {
		if (strcmp(subkeys.subkeys[i].name, subkey_names[i]) != 0) {
			fprintf(stderr, "subkey[%zu] %s expected %s\n",
				i,
				subkeys.subkeys[i].name,
				subkey_names[i]);
			goto fail;
		}
	}

	keystr = talloc_asprintf(frame, "%s\\%s", REG_VALUE_PREFIX, test_key);
	if (keystr == NULL) {
		fprintf(stderr, "talloc_asprintf failed\n");
		goto fail;
	}

	ok = TDB_WIRE_FORMAT_CHECK(db, keystr, &vals, regdb_value_list);
	if (!ok) {
		goto fail;
	}
	if (vals.num_values != ARRAY_SIZE(values)) {
		fprintf(stderr, "num_values %"PRIu32" expected %zu\n",
			vals.num_values,
			ARRAY_SIZE(values));
		goto fail;
	}
	for (i = 0; i < ARRAY_SIZE(values); i++) {
		const struct regdb_value *v = &vals.values[i];

		if ((strcmp(v->name, value_names[i]) != 0) ||
		    (v->type != values[i].type) ||
		    (v->size != values[i].data.length) ||
		    ((v->size > 0) &&
		     (memcmp(v->data, values[i].data.data, v->size) != 0)))
		{
			fprintf(stderr, "value[%zu] %s mismatch\n",
				i,
				value_names[i]);
			goto fail;
		}
	}

	ret = true;
fail:
	if (parent != NULL) {
		reg_deletekey_recursive(parent, test_name);
	}
	TALLOC_FREE(frame);
	return ret;
}

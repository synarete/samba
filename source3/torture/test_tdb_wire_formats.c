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
#include "passdb.h"
#include "lib/param/param.h"
#include "source3/param/loadparm.h"
#include "librpc/gen_ndr/samr.h"
#include "librpc/gen_ndr/ndr_tdbsam.h"
#include "../libcli/security/security.h"
#include "groupdb/mapping.h"
#include "librpc/gen_ndr/ndr_group_mapping.h"
#include "lib/privileges.h"
#include "librpc/gen_ndr/ndr_account_policy.h"
#include "idmap.h"
#include "idmap_autorid_tdb.h"
#include "winbindd/idmap_tdb_common.h"
#include "librpc/gen_ndr/ndr_idmap_tdb.h"
#include "lib/util/string_wrappers.h"

static void fill_pattern(void *ptr, size_t len, uint8_t start)
{
	uint8_t *p = ptr;
	size_t i;

	for (i = 0; i < len; i++) {
		p[i] = (uint8_t)(start + i);
	}
}

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

static bool tdbsam_blob_check(const char *name,
			      const struct tdbsam_blob *b,
			      const char *str)
{
	size_t len = (str != NULL) ? strlen(str) + 1 : 0;

	if ((b->length != len) ||
	    ((len > 0) && (memcmp(b->data, str, len) != 0)))
	{
		fprintf(stderr, "%s mismatch\n", name);
		return false;
	}
	return true;
}

/*
 * passdb.tdb, see source3/librpc/idl/tdbsam.idl
 */
bool run_passdb_wire_format(int dummy)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *username = "wireformat";
	uint8_t nt_pw[NT_HASH_LEN];
	uint8_t lm_pw[LM_HASH_LEN];
	uint8_t hours[MAX_HOURS_LEN];
	struct samu *sam = NULL;
	struct db_context *db = NULL;
	char *db_path = NULL;
	char *location = NULL;
	struct loadparm_context *lp_ctx = NULL;
	char *keystr = NULL;
	struct tdbsam_version_rec version = { .version = 0, };
	struct tdbsam_next_rid_rec next_rid = { .rid = 0, };
	struct tdbsam_rid_rec rid_rec = { .name = NULL, };
	struct tdbsam_user_v3 user = { .logon_time = 0, };
	uint32_t rid = 0;
	NTSTATUS status;
	bool ret = false;
	bool ok;

	db_path = lock_path(frame, "wire_format_passdb.tdb");
	if (db_path == NULL) {
		fprintf(stderr, "lock_path failed\n");
		goto fail;
	}
	unlink(db_path);

	location = talloc_asprintf(frame, "tdbsam:%s", db_path);
	if (location == NULL) {
		fprintf(stderr, "talloc_asprintf failed\n");
		goto fail;
	}
	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		fprintf(stderr, "loadparm_init_s3 failed\n");
		goto fail;
	}
	lpcfg_set_cmdline(lp_ctx, "passdb backend", location);

	ok = initialize_password_db(true, NULL);
	if (!ok) {
		fprintf(stderr, "initialize_password_db failed\n");
		goto fail;
	}

	ok = pdb_new_rid(&rid);
	if (!ok) {
		fprintf(stderr, "pdb_new_rid failed\n");
		goto fail;
	}

	sam = samu_new(frame);
	if (sam == NULL) {
		fprintf(stderr, "samu_new failed\n");
		goto fail;
	}

	fill_pattern(nt_pw, sizeof(nt_pw), 0x10);
	fill_pattern(lm_pw, sizeof(lm_pw), 0x20);
	fill_pattern(hours, sizeof(hours), 0x40);

	ok = pdb_set_username(sam, username, PDB_SET) &&
	     pdb_set_domain(sam, "WIREDOMAIN", PDB_SET) &&
	     pdb_set_nt_username(sam, "WireFormat", PDB_SET) &&
	     pdb_set_fullname(sam, "Wire Format", PDB_SET) &&
	     pdb_set_homedir(sam, "\\\\server\\home", PDB_SET) &&
	     pdb_set_dir_drive(sam, "H:", PDB_SET) &&
	     pdb_set_logon_script(sam, "logon.cmd", PDB_SET) &&
	     pdb_set_profile_path(sam, "\\\\server\\profile", PDB_SET) &&
	     pdb_set_acct_desc(sam, "description", PDB_SET) &&
	     pdb_set_workstations(sam, "ws1,ws2", PDB_SET) &&
	     pdb_set_comment(sam, "comment", PDB_SET) &&
	     pdb_set_user_sid_from_rid(sam, rid, PDB_SET) &&
	     pdb_set_nt_passwd(sam, nt_pw, PDB_SET) &&
	     pdb_set_lanman_passwd(sam, lm_pw, PDB_SET) &&
	     pdb_set_acct_ctrl(sam, ACB_NORMAL|ACB_PWNOEXP, PDB_SET) &&
	     pdb_set_logon_time(sam, 0x01020304, PDB_SET) &&
	     pdb_set_kickoff_time(sam, 0x11121314, PDB_SET) &&
	     pdb_set_pass_last_set_time(sam, 0x21222324, PDB_SET) &&
	     pdb_set_hours_len(sam, 21, PDB_SET) &&
	     pdb_set_hours(sam, hours, sizeof(hours), PDB_SET) &&
	     pdb_set_bad_password_count(sam, 0x0102, PDB_SET) &&
	     pdb_set_logon_count(sam, 0x0304, PDB_SET);
	if (!ok) {
		fprintf(stderr, "pdb_set_* failed\n");
		goto fail;
	}

	status = pdb_add_sam_account(sam);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "pdb_add_sam_account failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	/*
	 * This shares the tdb with pdb_tdb.c
	 */
	db = db_open(frame, db_path, 0,
		     TDB_DEFAULT, O_RDONLY, 0600,
		     DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	if (db == NULL) {
		fprintf(stderr, "db_open(%s) failed\n", db_path);
		goto fail;
	}

	ok = TDB_WIRE_FORMAT_CHECK(db,
				   "INFO/version",
				   &version,
				   tdbsam_version_rec);
	if (!ok) {
		goto fail;
	}
	if (version.version != 4) {
		fprintf(stderr, "version %d expected 4\n", version.version);
		goto fail;
	}

	ok = TDB_WIRE_FORMAT_CHECK(db,
				   "INFO/minor_version",
				   &version,
				   tdbsam_version_rec);
	if (!ok) {
		goto fail;
	}

	ok = TDB_WIRE_FORMAT_CHECK(db,
				   "NEXT_RID",
				   &next_rid,
				   tdbsam_next_rid_rec);
	if (!ok) {
		goto fail;
	}
	/* the next free rid */
	if (next_rid.rid != rid + 1) {
		fprintf(stderr, "next_rid %"PRIu32" expected %"PRIu32"\n",
			next_rid.rid,
			rid + 1);
		goto fail;
	}

	keystr = talloc_asprintf(frame, "RID_%.8x", rid);
	if (keystr == NULL) {
		fprintf(stderr, "talloc_asprintf failed\n");
		goto fail;
	}
	ok = TDB_WIRE_FORMAT_CHECK(db, keystr, &rid_rec, tdbsam_rid_rec);
	if (!ok) {
		goto fail;
	}
	if (strcmp(rid_rec.name, username) != 0) {
		fprintf(stderr, "%s: %s expected %s\n",
			keystr,
			rid_rec.name,
			username);
		goto fail;
	}

	keystr = talloc_asprintf(frame, "USER_%s", username);
	if (keystr == NULL) {
		fprintf(stderr, "talloc_asprintf failed\n");
		goto fail;
	}
	ok = TDB_WIRE_FORMAT_CHECK(db, keystr, &user, tdbsam_user_v3);
	if (!ok) {
		goto fail;
	}

	ok = (user.logon_time == 0x01020304) &&
	     (user.kickoff_time == 0x11121314) &&
	     (user.pass_last_set_time == 0x21222324) &&
	     (user.user_rid == rid) &&
	     (user.acct_ctrl == (ACB_NORMAL|ACB_PWNOEXP)) &&
	     (user.hours_len == 21) &&
	     (user.bad_password_count == 0x0102) &&
	     (user.logon_count == 0x0304) &&
	     tdbsam_blob_check("username", &user.username, username) &&
	     tdbsam_blob_check("domain", &user.domain, "WIREDOMAIN") &&
	     tdbsam_blob_check("fullname", &user.fullname, "Wire Format") &&
	     tdbsam_blob_check("workstations",
			       &user.workstations,
			       "ws1,ws2") &&
	     (user.nt_pw.length == sizeof(nt_pw)) &&
	     (memcmp(user.nt_pw.data, nt_pw, sizeof(nt_pw)) == 0) &&
	     (user.lm_pw.length == sizeof(lm_pw)) &&
	     (memcmp(user.lm_pw.data, lm_pw, sizeof(lm_pw)) == 0) &&
	     (user.hours.length == sizeof(hours)) &&
	     (memcmp(user.hours.data, hours, sizeof(hours)) == 0);
	if (!ok) {
		fprintf(stderr, "%s: content mismatch\n", keystr);
		NDR_PRINT_DEBUG(tdbsam_user_v3, &user);
		goto fail;
	}

	ret = true;
fail:
	TALLOC_FREE(frame);
	if (db_path != NULL) {
		unlink(db_path);
	}
	return ret;
}

/*
 * group_mapping.tdb, see source3/librpc/idl/group_mapping.idl
 */
bool run_group_mapping_wire_format(int dummy)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *group_sid_str = "S-1-5-21-1-2-3-4567";
	const char *alias_sid_str = "S-1-5-21-1-2-3-4568";
	const char *member_sid_str = "S-1-5-21-1-2-3-4569";
	struct dom_sid group_sid;
	struct dom_sid alias_sid;
	struct dom_sid member_sid;
	GROUP_MAP group_map = {
		.gid = 0x01020304,
		.sid_name_use = SID_NAME_DOM_GRP,
		.nt_name = discard_const_p(char, "wire format group"),
		.comment = discard_const_p(char, "group comment"),
	};
	GROUP_MAP alias_map = {
		.gid = 0x01020305,
		.sid_name_use = SID_NAME_ALIAS,
		.nt_name = discard_const_p(char, "wire format alias"),
		.comment = discard_const_p(char, ""),
	};
	struct db_context *db = NULL;
	char *db_path = NULL;
	char *keystr = NULL;
	struct group_mapping_rec rec = { .gid = 0, };
	struct group_mapping_memberof_rec memberof = { .aliases = NULL, };
	bool group_added = false;
	bool alias_added = false;
	bool member_added = false;
	NTSTATUS status;
	bool ret = false;
	bool ok;

	ok = string_to_sid(&group_sid, group_sid_str) &&
	     string_to_sid(&alias_sid, alias_sid_str) &&
	     string_to_sid(&member_sid, member_sid_str);
	if (!ok) {
		fprintf(stderr, "string_to_sid failed\n");
		goto fail;
	}
	group_map.sid = group_sid;
	alias_map.sid = alias_sid;

	status = pdb_add_group_mapping_entry(&group_map);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "pdb_add_group_mapping_entry failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	group_added = true;

	status = pdb_add_group_mapping_entry(&alias_map);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "pdb_add_group_mapping_entry failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	alias_added = true;

	status = pdb_add_aliasmem(&alias_sid, &member_sid);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "pdb_add_aliasmem failed: %s\n",
			nt_errstr(status));
		goto fail;
	}
	member_added = true;

	/*
	 * This shares the tdb with mapping_tdb.c
	 */
	db_path = state_path(frame, "group_mapping.tdb");
	if (db_path == NULL) {
		fprintf(stderr, "state_path failed\n");
		goto fail;
	}
	db = db_open(frame, db_path, 0,
		     TDB_DEFAULT, O_RDONLY, 0600,
		     DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	if (db == NULL) {
		fprintf(stderr, "db_open(%s) failed\n", db_path);
		goto fail;
	}

	keystr = talloc_asprintf(frame, "%s%s", GROUP_PREFIX, group_sid_str);
	if (keystr == NULL) {
		fprintf(stderr, "talloc_asprintf failed\n");
		goto fail;
	}
	ok = TDB_WIRE_FORMAT_CHECK(db, keystr, &rec, group_mapping_rec);
	if (!ok) {
		goto fail;
	}
	if ((rec.gid != group_map.gid) ||
	    (rec.sid_name_use != group_map.sid_name_use) ||
	    (strcmp(rec.nt_name, group_map.nt_name) != 0) ||
	    (strcmp(rec.comment, group_map.comment) != 0))
	{
		fprintf(stderr, "%s: content mismatch\n", keystr);
		goto fail;
	}

	keystr = talloc_asprintf(frame, "%s%s", GROUP_PREFIX, alias_sid_str);
	if (keystr == NULL) {
		fprintf(stderr, "talloc_asprintf failed\n");
		goto fail;
	}
	ok = TDB_WIRE_FORMAT_CHECK(db, keystr, &rec, group_mapping_rec);
	if (!ok) {
		goto fail;
	}
	if ((rec.gid != alias_map.gid) ||
	    (rec.sid_name_use != alias_map.sid_name_use) ||
	    (strcmp(rec.nt_name, alias_map.nt_name) != 0) ||
	    (strcmp(rec.comment, alias_map.comment) != 0))
	{
		fprintf(stderr, "%s: content mismatch\n", keystr);
		goto fail;
	}

	keystr = talloc_asprintf(frame,
				 "%s%s",
				 MEMBEROF_PREFIX,
				 member_sid_str);
	if (keystr == NULL) {
		fprintf(stderr, "talloc_asprintf failed\n");
		goto fail;
	}
	ok = TDB_WIRE_FORMAT_CHECK(db,
				   keystr,
				   &memberof,
				   group_mapping_memberof_rec);
	if (!ok) {
		goto fail;
	}
	if (strcmp(memberof.aliases, alias_sid_str) != 0) {
		fprintf(stderr, "%s: %s expected %s\n",
			keystr,
			memberof.aliases,
			alias_sid_str);
		goto fail;
	}

	ret = true;
fail:
	if (member_added) {
		pdb_del_aliasmem(&alias_sid, &member_sid);
	}
	if (alias_added) {
		pdb_delete_group_mapping_entry(alias_sid);
	}
	if (group_added) {
		pdb_delete_group_mapping_entry(group_sid);
	}
	TALLOC_FREE(frame);
	return ret;
}

/*
 * account_policy.tdb, see source3/librpc/idl/account_policy.idl
 */
bool run_account_policy_wire_format(int dummy)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *sid_str = "S-1-5-21-1-2-3-4570";
	struct dom_sid sid;
	enum pdb_policy_type type = PDB_POLICY_MIN_PASSWORD_LEN;
	const char *policy_name = NULL;
	uint32_t old_value = 0;
	struct db_context *db = NULL;
	char *keystr = NULL;
	struct account_policy_value_rec value = { .value = 0, };
	struct account_policy_privileges_rec privs = { .privileges = 0, };
	bool policy_changed = false;
	bool privs_granted = false;
	bool ret = false;
	bool ok;

	ok = string_to_sid(&sid, sid_str);
	if (!ok) {
		fprintf(stderr, "string_to_sid failed\n");
		goto fail;
	}

	policy_name = decode_account_policy_name(type);
	if (policy_name == NULL) {
		fprintf(stderr, "decode_account_policy_name failed\n");
		goto fail;
	}

	ok = account_policy_get(type, &old_value);
	if (!ok) {
		fprintf(stderr, "account_policy_get failed\n");
		goto fail;
	}

	ok = account_policy_set(type, 0x01020304);
	if (!ok) {
		fprintf(stderr, "account_policy_set failed\n");
		goto fail;
	}
	policy_changed = true;

	ok = grant_privilege_by_name(&sid, "SeBackupPrivilege") &&
	     grant_privilege_by_name(&sid, "SeRestorePrivilege");
	if (!ok) {
		fprintf(stderr, "grant_privilege_by_name failed\n");
		goto fail;
	}
	privs_granted = true;

	/*
	 * This shares the tdb with account_pol.c
	 */
	db = get_account_pol_db();
	if (db == NULL) {
		fprintf(stderr, "get_account_pol_db failed\n");
		goto fail;
	}

	ok = TDB_WIRE_FORMAT_CHECK(db,
				   "INFO/version",
				   &value,
				   account_policy_value_rec);
	if (!ok) {
		goto fail;
	}
	if (value.value != 3) {
		fprintf(stderr, "version %"PRIu32" expected 3\n",
			value.value);
		goto fail;
	}

	ok = TDB_WIRE_FORMAT_CHECK(db,
				   policy_name,
				   &value,
				   account_policy_value_rec);
	if (!ok) {
		goto fail;
	}
	if (value.value != 0x01020304) {
		fprintf(stderr, "%s: 0x%"PRIx32" expected 0x01020304\n",
			policy_name,
			value.value);
		goto fail;
	}

	keystr = talloc_asprintf(frame, "PRIV_%s", sid_str);
	if (keystr == NULL) {
		fprintf(stderr, "talloc_asprintf failed\n");
		goto fail;
	}
	ok = TDB_WIRE_FORMAT_CHECK(db,
				   keystr,
				   &privs,
				   account_policy_privileges_rec);
	if (!ok) {
		goto fail;
	}
	if (privs.privileges != (SEC_PRIV_BACKUP_BIT|SEC_PRIV_RESTORE_BIT)) {
		fprintf(stderr, "%s: 0x%"PRIx64" expected 0x%"PRIx64"\n",
			keystr,
			privs.privileges,
			(uint64_t)(SEC_PRIV_BACKUP_BIT|SEC_PRIV_RESTORE_BIT));
		goto fail;
	}

	ret = true;
fail:
	if (privs_granted) {
		revoke_all_privileges(&sid);
	}
	if (policy_changed) {
		account_policy_set(type, old_value);
	}
	TALLOC_FREE(frame);
	return ret;
}

static bool idmap_wire_format_check_uint32(struct db_context *db,
					   const char *keystr,
					   uint32_t expected)
{
	struct idmap_tdb_uint32_rec rec = { .value = 0, };
	bool ok;

	ok = TDB_WIRE_FORMAT_CHECK(db, keystr, &rec, idmap_tdb_uint32_rec);
	if (!ok) {
		return false;
	}
	if (rec.value != expected) {
		fprintf(stderr, "%s: %"PRIu32" expected %"PRIu32"\n",
			keystr,
			rec.value,
			expected);
		return false;
	}
	return true;
}

static bool idmap_wire_format_check_string(struct db_context *db,
					   const char *keystr,
					   const char *expected)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct idmap_tdb_string_rec rec = { .str = NULL, };
	bool ok;

	ok = TDB_WIRE_FORMAT_CHECK(db, keystr, &rec, idmap_tdb_string_rec);
	if (!ok) {
		TALLOC_FREE(frame);
		return false;
	}
	if (strcmp(rec.str, expected) != 0) {
		fprintf(stderr, "%s: %s expected %s\n",
			keystr,
			rec.str,
			expected);
		TALLOC_FREE(frame);
		return false;
	}
	TALLOC_FREE(frame);
	return true;
}

/*
 * idmap2.tdb and autorid.tdb, see source3/librpc/idl/idmap_tdb.idl
 */
bool run_idmap_wire_format(int dummy)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *domsid = "S-1-5-21-1-2-3";
	const char *user_sid_str = "S-1-5-21-1-2-3-1000";
	const char *group_sid_str = "S-1-5-21-1-2-3-1001";
	struct autorid_global_config cfg = {
		.minvalue = 1000000,
		.rangesize = 100000,
		.maxranges = 10,
	};
	struct autorid_range_config range0 = { .domain_range_index = 0, };
	struct autorid_range_config range1 = { .domain_range_index = 1, };
	struct idmap_domain *dom = NULL;
	struct idmap_tdb_common_context *ctx = NULL;
	struct id_map map = { .status = ID_UNKNOWN, };
	struct dom_sid user_sid;
	struct dom_sid group_sid;
	struct db_context *db = NULL;
	char *db_path = NULL;
	char *keystr = NULL;
	char *expected = NULL;
	struct idmap_autorid_config_rec config = { .config = NULL, };
	NTSTATUS status;
	bool ret = false;
	bool ok;

	ok = string_to_sid(&user_sid, user_sid_str) &&
	     string_to_sid(&group_sid, group_sid_str);
	if (!ok) {
		fprintf(stderr, "string_to_sid failed\n");
		goto fail;
	}

	db_path = lock_path(frame, "wire_format_autorid.tdb");
	if (db_path == NULL) {
		fprintf(stderr, "lock_path failed\n");
		goto fail;
	}
	unlink(db_path);

	status = idmap_autorid_db_init(db_path, frame, &db);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "idmap_autorid_db_init failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = idmap_autorid_saveconfig(db, &cfg);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "idmap_autorid_saveconfig failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	fstrcpy(range0.domsid, domsid);
	status = idmap_autorid_acquire_range(db, &range0);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "idmap_autorid_acquire_range failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	fstrcpy(range1.domsid, domsid);
	status = idmap_autorid_acquire_range(db, &range1);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "idmap_autorid_acquire_range failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	/*
	 * The mappings are stored with idmap_tdb_common_set_mapping()
	 * by idmap_autorid and idmap_tdb2 uses the same format.
	 */
	dom = talloc_zero(frame, struct idmap_domain);
	if (dom == NULL) {
		fprintf(stderr, "talloc_zero failed\n");
		goto fail;
	}
	dom->name = "*";
	dom->low_id = 1000;
	dom->high_id = 2000;

	ctx = talloc_zero(dom, struct idmap_tdb_common_context);
	if (ctx == NULL) {
		fprintf(stderr, "talloc_zero failed\n");
		goto fail;
	}
	ctx->db = db;
	dom->private_data = ctx;

	map = (struct id_map) {
		.sid = &user_sid,
		.xid = { .id = 1000, .type = ID_TYPE_UID, },
	};
	status = idmap_tdb_common_set_mapping(dom, &map);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "idmap_tdb_common_set_mapping failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	map = (struct id_map) {
		.sid = &group_sid,
		.xid = { .id = 1001, .type = ID_TYPE_GID, },
	};
	status = idmap_tdb_common_set_mapping(dom, &map);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "idmap_tdb_common_set_mapping failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	ok = idmap_wire_format_check_uint32(db, HWM, 2) &&
	     idmap_wire_format_check_uint32(db, ALLOC_HWM_UID, 0) &&
	     idmap_wire_format_check_uint32(db, ALLOC_HWM_GID, 0) &&
	     idmap_wire_format_check_uint32(db, domsid, range0.rangenum) &&
	     idmap_wire_format_check_string(db, "0", domsid) &&
	     idmap_wire_format_check_string(db, user_sid_str, "UID 1000") &&
	     idmap_wire_format_check_string(db, "UID 1000", user_sid_str) &&
	     idmap_wire_format_check_string(db, group_sid_str, "GID 1001") &&
	     idmap_wire_format_check_string(db, "GID 1001", group_sid_str);
	if (!ok) {
		goto fail;
	}

	keystr = talloc_asprintf(frame, "%s#1", domsid);
	if (keystr == NULL) {
		fprintf(stderr, "talloc_asprintf failed\n");
		goto fail;
	}
	ok = idmap_wire_format_check_uint32(db, keystr, range1.rangenum) &&
	     idmap_wire_format_check_string(db, "1", keystr);
	if (!ok) {
		goto fail;
	}

	ok = TDB_WIRE_FORMAT_CHECK(db,
				   CONFIGKEY,
				   &config,
				   idmap_autorid_config_rec);
	if (!ok) {
		goto fail;
	}
	expected = talloc_asprintf(frame,
				   "minvalue:%"PRIu32" rangesize:%"PRIu32" "
				   "maxranges:%"PRIu32,
				   cfg.minvalue,
				   cfg.rangesize,
				   cfg.maxranges);
	if (expected == NULL) {
		fprintf(stderr, "talloc_asprintf failed\n");
		goto fail;
	}
	if (strcmp(config.config, expected) != 0) {
		fprintf(stderr, "%s: %s expected %s\n",
			CONFIGKEY,
			config.config,
			expected);
		goto fail;
	}

	ret = true;
fail:
	TALLOC_FREE(frame);
	if (db_path != NULL) {
		unlink(db_path);
	}
	return ret;
}

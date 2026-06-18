/*
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
 *  Copyright (C) Michael Adam                      2007-2011
 *  Copyright (C) Gregor Beck                       2011
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Implementation of internal registry database functions. */

#include "includes.h"
#include "system/filesys.h"
#include "registry.h"
#include "reg_util_internal.h"
#include "reg_parse_internal.h"
#include "reg_backend_db.h"
#include "reg_objects.h"
#include "nt_printing.h"
#include "util_tdb.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../libcli/security/secdesc.h"
#include "librpc/gen_ndr/ndr_registry.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

#define REG_TDB_FLAGS   TDB_SEQNUM
#define REG_DBWRAP_FLAGS DBWRAP_FLAG_NONE
#define REGDB_VERSION_KEYNAME "INFO/version"

static struct db_context *regdb = NULL;
static int regdb_refcount;

static bool regdb_key_exists(struct db_context *db, const char *key);
static WERROR regdb_fetch_keys_internal(struct db_context *db, const char *key,
					struct regsubkey_ctr *ctr);
static bool regdb_store_keys_internal(struct db_context *db, const char *key,
				      struct regsubkey_ctr *ctr);
static int regdb_fetch_values_internal(struct db_context *db, const char* key,
				       struct regval_ctr *values);
static NTSTATUS regdb_store_values_internal(struct db_context *db, const char *key,
					    struct regval_ctr *values);
static WERROR regdb_store_subkey_list(struct db_context *db, const char *parent,
				      const char *key);

static WERROR regdb_create_basekey(struct db_context *db, const char *key);
static WERROR regdb_create_subkey_internal(struct db_context *db,
					   const char *key,
					   const char *subkey);

static int regdb_unpack_values(struct regval_ctr *values,
			       uint8_t *buf,
			       size_t buflen);
WERROR regdb_pack_values_v4(struct regval_ctr *values,
			    uint8_t **buf,
			    size_t *buflen,
			    TALLOC_CTX *mem_ctx);
WERROR regdb_unpack_values_v4(struct regval_ctr *values,
			      uint8_t *buf,
			      size_t buflen);
WERROR regdb_pack_keys_v4(struct regsubkey_ctr *ctr,
			  uint8_t **buf,
			  size_t *buflen,
			  TALLOC_CTX *mem_ctx);
WERROR regdb_unpack_keys_v4(struct regsubkey_ctr *ctr,
			    uint8_t *buf,
			    size_t buflen);

struct regdb_trans_ctx {
	NTSTATUS (*action)(struct db_context *, void *);
	void *private_data;
};

static NTSTATUS regdb_trans_do_action(struct db_context *db, void *private_data)
{
	NTSTATUS status;
	int32_t version_id;
	struct regdb_trans_ctx *ctx = (struct regdb_trans_ctx *)private_data;

	status = dbwrap_fetch_int32_bystring(db, REGDB_VERSION_KEYNAME,
					     &version_id);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("ERROR: could not fetch registry db version: %s. "
			  "Denying access.\n", nt_errstr(status)));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (version_id != REGDB_CODE_VERSION) {
		DEBUG(0, ("ERROR: changed registry version %d found while "
			  "trying to write to the registry. Version %d "
			  "expected.  Denying access.\n",
			  version_id, REGDB_CODE_VERSION));
		return NT_STATUS_ACCESS_DENIED;
	}

	status = ctx->action(db,  ctx->private_data);
	return status;
}

static WERROR regdb_trans_do(struct db_context *db,
			     NTSTATUS (*action)(struct db_context *, void *),
			     void *private_data)
{
	NTSTATUS status;
	struct regdb_trans_ctx ctx;


	ctx.action = action;
	ctx.private_data = private_data;

	status = dbwrap_trans_do(db, regdb_trans_do_action, &ctx);

	return ntstatus_to_werror(status);
}

/* List the deepest path into the registry.  All part components will be created.*/

/* If you want to have a part of the path controlled by the tdb and part by
   a virtual registry db (e.g. printing), then you have to list the deepest
   path. For example,"HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Print"
   allows the reg_db backend to handle everything up to
   "HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion" and then we'll hook
   the reg_printing backend onto the last component of the path (see
   KEY_PRINTING_2K in include/rpc_reg.h)   --jerry */

static const char *builtin_registry_paths[] = {
	KEY_PRINTING_2K,
	KEY_PCC,
	KEY_PRINTING_PORTS,
	KEY_PRINTING,
	KEY_PRINTING "\\Forms",
	KEY_PRINTING "\\Printers",
	KEY_PRINTING "\\Environments\\Windows NT x86\\Print Processors\\winprint",
	KEY_PRINTING "\\Environments\\Windows x64\\Print Processors\\winprint",
	KEY_SHARES,
	KEY_EVENTLOG,
	KEY_SMBCONF,
	KEY_PERFLIB,
	KEY_PERFLIB_009,
	KEY_GROUP_POLICY,
	KEY_SAMBA_GROUP_POLICY,
	KEY_GP_MACHINE_POLICY,
	KEY_GP_MACHINE_WIN_POLICY,
	KEY_HKCU,
	KEY_GP_USER_POLICY,
	KEY_GP_USER_WIN_POLICY,
	"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions",
	"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",
	KEY_PROD_OPTIONS,
	"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration",
	KEY_TCPIP_PARAMS,
	KEY_NETLOGON_PARAMS,
	KEY_HKU,
	KEY_HKCR,
	KEY_HKPD,
	KEY_HKPT,
	 NULL };

struct builtin_regkey_value {
	const char *path;
	const char *valuename;
	uint32_t type;
	union {
		const char *string;
		uint32_t dw_value;
	} data;
};

static struct builtin_regkey_value builtin_registry_values[] = {
	{ KEY_PRINTING_PORTS,
		SAMBA_PRINTER_PORT_NAME, REG_SZ, { "" } },
	{ KEY_PRINTING_2K,
		"DefaultSpoolDirectory", REG_SZ, { "C:\\Windows\\System32\\Spool\\Printers" } },
	{ KEY_EVENTLOG,
		"DisplayName", REG_SZ, { "Event Log" } },
	{ KEY_EVENTLOG,
		"ErrorControl", REG_DWORD, { (char*)0x00000001 } },
	{ NULL, NULL, 0, { NULL } }
};

static WERROR create_key_recursive(struct db_context *db,
				   char *path,
				   const char *subkey)
{
	WERROR werr;
	char *p;

	if (subkey == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	if (path == NULL) {
		return regdb_create_basekey(db, subkey);
	}

	p = strrchr_m(path, '\\');

	if (p == NULL) {
		werr = create_key_recursive(db, NULL, path);
	} else {
		*p = '\0';
		werr = create_key_recursive(db, path, p+1);
		*p = '\\';
	}

	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = regdb_create_subkey_internal(db, path, subkey);

done:
	return werr;
}

/**
 * Initialize a key in the registry:
 * create each component key of the specified path.
 */
static WERROR init_registry_key_internal(struct db_context *db,
					 const char *add_path)
{
	char *subkey, *key;
	WERROR werr;
	TALLOC_CTX *frame = talloc_stackframe();

	if (add_path == NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto done;
	}

	key = talloc_strdup(frame, add_path);

	subkey = strrchr_m(key, '\\');
	if (subkey == NULL) {
		subkey = key;
		key = NULL;
	} else {
		*subkey = '\0';
		subkey++;
	}

	werr = create_key_recursive(db, key, subkey);

done:
	talloc_free(frame);
	return werr;
}

struct init_registry_key_context {
	const char *add_path;
};

static NTSTATUS init_registry_key_action(struct db_context *db,
					 void *private_data)
{
	struct init_registry_key_context *init_ctx =
		(struct init_registry_key_context *)private_data;

	return werror_to_ntstatus(init_registry_key_internal(
					db, init_ctx->add_path));
}

/**
 * Initialize a key in the registry:
 * create each component key of the specified path,
 * wrapped in one db transaction.
 */
WERROR init_registry_key(const char *add_path)
{
	struct init_registry_key_context init_ctx;

	if (regdb_key_exists(regdb, add_path)) {
		return WERR_OK;
	}

	init_ctx.add_path = add_path;

	return regdb_trans_do(regdb,
			      init_registry_key_action,
			      &init_ctx);
}

/***********************************************************************
 Open the registry data in the tdb
 ***********************************************************************/

static void regdb_ctr_add_value(struct regval_ctr *ctr,
				struct builtin_regkey_value *value)
{
	switch(value->type) {
	case REG_DWORD:
		regval_ctr_addvalue(ctr, value->valuename, REG_DWORD,
				    (uint8_t *)&value->data.dw_value,
				    sizeof(uint32_t));
		break;

	case REG_SZ:
		regval_ctr_addvalue_sz(ctr, value->valuename,
				       value->data.string);
		break;

	default:
		DEBUG(0, ("regdb_ctr_add_value: invalid value type in "
			  "registry values [%d]\n", value->type));
	}
}

static NTSTATUS init_registry_data_action(struct db_context *db,
					  void *private_data)
{
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	struct regval_ctr *values;
	int i, fetch_ret;

	/* loop over all of the predefined paths and add each component */

	for (i=0; builtin_registry_paths[i] != NULL; i++) {
		if (regdb_key_exists(db, builtin_registry_paths[i])) {
			continue;
		}
		status = werror_to_ntstatus(init_registry_key_internal(db,
						  builtin_registry_paths[i]));
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}

	/* loop over all of the predefined values and add each component */

	for (i=0; builtin_registry_values[i].path != NULL; i++) {
		WERROR werr;

		werr = regval_ctr_init(frame, &values);
		if (!W_ERROR_IS_OK(werr)) {
			status = werror_to_ntstatus(werr);
			goto done;
		}

		fetch_ret = regdb_fetch_values_internal(db,
					    builtin_registry_values[i].path,
					    values);
		if (fetch_ret == -1) {
			DEBUG(1, ("init_registry_data_action: "
				  "regdb_fetch_values_internal failed for [%s]\n",
				  builtin_registry_values[i].path));
			status = NT_STATUS_INTERNAL_ERROR;
			goto done;
		}

		/* preserve existing values across restarts. Only add new ones */

		if (!regval_ctr_value_exists(values,
					builtin_registry_values[i].valuename))
		{
			regdb_ctr_add_value(values,
					    &builtin_registry_values[i]);
			status = regdb_store_values_internal(db,
					builtin_registry_values[i].path,
					values);
			if (!NT_STATUS_IS_OK(status)) {
				goto done;
			}
		}
		TALLOC_FREE(values);
	}

	status = NT_STATUS_OK;

done:

	TALLOC_FREE(frame);
	return status;
}

WERROR init_registry_data(void)
{
	WERROR werr;
	TALLOC_CTX *frame = talloc_stackframe();
	struct regval_ctr *values;
	int i, fetch_ret;

	/*
	 * First, check for the existence of the needed keys and values.
	 * If all do already exist, we can save the writes.
	 */
	for (i=0; builtin_registry_paths[i] != NULL; i++) {
		if (!regdb_key_exists(regdb, builtin_registry_paths[i])) {
			goto do_init;
		}
	}

	for (i=0; builtin_registry_values[i].path != NULL; i++) {
		werr = regval_ctr_init(frame, &values);
		W_ERROR_NOT_OK_GOTO_DONE(werr);

		fetch_ret = regdb_fetch_values_internal(regdb,
					    builtin_registry_values[i].path,
					    values);
		if (fetch_ret == -1) {
			DEBUG(1, ("init_registry_data: "
				  "regdb_fetch_values_internal failed for [%s]\n",
				  builtin_registry_values[i].path));
			TALLOC_FREE(values);
			goto do_init;
		}
		if (!regval_ctr_value_exists(values,
					builtin_registry_values[i].valuename))
		{
			TALLOC_FREE(values);
			goto do_init;
		}

		TALLOC_FREE(values);
	}

	werr = WERR_OK;
	goto done;

do_init:

	/*
	 * There are potentially quite a few store operations which are all
	 * individually wrapped in tdb transactions. Wrapping them in a single
	 * transaction gives just a single transaction_commit() to actually do
	 * its fsync()s. See tdb/common/transaction.c for info about nested
	 * transaction behaviour.
	 */

	werr = regdb_trans_do(regdb,
			      init_registry_data_action,
			      NULL);

done:
	TALLOC_FREE(frame);
	return werr;
}

static int regdb_normalize_keynames_fn(struct db_record *rec,
				       void *private_data)
{
	TALLOC_CTX *mem_ctx = talloc_tos();
	const char *keyname;
	NTSTATUS status;
	TDB_DATA key;
	TDB_DATA value;
	struct db_context *db = (struct db_context *)private_data;

	key = dbwrap_record_get_key(rec);
	if (key.dptr == NULL || key.dsize == 0) {
		return 0;
	}

	value = dbwrap_record_get_value(rec);

	if (db == NULL) {
		DEBUG(0, ("regdb_normalize_keynames_fn: ERROR: "
			  "NULL db context handed in via private_data\n"));
		return 1;
	}

	if (strncmp((const char *)key.dptr, REGDB_VERSION_KEYNAME,
	    strlen(REGDB_VERSION_KEYNAME)) == 0)
	{
		return 0;
	}

	keyname = strchr((const char *)key.dptr, '/');
	if (keyname) {
		keyname = talloc_string_sub(mem_ctx,
					    (const char *)key.dptr,
					    "/",
					    "\\");

		DEBUG(2, ("regdb_normalize_keynames_fn: Convert %s to %s\n",
			  (const char *)key.dptr,
			  keyname));

		/* Delete the original record and store the normalized key */
		status = dbwrap_record_delete(rec);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("regdb_normalize_keynames_fn: "
				 "tdb_delete for [%s] failed!\n",
				 (const char *)key.dptr));
			return 1;
		}

		status = dbwrap_store_bystring(db, keyname, value, TDB_REPLACE);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("regdb_normalize_keynames_fn: "
				 "failed to store new record for [%s]!\n",
				 keyname));
			return 1;
		}
	}

	return 0;
}

static WERROR regdb_store_regdb_version(struct db_context *db, uint32_t version)
{
	NTSTATUS status;

	if (db == NULL) {
		return WERR_CAN_NOT_COMPLETE;
	}

	status = dbwrap_trans_store_int32_bystring(db, REGDB_VERSION_KEYNAME,
						   version);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("regdb_store_regdb_version: error storing %s = %d: %s\n",
			  REGDB_VERSION_KEYNAME, version, nt_errstr(status)));
		return ntstatus_to_werror(status);
	} else {
		DEBUG(10, ("regdb_store_regdb_version: stored %s = %d\n",
			  REGDB_VERSION_KEYNAME, version));
		return WERR_OK;
	}
}

static WERROR regdb_upgrade_v1_to_v2(struct db_context *db)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	WERROR werr;

	mem_ctx = talloc_stackframe();

	status = dbwrap_traverse(db, regdb_normalize_keynames_fn, db, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		werr = WERR_REGISTRY_IO_FAILED;
		goto done;
	}

	werr = regdb_store_regdb_version(db, REGDB_VERSION_V2);

done:
	talloc_free(mem_ctx);
	return werr;
}

static bool tdb_data_read_uint32(TDB_DATA *buf, uint32_t *result)
{
	const size_t len = sizeof(uint32_t);
	if (buf->dsize >= len) {
		*result = IVAL(buf->dptr, 0);
		buf->dptr += len;
		buf->dsize -= len;
		return true;
	}
	return false;
}

static bool tdb_data_read_cstr(TDB_DATA *buf, char **result)
{
	const size_t len = strnlen((char*)buf->dptr, buf->dsize) + 1;

	if (buf->dsize >= len) {
		*result = (char*)buf->dptr;
		buf->dptr += len;
		buf->dsize -= len;
		return true;
	}
	return false;
}

static bool tdb_data_is_cstr(TDB_DATA d)
{
	if (tdb_data_is_empty(d) || (d.dptr[d.dsize-1] != '\0')) {
		return false;
	}
	return strlen((char *)d.dptr) == (d.dsize-1);
}

static bool upgrade_v2_to_v3_check_subkeylist(struct db_context *db,
					      const char *key,
					      const char *subkey)
{
	static uint32_t zero = 0;
	static TDB_DATA empty_subkey_list = {
		.dptr = (unsigned char*)&zero,
		.dsize = sizeof(uint32_t),
	};
	bool success = false;
	char *path = talloc_asprintf(talloc_tos(), "%s\\%s", key, subkey);

	if (!strupper_m(path)) {
		goto done;
	}

	if (!dbwrap_exists(db, string_term_tdb_data(path))) {
		NTSTATUS status;

		DEBUG(10, ("regdb_upgrade_v2_to_v3: writing subkey list [%s]\n",
			   path));

		status = dbwrap_store_bystring(db, path, empty_subkey_list,
					       TDB_INSERT);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("regdb_upgrade_v2_to_v3: writing subkey list "
				  "[%s] failed\n", path));
			goto done;
		}
	}
	success = true;
done:
	talloc_free(path);
	return success;
}

static bool upgrade_v2_to_v3_check_parent(struct db_context *db,
					  const char *key)
{
	const char *sep = strrchr_m(key, '\\');

	if (sep != NULL) {
		char *pkey = talloc_strndup(talloc_tos(), key, sep-key);
		if (!dbwrap_exists(db, string_term_tdb_data(pkey))) {
			DEBUG(0, ("regdb_upgrade_v2_to_v3: missing subkey list "
				  "[%s]\nrun \"net registry check\"\n", pkey));
		}
		talloc_free(pkey);
	}
	return true;
}


#define IS_EQUAL(d,s) (((d).dsize == strlen(s)+1) &&	\
		       (strcmp((char*)(d).dptr, (s)) == 0))
#define STARTS_WITH(d,s) (((d).dsize > strlen(s)) &&			\
			  (strncmp((char*)(d).dptr, (s), strlen(s)) == 0))
#define SSTR(d) (int)(d).dsize , (char*)(d).dptr


static int regdb_upgrade_v2_to_v3_fn(struct db_record *rec, void *private_data)
{
	struct db_context *db = (struct db_context *)private_data;
	TDB_DATA key = dbwrap_record_get_key(rec);
	TDB_DATA val = dbwrap_record_get_value(rec);

	if (tdb_data_is_empty(key)) {
		return 0;
	}

	if (db == NULL) {
		DEBUG(0, ("regdb_upgrade_v2_to_v3_fn: ERROR: "
			  "NULL db context handed in via private_data\n"));
		return 1;
	}

	if (IS_EQUAL(key, REGDB_VERSION_KEYNAME) ||
	    STARTS_WITH(key, REG_VALUE_PREFIX) ||
	    STARTS_WITH(key, REG_SECDESC_PREFIX))
	{
		DEBUG(10, ("regdb_upgrade_v2_to_v3: skipping [%.*s]\n",
			   SSTR(key)));
		return 0;
	}

	if (STARTS_WITH(key, REG_SORTED_SUBKEYS_PREFIX)) {
		NTSTATUS status;
		/* Delete the deprecated sorted subkeys cache. */

		DEBUG(10, ("regdb_upgrade_v2_to_v3: deleting [%.*s]\n",
			   SSTR(key)));

		status = dbwrap_record_delete(rec);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("regdb_upgrade_v2_to_v3: deleting [%.*s] "
				  "failed!\n", SSTR(key)));
			return 1;
		}

		return 0;
	}

	if ( tdb_data_is_cstr(key) &&
	     hive_info((char*)key.dptr) != NULL )
	{
		/*
		 * Found a regular subkey list record.
		 * Walk the list and create the list record for those
		 * subkeys that don't already have one.
		 */
		TDB_DATA pos = val;
		char *subkey, *path = (char*)key.dptr;
		uint32_t num_items, found_items = 0;


		DEBUG(10, ("regdb_upgrade_v2_to_v3: scanning subkeylist of "
			   "[%s]\n", path));

		if (!tdb_data_read_uint32(&pos, &num_items)) {
			/* invalid or empty - skip */
			return 0;
		}

		while (tdb_data_read_cstr(&pos, &subkey)) {
			found_items++;

			if (!upgrade_v2_to_v3_check_subkeylist(db, path, subkey))
			{
				return 1;
			}

			if (!upgrade_v2_to_v3_check_parent(db, path)) {
				return 1;
			}
		}
		if (found_items != num_items) {
			DEBUG(0, ("regdb_upgrade_v2_to_v3: inconsistent subkey "
				  "list [%s]\nrun \"net registry check\"\n",
				  path));
		}
	} else {
		DEBUG(10, ("regdb_upgrade_v2_to_v3: skipping invalid [%.*s]\n"
			   "run \"net registry check\"\n", SSTR(key)));
	}

	return 0;
}

static WERROR regdb_upgrade_v2_to_v3(struct db_context *db)
{
	NTSTATUS status;
	WERROR werr;

	status = dbwrap_traverse(db, regdb_upgrade_v2_to_v3_fn, db, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		werr = WERR_REGISTRY_IO_FAILED;
		goto done;
	}

	werr = regdb_store_regdb_version(db, REGDB_VERSION_V3);

done:
	return werr;
}

/* Conversion limits to prevent resource exhaustion */
#define REGDB_MAX_VALUES_PER_KEY 1000
#define REGDB_MAX_SUBKEYS_PER_KEY 10000
#define REGDB_MAX_VALUE_DATA_SIZE (10 * 1024 * 1024) /* 10MB */
#define REGDB_MAX_SUBKEY_DATA_SIZE (1024 * 1024)     /* 1MB */

struct regdb_upgrade_v3_to_v4_ctx {
	struct db_context *db;
	uint32_t *converted_values;
	uint32_t *converted_subkeys;
	uint32_t *skipped_records;
};

/**
 * Verify converted values by unpacking and comparing counts
 */
static WERROR regdb_verify_converted_values(TALLOC_CTX *mem_ctx,
					    struct regval_ctr *original,
					    const uint8_t *packed_data,
					    size_t packed_len,
					    TDB_DATA key)
{
	struct regval_ctr *verify_values = NULL;
	WERROR werr;
	int original_count, verify_count;

	werr = regval_ctr_init(mem_ctx, &verify_values);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(1, ("regdb_verify_converted_values: "
			  "regval_ctr_init failed, skipping verification\n"));
		return WERR_OK; /* Non-fatal: skip verification */
	}

	werr = regdb_unpack_values_v4(verify_values,
				      discard_const_p(uint8_t, packed_data),
				      packed_len);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_verify_converted_values: "
			  "verification failed for [%.*s]: %s\n",
			  SSTR(key), win_errstr(werr)));
		return werr;
	}

	original_count = regval_ctr_numvals(original);
	verify_count = regval_ctr_numvals(verify_values);

	if (verify_count != original_count) {
		DEBUG(0, ("regdb_verify_converted_values: "
			  "count mismatch for [%.*s]: original %d, converted %d\n",
			  SSTR(key), original_count, verify_count));
		return WERR_INTERNAL_DB_CORRUPTION;
	}

	return WERR_OK;
}

/**
 * Verify converted subkeys by unpacking and comparing counts
 */
static WERROR regdb_verify_converted_subkeys(TALLOC_CTX *mem_ctx,
					     struct regsubkey_ctr *original,
					     const uint8_t *packed_data,
					     size_t packed_len,
					     TDB_DATA key)
{
	struct regsubkey_ctr *verify_subkeys = NULL;
	WERROR werr;
	int original_count, verify_count;

	werr = regsubkey_ctr_init(mem_ctx, &verify_subkeys);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(1, ("regdb_verify_converted_subkeys: "
			  "regsubkey_ctr_init failed, skipping verification\n"));
		return WERR_OK; /* Non-fatal: skip verification */
	}

	werr = regdb_unpack_keys_v4(verify_subkeys,
				    discard_const_p(uint8_t, packed_data),
				    packed_len);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_verify_converted_subkeys: "
			  "verification failed for [%.*s]: %s\n",
			  SSTR(key), win_errstr(werr)));
		return werr;
	}

	original_count = regsubkey_ctr_numkeys(original);
	verify_count = regsubkey_ctr_numkeys(verify_subkeys);

	if (verify_count != original_count) {
		DEBUG(0, ("regdb_verify_converted_subkeys: "
			  "count mismatch for [%.*s]: original %d, converted %d\n",
			  SSTR(key), original_count, verify_count));
		return WERR_INTERNAL_DB_CORRUPTION;
	}

	return WERR_OK;
}

/**
 * Convert registry values from V3 to V4 format
 */
static WERROR regdb_convert_values_v3_to_v4(TALLOC_CTX *mem_ctx,
					    struct db_record *rec,
					    TDB_DATA key,
					    TDB_DATA val)
{
	struct regval_ctr *values = NULL;
	uint8_t *new_buf = NULL;
	size_t new_buflen = 0;
	WERROR werr;
	NTSTATUS status;
	int ret;
	int num_values;

	DEBUG(10, ("regdb_convert_values_v3_to_v4: converting [%.*s]\n",
		   SSTR(key)));

	werr = regval_ctr_init(mem_ctx, &values);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_convert_values_v3_to_v4: "
			  "regval_ctr_init failed\n"));
		return werr;
	}

	/* Unpack using V3 (legacy) format */
	ret = regdb_unpack_values(values, val.dptr, val.dsize);
	if (ret == -1) {
		DEBUG(0, ("regdb_convert_values_v3_to_v4: "
			  "regdb_unpack_values failed for [%.*s], skipping\n",
			  SSTR(key)));
		return WERR_INVALID_DATA;
	}

	num_values = regval_ctr_numvals(values);

	/* Initialize seqnum to 0 for converted values */
	werr = regval_ctr_set_seqnum(values, 0);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_convert_values_v3_to_v4: "
			  "regval_ctr_set_seqnum failed for [%.*s]: %s\n",
			  SSTR(key), win_errstr(werr)));
		return werr;
	}

	/* Validate unpacked data */
	if (num_values == 0 && val.dsize > 4) {
		DEBUG(1, ("regdb_convert_values_v3_to_v4: "
			  "warning: non-empty data unpacked to zero values for [%.*s]\n",
			  SSTR(key)));
	}

	if (num_values > REGDB_MAX_VALUES_PER_KEY) {
		DEBUG(0, ("regdb_convert_values_v3_to_v4: "
			  "suspicious number of values (%d) for [%.*s], skipping\n",
			  num_values, SSTR(key)));
		return WERR_INVALID_DATA;
	}

	/* Pack using V4 format */
	werr = regdb_pack_values_v4(values, &new_buf, &new_buflen, mem_ctx);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_convert_values_v3_to_v4: "
			  "regdb_pack_values_v4 failed for [%.*s]: %s\n",
			  SSTR(key), win_errstr(werr)));
		return werr;
	}

	/* Sanity check the packed size */
	if (new_buflen > REGDB_MAX_VALUE_DATA_SIZE) {
		DEBUG(0, ("regdb_convert_values_v3_to_v4: "
			  "packed size too large (%zu bytes) for [%.*s], skipping\n",
			  new_buflen, SSTR(key)));
		return WERR_INVALID_DATA;
	}

	/* Verify conversion before storing */
	werr = regdb_verify_converted_values(
		mem_ctx, values, new_buf, new_buflen, key);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_convert_values_v3_to_v4: "
			  "verification failed for [%.*s]: %s\n",
			  SSTR(key), win_errstr(werr)));
		return werr;
	}

	/* Store the converted data */
	status = dbwrap_record_store(rec,
				     make_tdb_data(new_buf, new_buflen),
				     TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("regdb_convert_values_v3_to_v4: "
			  "storing converted values [%.*s] failed: %s\n",
			  SSTR(key), nt_errstr(status)));
		return WERR_REGISTRY_IO_FAILED;
	}

	DEBUG(10, ("regdb_convert_values_v3_to_v4: successfully converted [%.*s]\n",
		   SSTR(key)));

	return WERR_OK;
}
/**
 * Convert registry subkeys from V3 to V4 format
 */
static WERROR regdb_convert_subkeys_v3_to_v4(TALLOC_CTX *mem_ctx,
					     struct db_record *rec,
					     TDB_DATA key,
					     TDB_DATA val)
{
	struct regsubkey_ctr *subkeys = NULL;
	uint8_t *new_buf = NULL;
	size_t new_buflen = 0;
	WERROR werr;
	NTSTATUS status;
	int num_subkeys;

	DEBUG(10, ("regdb_convert_subkeys_v3_to_v4: converting [%.*s]\n",
		   SSTR(key)));

	werr = regsubkey_ctr_init(mem_ctx, &subkeys);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_convert_subkeys_v3_to_v4: "
			  "regsubkey_ctr_init failed\n"));
		return werr;
	}

	/* Unpack using legacy format */
	werr = regdb_unpack_keys_v4(subkeys, val.dptr, val.dsize);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_convert_subkeys_v3_to_v4: "
			  "regdb_unpack_keys_v4 failed for [%.*s]: %s, skipping\n",
			  SSTR(key), win_errstr(werr)));
		return werr;
	}

	num_subkeys = regsubkey_ctr_numkeys(subkeys);

	/* Validate unpacked data */
	if (num_subkeys == 0 && val.dsize > 4) {
		DEBUG(1, ("regdb_convert_subkeys_v3_to_v4: "
			  "warning: non-empty data unpacked to zero subkeys for [%.*s]\n",
			  SSTR(key)));
	}

	if (num_subkeys > REGDB_MAX_SUBKEYS_PER_KEY) {
		DEBUG(0, ("regdb_convert_subkeys_v3_to_v4: "
			  "suspicious number of subkeys (%d) for [%.*s], skipping\n",
			  num_subkeys, SSTR(key)));
		return WERR_INVALID_DATA;
	}

	/* Pack using V4 format */
	werr = regdb_pack_keys_v4(subkeys, &new_buf, &new_buflen, mem_ctx);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_convert_subkeys_v3_to_v4: "
			  "regdb_pack_keys_v4 failed for [%.*s]: %s\n",
			  SSTR(key), win_errstr(werr)));
		return werr;
	}

	/* Sanity check the packed size */
	if (new_buflen > REGDB_MAX_SUBKEY_DATA_SIZE) {
		DEBUG(0, ("regdb_convert_subkeys_v3_to_v4: "
			  "packed size too large (%zu bytes) for [%.*s], skipping\n",
			  new_buflen, SSTR(key)));
		return WERR_INVALID_DATA;
	}

	/* Verify conversion before storing */
	werr = regdb_verify_converted_subkeys(
		mem_ctx, subkeys, new_buf, new_buflen, key);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_convert_subkeys_v3_to_v4: "
			  "verification failed for [%.*s]: %s\n",
			  SSTR(key), win_errstr(werr)));
		return werr;
	}

	/* Store the converted data */
	status = dbwrap_record_store(rec,
				     make_tdb_data(new_buf, new_buflen),
				     TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("regdb_convert_subkeys_v3_to_v4: "
			  "storing converted subkeys [%.*s] failed: %s\n",
			  SSTR(key), nt_errstr(status)));
		return WERR_REGISTRY_IO_FAILED;
	}

	DEBUG(10, ("regdb_convert_subkeys_v3_to_v4: successfully converted [%.*s]\n",
		   SSTR(key)));

	return WERR_OK;
}

/**
 * Traverse callback for V3 to V4 upgrade
 */
static int regdb_upgrade_v3_to_v4_fn(struct db_record *rec, void *private_data)
{
	struct regdb_upgrade_v3_to_v4_ctx
		*ctx = (struct regdb_upgrade_v3_to_v4_ctx *)private_data;
	TDB_DATA key = dbwrap_record_get_key(rec);
	TDB_DATA val = dbwrap_record_get_value(rec);
	TALLOC_CTX *tmp_ctx = NULL;
	WERROR werr;
	int result = 0;

	/* Skip empty keys */
	if (tdb_data_is_empty(key)) {
		return 0;
	}

	/* Sanity check: db context should never be NULL */
	if (ctx->db == NULL) {
		DEBUG(0, ("regdb_upgrade_v3_to_v4_fn: "
			  "NULL db context in private_data\n"));
		return 1;
	}

	/* Skip version key and security descriptors */
	if (IS_EQUAL(key, REGDB_VERSION_KEYNAME) ||
	    STARTS_WITH(key, REG_SECDESC_PREFIX))
	{
		DEBUG(10, ("regdb_upgrade_v3_to_v4_fn: skipping [%.*s]\n",
			   SSTR(key)));
		return 0;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		DEBUG(0, ("regdb_upgrade_v3_to_v4_fn: talloc_stackframe failed\n"));
		return 1;
	}

	/* Handle registry values (prefixed with REG_VALUE_PREFIX) */
	if (STARTS_WITH(key, REG_VALUE_PREFIX)) {
		werr = regdb_convert_values_v3_to_v4(tmp_ctx, rec, key, val);
		if (W_ERROR_IS_OK(werr)) {
			(*ctx->converted_values)++;
		} else if (W_ERROR_EQUAL(werr, WERR_INVALID_DATA)) {
			DEBUG(1, ("regdb_upgrade_v3_to_v4_fn: skipping invalid "
				  "value record [%.*s]: %s\n",
				  SSTR(key), win_errstr(werr)));
			(*ctx->skipped_records)++;
		} else {
			DEBUG(0, ("regdb_upgrade_v3_to_v4_fn: fatal error "
				  "converting value record [%.*s]: %s\n",
				  SSTR(key), win_errstr(werr)));
			result = 1;
		}
		goto done;
	}

	/* Handle subkey lists (regular keys without prefix) */
	if (tdb_data_is_cstr(key) && hive_info((char *)key.dptr) != NULL) {
		werr = regdb_convert_subkeys_v3_to_v4(tmp_ctx, rec, key, val);
		if (W_ERROR_IS_OK(werr)) {
			(*ctx->converted_subkeys)++;
		} else if (W_ERROR_EQUAL(werr, WERR_INVALID_DATA)) {
			DEBUG(1, ("regdb_upgrade_v3_to_v4_fn: skipping invalid "
				  "subkey record [%.*s]: %s\n",
				  SSTR(key), win_errstr(werr)));
			(*ctx->skipped_records)++;
		} else {
			DEBUG(0, ("regdb_upgrade_v3_to_v4_fn: fatal error "
				  "converting subkey record [%.*s]: %s\n",
				  SSTR(key), win_errstr(werr)));
			result = 1;
		}
		goto done;
	}

	/* Skip unrecognized records */
	DEBUG(10, ("regdb_upgrade_v3_to_v4_fn: skipping unrecognized [%.*s]\n",
		   SSTR(key)));
	(*ctx->skipped_records)++;

done:
	TALLOC_FREE(tmp_ctx);
	return result;
}

static WERROR regdb_upgrade_v3_to_v4(struct db_context *db)
{
	NTSTATUS status;
	WERROR werr;
	uint32_t converted_values = 0;
	uint32_t converted_subkeys = 0;
	uint32_t skipped_records = 0;
	struct regdb_upgrade_v3_to_v4_ctx ctx;

	DEBUG(1, ("regdb_upgrade_v3_to_v4: starting upgrade to version %u\n",
		  REGDB_VERSION_V4));

	ctx.db = db;
	ctx.converted_values = &converted_values;
	ctx.converted_subkeys = &converted_subkeys;
	ctx.skipped_records = &skipped_records;

	status = dbwrap_traverse(db, regdb_upgrade_v3_to_v4_fn, &ctx, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("regdb_upgrade_v3_to_v4: traverse failed: %s\n",
			  nt_errstr(status)));
		werr = WERR_REGISTRY_IO_FAILED;
		goto done;
	}

	/* Verify that we actually converted some records */
	if (converted_values == 0 && converted_subkeys == 0) {
		DEBUG(1, ("regdb_upgrade_v3_to_v4: warning - no records were converted\n"));
	}

	werr = regdb_store_regdb_version(db, REGDB_VERSION_V4);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_upgrade_v3_to_v4: "
			  "regdb_store_regdb_version failed: %s\n",
			  win_errstr(werr)));
		goto done;
	}

	DEBUG(1, ("regdb_upgrade_v3_to_v4: upgrade complete - "
		   "converted %u value records, %u subkey records, "
		   "skipped %u records\n",
		   converted_values, converted_subkeys, skipped_records));

done:
	return werr;
}

/***********************************************************************
 Open the registry database
 ***********************************************************************/

WERROR regdb_init(void)
{
	int32_t vers_id;
	WERROR werr;
	NTSTATUS status;
	char *db_path;

	if (regdb) {
		DEBUG(10, ("regdb_init: incrementing refcount (%d->%d)\n",
			   regdb_refcount, regdb_refcount+1));
		regdb_refcount++;
		return WERR_OK;
	}

	/*
	 * Clustered Samba can only work as root because we need messaging to
	 * talk to ctdb which only works as root.
	 */
	if (!uid_wrapper_enabled() && lp_clustering() && geteuid() != 0) {
		DBG_ERR("Cluster mode requires running as root.\n");
		return WERR_ACCESS_DENIED;
	}

	db_path = state_path(talloc_tos(), "registry.tdb");
	if (db_path == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	regdb = db_open(NULL, db_path, 0,
			REG_TDB_FLAGS, O_RDWR, 0600,
			DBWRAP_LOCK_ORDER_1, REG_DBWRAP_FLAGS);
	if (!regdb) {
		regdb = db_open(NULL, db_path, 0,
				REG_TDB_FLAGS, O_RDWR|O_CREAT, 0600,
				DBWRAP_LOCK_ORDER_1, REG_DBWRAP_FLAGS);
		if (!regdb) {
			werr = ntstatus_to_werror(map_nt_error_from_unix(errno));
			DEBUG(1,("regdb_init: Failed to open registry %s (%s)\n",
				db_path, strerror(errno) ));
			TALLOC_FREE(db_path);
			return werr;
		}

		werr = regdb_store_regdb_version(regdb, REGDB_CODE_VERSION);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(1, ("regdb_init: Failed to store version: %s\n",
				  win_errstr(werr)));
			TALLOC_FREE(db_path);
			return werr;
		}

		DEBUG(10,("regdb_init: Successfully created registry tdb\n"));
	}
	TALLOC_FREE(db_path);

	regdb_refcount = 1;
	DEBUG(10, ("regdb_init: registry db opened. refcount reset (%d)\n",
		   regdb_refcount));

	status = dbwrap_fetch_int32_bystring(regdb, REGDB_VERSION_KEYNAME,
					     &vers_id);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("Reading registry version failed: %s, "
			  "initializing to version %d\n",
			  nt_errstr(status), REGDB_VERSION_V1);

		/*
		 * There was a regdb format version prior to version 1
		 * which did not store a INFO/version key. The format
		 * of this version was identical to version 1 except for
		 * the lack of the sorted subkey cache records.
		 * Since these are disposable, we can safely assume version
		 * 1 if no INFO/version key is found and run the db through
		 * the whole chain of upgrade. If the database was not
		 * initialized, this does not harm. If it was the unversioned
		 * version ("0"), then it do the right thing with the records.
		 */
		werr = regdb_store_regdb_version(regdb, REGDB_VERSION_V1);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}
		vers_id = REGDB_VERSION_V1;
	}

	if (vers_id == REGDB_CODE_VERSION) {
		return WERR_OK;
	}

	if (vers_id > REGDB_CODE_VERSION || vers_id == 0) {
		DEBUG(0, ("regdb_init: unknown registry version %d "
			  "(code version = %d), refusing initialization\n",
			  vers_id, REGDB_CODE_VERSION));
		return WERR_CAN_NOT_COMPLETE;
	}

	if (dbwrap_transaction_start(regdb) != 0) {
		return WERR_REGISTRY_IO_FAILED;
	}

	if (vers_id == REGDB_VERSION_V1) {
		DEBUG(10, ("regdb_init: upgrading registry from version %d "
			   "to %d\n", REGDB_VERSION_V1, REGDB_VERSION_V2));

		werr = regdb_upgrade_v1_to_v2(regdb);
		if (!W_ERROR_IS_OK(werr)) {
			dbwrap_transaction_cancel(regdb);
			return werr;
		}

		vers_id = REGDB_VERSION_V2;
	}

	if (vers_id == REGDB_VERSION_V2) {
		DEBUG(10, ("regdb_init: upgrading registry from version %d "
			   "to %d\n", REGDB_VERSION_V2, REGDB_VERSION_V3));

		werr = regdb_upgrade_v2_to_v3(regdb);
		if (!W_ERROR_IS_OK(werr)) {
			dbwrap_transaction_cancel(regdb);
			return werr;
		}

		vers_id = REGDB_VERSION_V3;
	}

	if (vers_id == REGDB_VERSION_V3) {
		DEBUG(10, ("regdb_init: upgrading registry from version %d "
			   "to %d\n", REGDB_VERSION_V3, REGDB_VERSION_V4));

		werr = regdb_upgrade_v3_to_v4(regdb);
		if (!W_ERROR_IS_OK(werr)) {
			dbwrap_transaction_cancel(regdb);
			return werr;
		}

		vers_id = REGDB_VERSION_V4;
	}

	/* future upgrade code should go here */

	if (dbwrap_transaction_commit(regdb) != 0) {
		return WERR_REGISTRY_IO_FAILED;
	}

	return WERR_OK;
}

/***********************************************************************
 Open the registry.  Must already have been initialized by regdb_init()
 ***********************************************************************/

WERROR regdb_open( void )
{
	WERROR result;
	char *db_path = NULL;
	int saved_errno;

	if ( regdb ) {
		DEBUG(10, ("regdb_open: incrementing refcount (%d->%d)\n",
			   regdb_refcount, regdb_refcount+1));
		regdb_refcount++;
		result = WERR_OK;
		goto done;
	}

	db_path = state_path(talloc_tos(), "registry.tdb");
	if (db_path == NULL) {
		result = WERR_NOT_ENOUGH_MEMORY;
		goto done;
	}

	become_root();

	regdb = db_open(NULL, db_path, 0,
			REG_TDB_FLAGS, O_RDWR, 0600,
			DBWRAP_LOCK_ORDER_1, REG_DBWRAP_FLAGS);
	saved_errno = errno;
	unbecome_root();
	if ( !regdb ) {
		result = ntstatus_to_werror(map_nt_error_from_unix(saved_errno));
		DEBUG(0,("regdb_open: Failed to open %s! (%s)\n",
			 db_path, strerror(saved_errno)));
		goto done;
	}

	regdb_refcount = 1;
	DEBUG(10, ("regdb_open: registry db opened. refcount reset (%d)\n",
		   regdb_refcount));

	result = WERR_OK;
done:
	TALLOC_FREE(db_path);
	return result;
}

/***********************************************************************
 ***********************************************************************/

int regdb_close( void )
{
	if (regdb_refcount == 0) {
		return 0;
	}

	regdb_refcount--;

	DEBUG(10, ("regdb_close: decrementing refcount (%d->%d)\n",
		   regdb_refcount+1, regdb_refcount));

	if ( regdb_refcount > 0 )
		return 0;

	SMB_ASSERT( regdb_refcount >= 0 );

	TALLOC_FREE(regdb);
	return 0;
}

WERROR regdb_transaction_start(void)
{
	return (dbwrap_transaction_start(regdb) == 0) ?
		WERR_OK : WERR_REGISTRY_IO_FAILED;
}

WERROR regdb_transaction_commit(void)
{
	return (dbwrap_transaction_commit(regdb) == 0) ?
		WERR_OK : WERR_REGISTRY_IO_FAILED;
}

WERROR regdb_transaction_cancel(void)
{
	return (dbwrap_transaction_cancel(regdb) == 0) ?
		WERR_OK : WERR_REGISTRY_IO_FAILED;
}

/***********************************************************************
 return the tdb sequence number of the registry tdb.
 this is an indicator for the content of the registry
 having changed. it will change upon regdb_init, too, though.
 ***********************************************************************/
int regdb_get_seqnum(void)
{
	return dbwrap_get_seqnum(regdb);
}


static WERROR regdb_delete_key_with_prefix(struct db_context *db,
					   const char *keyname,
					   const char *prefix)
{
	char *path;
	WERROR werr = WERR_NOT_ENOUGH_MEMORY;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (keyname == NULL) {
		werr = WERR_INVALID_PARAMETER;
		goto done;
	}

	if (prefix == NULL) {
		path = discard_const_p(char, keyname);
	} else {
		path = talloc_asprintf(mem_ctx, "%s\\%s", prefix, keyname);
		if (path == NULL) {
			goto done;
		}
	}

	path = normalize_reg_path(mem_ctx, path);
	if (path == NULL) {
		goto done;
	}

	werr = ntstatus_to_werror(dbwrap_purge_bystring(db, path));

done:
	talloc_free(mem_ctx);
	return werr;
}


static WERROR regdb_delete_values(struct db_context *db, const char *keyname)
{
	return regdb_delete_key_with_prefix(db, keyname, REG_VALUE_PREFIX);
}

static WERROR regdb_delete_secdesc(struct db_context *db, const char *keyname)
{
	return regdb_delete_key_with_prefix(db, keyname, REG_SECDESC_PREFIX);
}

static WERROR regdb_delete_subkeylist(struct db_context *db, const char *keyname)
{
	return regdb_delete_key_with_prefix(db, keyname, NULL);
}


static WERROR regdb_delete_key_lists(struct db_context *db, const char *keyname)
{
	WERROR werr;

	werr = regdb_delete_values(db, keyname);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(1, (__location__ " Deleting %s\\%s failed: %s\n",
			  REG_VALUE_PREFIX, keyname, win_errstr(werr)));
		goto done;
	}

	werr = regdb_delete_secdesc(db, keyname);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(1, (__location__ " Deleting %s\\%s failed: %s\n",
			  REG_SECDESC_PREFIX, keyname, win_errstr(werr)));
		goto done;
	}

	werr = regdb_delete_subkeylist(db, keyname);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(1, (__location__ " Deleting %s failed: %s\n",
			  keyname, win_errstr(werr)));
		goto done;
	}

done:
	return werr;
}

/***********************************************************************
 Add subkey strings to the registry tdb under a defined key
 fmt is the same format as tdb_pack except this function only supports
 fstrings
 ***********************************************************************/

static WERROR regdb_store_keys_internal2(struct db_context *db,
					 const char *key,
					 struct regsubkey_ctr *ctr)
{
	TDB_DATA dbuf;
	uint8_t *buffer = NULL;
	size_t buflen = 0;
	char *keyname = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	WERROR werr;

	if (!key) {
		werr = WERR_INVALID_PARAMETER;
		goto done;
	}

	keyname = talloc_strdup(ctx, key);
	if (!keyname) {
		werr = WERR_NOT_ENOUGH_MEMORY;
		goto done;
	}

	keyname = normalize_reg_path(ctx, keyname);
	if (!keyname) {
		werr = WERR_NOT_ENOUGH_MEMORY;
		goto done;
	}

	werr = regdb_pack_keys_v4(ctr, &buffer, &buflen, ctx);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_store_keys_internal2: "
			  "regdb_pack_keys_v4 failed: %s\n",
			  win_errstr(werr)));
		goto done;
	}

	dbuf.dptr = buffer;
	dbuf.dsize = buflen;
	werr = ntstatus_to_werror(dbwrap_store_bystring(db, keyname, dbuf,
							TDB_REPLACE));

done:
	TALLOC_FREE(ctx);
	return werr;
}

/**
 * Utility function to store a new empty list of
 * subkeys of given key specified as parent and subkey name
 * (thereby creating the key).
 * If the parent keyname is NULL, then the "subkey" is
 * interpreted as a base key.
 * If the subkey list does already exist, it is not modified.
 *
 * Must be called from within a transaction.
 */
static WERROR regdb_store_subkey_list(struct db_context *db, const char *parent,
				      const char *key)
{
	WERROR werr;
	char *path = NULL;
	struct regsubkey_ctr *subkeys = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	if (parent == NULL) {
		path = talloc_strdup(frame, key);
	} else {
		path = talloc_asprintf(frame, "%s\\%s", parent, key);
	}
	if (!path) {
		werr = WERR_NOT_ENOUGH_MEMORY;
		goto done;
	}

	werr = regsubkey_ctr_init(frame, &subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_fetch_keys_internal(db, path, subkeys);
	if (W_ERROR_IS_OK(werr)) {
		/* subkey list exists already - don't modify */
		goto done;
	}

	werr = regsubkey_ctr_reinit(subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	/* create a record with 0 subkeys */
	werr = regdb_store_keys_internal2(db, path, subkeys);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_store_keys: Failed to store new record for "
			  "key [%s]: %s\n", path, win_errstr(werr)));
		goto done;
	}

done:
	talloc_free(frame);
	return werr;
}

/***********************************************************************
 Store the new subkey record and create any child key records that
 do not currently exist
 ***********************************************************************/

struct regdb_store_keys_context {
	const char *key;
	struct regsubkey_ctr *ctr;
};

static NTSTATUS regdb_store_keys_action(struct db_context *db,
					void *private_data)
{
	struct regdb_store_keys_context *store_ctx;
	WERROR werr;
	int num_subkeys, i;
	char *path = NULL;
	struct regsubkey_ctr *old_subkeys = NULL;
	char *oldkeyname = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	store_ctx = (struct regdb_store_keys_context *)private_data;

	/*
	 * Re-fetch the old keys inside the transaction
	 */

	werr = regsubkey_ctr_init(mem_ctx, &old_subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_fetch_keys_internal(db, store_ctx->key, old_subkeys);
	if (!W_ERROR_IS_OK(werr) &&
	    !W_ERROR_EQUAL(werr, WERR_NOT_FOUND))
	{
		goto done;
	}

	/*
	 * Make the store operation as safe as possible without transactions:
	 *
	 * (1) For each subkey removed from ctr compared with old_subkeys:
	 *
	 *     (a) First delete the value db entry.
	 *
	 *     (b) Next delete the secdesc db record.
	 *
	 *     (c) Then delete the subkey list entry.
	 *
	 * (2) Now write the list of subkeys of the parent key,
	 *     deleting removed entries and adding new ones.
	 *
	 * (3) Finally create the subkey list entries for the added keys.
	 *
	 * This way if we crash half-way in between deleting the subkeys
	 * and storing the parent's list of subkeys, no old data can pop up
	 * out of the blue when re-adding keys later on.
	 */

	/* (1) delete removed keys' lists (values/secdesc/subkeys) */

	num_subkeys = regsubkey_ctr_numkeys(old_subkeys);
	for (i=0; i<num_subkeys; i++) {
		oldkeyname = regsubkey_ctr_specific_key(old_subkeys, i);

		if (regsubkey_ctr_key_exists(store_ctx->ctr, oldkeyname)) {
			/*
			 * It's still around, don't delete
			 */
			continue;
		}

		path = talloc_asprintf(mem_ctx, "%s\\%s", store_ctx->key,
				       oldkeyname);
		if (!path) {
			werr = WERR_NOT_ENOUGH_MEMORY;
			goto done;
		}

		werr = regdb_delete_key_lists(db, path);
		W_ERROR_NOT_OK_GOTO_DONE(werr);

		TALLOC_FREE(path);
	}

	TALLOC_FREE(old_subkeys);

	/* (2) store the subkey list for the parent */

	werr = regdb_store_keys_internal2(db, store_ctx->key, store_ctx->ctr);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,("regdb_store_keys: Failed to store new subkey list "
			 "for parent [%s]: %s\n", store_ctx->key,
			 win_errstr(werr)));
		goto done;
	}

	/* (3) now create records for any subkeys that don't already exist */

	num_subkeys = regsubkey_ctr_numkeys(store_ctx->ctr);

	for (i=0; i<num_subkeys; i++) {
		const char *subkey;

		subkey = regsubkey_ctr_specific_key(store_ctx->ctr, i);

		werr = regdb_store_subkey_list(db, store_ctx->key, subkey);
		W_ERROR_NOT_OK_GOTO_DONE(werr);
	}

	/*
	 * Update the seqnum in the container to possibly
	 * prevent next read from going to disk
	 */
	werr = regsubkey_ctr_set_seqnum(store_ctx->ctr, dbwrap_get_seqnum(db));

done:
	talloc_free(mem_ctx);
	return werror_to_ntstatus(werr);
}

static bool regdb_store_keys_internal(struct db_context *db, const char *key,
				      struct regsubkey_ctr *ctr)
{
	int num_subkeys, old_num_subkeys, i;
	struct regsubkey_ctr *old_subkeys = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	WERROR werr;
	bool ret = false;
	struct regdb_store_keys_context store_ctx;

	if (!regdb_key_exists(db, key)) {
		goto done;
	}

	/*
	 * fetch a list of the old subkeys so we can determine if anything has
	 * changed
	 */

	werr = regsubkey_ctr_init(ctx, &old_subkeys);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,("regdb_store_keys: talloc() failure!\n"));
		goto done;
	}

	werr = regdb_fetch_keys_internal(db, key, old_subkeys);
	if (!W_ERROR_IS_OK(werr) &&
	    !W_ERROR_EQUAL(werr, WERR_NOT_FOUND))
	{
		goto done;
	}

	num_subkeys = regsubkey_ctr_numkeys(ctr);
	old_num_subkeys = regsubkey_ctr_numkeys(old_subkeys);
	if ((num_subkeys && old_num_subkeys) &&
	    (num_subkeys == old_num_subkeys)) {

		for (i = 0; i < num_subkeys; i++) {
			if (strcmp(regsubkey_ctr_specific_key(ctr, i),
				   regsubkey_ctr_specific_key(old_subkeys, i))
			    != 0)
			{
				break;
			}
		}
		if (i == num_subkeys) {
			/*
			 * Nothing changed, no point to even start a tdb
			 * transaction
			 */

			ret = true;
			goto done;
		}
	}

	TALLOC_FREE(old_subkeys);

	store_ctx.key = key;
	store_ctx.ctr = ctr;

	werr = regdb_trans_do(db,
			      regdb_store_keys_action,
			      &store_ctx);

	ret = W_ERROR_IS_OK(werr);

done:
	TALLOC_FREE(ctx);

	return ret;
}

static bool regdb_store_keys(const char *key, struct regsubkey_ctr *ctr)
{
	return regdb_store_keys_internal(regdb, key, ctr);
}

/**
 * create a subkey of a given key
 */

struct regdb_create_subkey_context {
	const char *key;
	const char *subkey;
};

static NTSTATUS regdb_create_subkey_action(struct db_context *db,
					   void *private_data)
{
	WERROR werr;
	struct regdb_create_subkey_context *create_ctx;
	struct regsubkey_ctr *subkeys;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	create_ctx = (struct regdb_create_subkey_context *)private_data;

	werr = regsubkey_ctr_init(mem_ctx, &subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_fetch_keys_internal(db, create_ctx->key, subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regsubkey_ctr_addkey(subkeys, create_ctx->subkey);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_store_keys_internal2(db, create_ctx->key, subkeys);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, (__location__ " failed to store new subkey list for "
			 "parent key %s: %s\n", create_ctx->key,
			 win_errstr(werr)));
	}

	werr = regdb_store_subkey_list(db, create_ctx->key, create_ctx->subkey);

done:
	talloc_free(mem_ctx);
	return werror_to_ntstatus(werr);
}

static WERROR regdb_create_subkey_internal(struct db_context *db,
					   const char *key,
					   const char *subkey)
{
	WERROR werr;
	struct regsubkey_ctr *subkeys;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct regdb_create_subkey_context create_ctx;

	if (!regdb_key_exists(db, key)) {
		werr = WERR_NOT_FOUND;
		goto done;
	}

	werr = regsubkey_ctr_init(mem_ctx, &subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_fetch_keys_internal(db, key, subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	if (regsubkey_ctr_key_exists(subkeys, subkey)) {
		char *newkey;

		newkey = talloc_asprintf(mem_ctx, "%s\\%s", key, subkey);
		if (newkey == NULL) {
			werr = WERR_NOT_ENOUGH_MEMORY;
			goto done;
		}

		if (regdb_key_exists(db, newkey)) {
			werr = WERR_OK;
			goto done;
		}
	}

	talloc_free(subkeys);

	create_ctx.key = key;
	create_ctx.subkey = subkey;

	werr = regdb_trans_do(db,
			      regdb_create_subkey_action,
			      &create_ctx);

done:
	talloc_free(mem_ctx);
	return werr;
}

static WERROR regdb_create_subkey(const char *key, const char *subkey)
{
	return regdb_create_subkey_internal(regdb, key, subkey);
}

/**
 * create a base key
 */

struct regdb_create_basekey_context {
	const char *key;
};

static NTSTATUS regdb_create_basekey_action(struct db_context *db,
					    void *private_data)
{
	WERROR werr;
	struct regdb_create_basekey_context *create_ctx;

	create_ctx = (struct regdb_create_basekey_context *)private_data;

	werr = regdb_store_subkey_list(db, NULL, create_ctx->key);

	return werror_to_ntstatus(werr);
}

static WERROR regdb_create_basekey(struct db_context *db, const char *key)
{
	WERROR werr;
	struct regdb_create_subkey_context create_ctx;

	create_ctx.key = key;

	werr = regdb_trans_do(db,
			      regdb_create_basekey_action,
			      &create_ctx);

	return werr;
}

/**
 * create a subkey of a given key
 */

struct regdb_delete_subkey_context {
	const char *key;
	const char *subkey;
	const char *path;
	bool lazy;
};

static NTSTATUS regdb_delete_subkey_action(struct db_context *db,
					   void *private_data)
{
	WERROR werr;
	struct regdb_delete_subkey_context *delete_ctx;
	struct regsubkey_ctr *subkeys;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	delete_ctx = (struct regdb_delete_subkey_context *)private_data;

	werr = regdb_delete_key_lists(db, delete_ctx->path);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	if (delete_ctx->lazy) {
		goto done;
	}

	werr = regsubkey_ctr_init(mem_ctx, &subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_fetch_keys_internal(db, delete_ctx->key, subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regsubkey_ctr_delkey(subkeys, delete_ctx->subkey);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_store_keys_internal2(db, delete_ctx->key, subkeys);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, (__location__ " failed to store new subkey_list for "
			 "parent key %s: %s\n", delete_ctx->key,
			 win_errstr(werr)));
	}

done:
	talloc_free(mem_ctx);
	return werror_to_ntstatus(werr);
}

static WERROR regdb_delete_subkey(const char *key, const char *subkey, bool lazy)
{
	WERROR werr;
	char *path;
	struct regdb_delete_subkey_context delete_ctx;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (!regdb_key_exists(regdb, key)) {
		werr = WERR_NOT_FOUND;
		goto done;
	}

	path = talloc_asprintf(mem_ctx, "%s\\%s", key, subkey);
	if (path == NULL) {
		werr = WERR_NOT_ENOUGH_MEMORY;
		goto done;
	}

	if (!regdb_key_exists(regdb, path)) {
		werr = WERR_OK;
		goto done;
	}

	delete_ctx.key = key;
	delete_ctx.subkey = subkey;
	delete_ctx.path = path;
	delete_ctx.lazy = lazy;

	werr = regdb_trans_do(regdb,
			      regdb_delete_subkey_action,
			      &delete_ctx);

done:
	talloc_free(mem_ctx);
	return werr;
}

static TDB_DATA regdb_fetch_key_internal(struct db_context *db,
					 TALLOC_CTX *mem_ctx, const char *key)
{
	char *path = NULL;
	TDB_DATA data;
	NTSTATUS status;

	path = normalize_reg_path(mem_ctx, key);
	if (!path) {
		return make_tdb_data(NULL, 0);
	}

	status = dbwrap_fetch_bystring(db, mem_ctx, path, &data);
	if (!NT_STATUS_IS_OK(status)) {
		data = tdb_null;
	}

	TALLOC_FREE(path);
	return data;
}


/**
 * Check for the existence of a key.
 *
 * Existence of a key is authoritatively defined by
 * the existence of the record that contains the list
 * of its subkeys.
 *
 * Return false, if the record does not match the correct
 * structure of an initial 4-byte counter and then a
 * list of the corresponding number of zero-terminated
 * strings.
 */
static bool regdb_key_exists(struct db_context *db, const char *key)
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	TDB_DATA value;
	bool ret = false;
	char *path;

	if (key == NULL) {
		goto done;
	}

	path = normalize_reg_path(mem_ctx, key);
	if (path == NULL) {
		DEBUG(0, ("out of memory! (talloc failed)\n"));
		goto done;
	}

	if (*path == '\0') {
		goto done;
	}

	value = regdb_fetch_key_internal(db, mem_ctx, path);
	if (value.dptr == NULL) {
		goto done;
	}

	if (value.dsize == 0) {
		DEBUG(10, ("regdb_key_exists: subkeylist-record for key "
			  "[%s] is empty: Could be a deleted record in a "
			  "clustered (ctdb) environment?\n",
			  path));
		goto done;
	}

	ret = true;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}


/***********************************************************************
 Retrieve an array of strings containing subkeys.  Memory should be
 released by the caller.
 ***********************************************************************/

static WERROR regdb_fetch_keys_internal(struct db_context *db, const char *key,
					struct regsubkey_ctr *ctr)
{
	WERROR werr;
	TALLOC_CTX *frame = talloc_stackframe();
	TDB_DATA value;
	int seqnum[2], count;

	DEBUG(11,("regdb_fetch_keys: Enter key => [%s]\n", key ? key : "NULL"));

	if (!regdb_key_exists(db, key)) {
		DEBUG(10, ("key [%s] not found\n", key));
		werr = WERR_NOT_FOUND;
		goto done;
	}

	werr = regsubkey_ctr_reinit(ctr);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	count = 0;
	ZERO_STRUCT(value);
	seqnum[0] = dbwrap_get_seqnum(db);

	do {
		count++;
		TALLOC_FREE(value.dptr);
		value = regdb_fetch_key_internal(db, frame, key);
		seqnum[count % 2] = dbwrap_get_seqnum(db);

	} while (seqnum[0] != seqnum[1]);

	if (count > 1) {
		DEBUG(5, ("regdb_fetch_keys_internal: it took %d attempts to "
			  "fetch key '%s' with constant seqnum\n",
			  count, key));
	}

	werr = regsubkey_ctr_set_seqnum(ctr, seqnum[0]);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	if (value.dsize == 0 || value.dptr == NULL) {
		DEBUG(10, ("regdb_fetch_keys: no subkeys found for key [%s]\n",
			   key));
		goto done;
	}

	werr = regdb_unpack_keys_v4(ctr, value.dptr, value.dsize);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(5, ("regdb_fetch_keys: regdb_unpack_keys_v4 "
			  "failed: %s\n", win_errstr(werr)));
		goto done;
	}

	DEBUG(11,("regdb_fetch_keys: Exit [%d] items\n",
		  regsubkey_ctr_numkeys(ctr)));

done:
	TALLOC_FREE(frame);
	return werr;
}

static int regdb_fetch_keys(const char *key, struct regsubkey_ctr *ctr)
{
	WERROR werr;

	werr = regdb_fetch_keys_internal(regdb, key, ctr);
	if (!W_ERROR_IS_OK(werr)) {
		return -1;
	}

	return regsubkey_ctr_numkeys(ctr);
}

/****************************************************************************
 Unpack a list of registry values frem the TDB
 ***************************************************************************/

static int regdb_unpack_values(struct regval_ctr *values,
			       uint8_t *buf,
			       size_t buflen)
{
	int this_len;
	size_t len = 0;
	uint32_t type;
	fstring valuename;
	uint32_t size;
	uint8_t *data_p;
	uint32_t num_values = 0;
	uint32_t i;

	/* loop and unpack the rest of the registry values */

	this_len = tdb_unpack(buf, buflen, "d", &num_values);
	if (this_len == -1) {
		DBG_WARNING("Invalid registry data, "
			    "tdb_unpack failed\n");
		return -1;
	}
	len = this_len;

	for ( i=0; i<num_values; i++ ) {
		/* unpack the next regval */

		type = REG_NONE;
		size = 0;
		data_p = NULL;
		valuename[0] = '\0';
		this_len = tdb_unpack(buf+len, buflen-len, "fdB",
				      valuename,
				      &type,
				      &size,
				      &data_p);
		if (this_len == -1) {
			DBG_WARNING("Invalid registry data, "
				    "tdb_unpack failed\n");
			return -1;
		}
		len += this_len;
		if (len < (size_t)this_len) {
			DBG_WARNING("Invalid registry data, "
				    "integer overflow\n");
			return -1;
		}

		regval_ctr_addvalue(values, valuename, type,
				(uint8_t *)data_p, size);
		SAFE_FREE(data_p); /* 'B' option to tdb_unpack does a malloc() */

		DEBUG(10, ("regdb_unpack_values: value[%d]: name[%s] len[%d]\n",
			   i, valuename, size));
	}

	return len;
}

/****************************************************************************
 Pack all values in all printer keys
 ***************************************************************************/

int regdb_pack_values_v3(struct regval_ctr *values, uint8_t *buf, int buflen)
{
	int len = 0;
	int i;
	struct regval_blob *val;
	int num_values;

	if ( !values )
		return 0;

	num_values = regval_ctr_numvals( values );

	/* pack the number of values first */

	len += tdb_pack( buf+len, buflen-len, "d", num_values );

	/* loop over all values */

	for ( i=0; i<num_values; i++ ) {
		val = regval_ctr_specific_value( values, i );
		len += tdb_pack(buf+len, buflen-len, "fdB",
				regval_name(val),
				regval_type(val),
				regval_size(val),
				regval_data_p(val) );
	}

	return len;
}

/****************************************************************************
 Pack subkeys using V3 format (legacy tdb_pack)
 ***************************************************************************/

int regdb_pack_keys_v3(struct regsubkey_ctr *ctr, uint8_t *buf, int buflen)
{
	int len = 0;
	uint32_t j;
	uint32_t num_subkeys;

	if (ctr == NULL) {
		return 0;
	}

	num_subkeys = regsubkey_ctr_numkeys(ctr);

	/* Pack the number of subkeys first */
	len += tdb_pack(buf + len, buflen - len, "d", num_subkeys);

	/* Loop over all subkeys */
	for (j = 0; j < num_subkeys; j++) {
		const char *subkey = regsubkey_ctr_specific_key(ctr, j);
		len += tdb_pack(buf + len, buflen - len, "f", subkey);
	}

	return len;
}

/****************************************************************************
 Pack values using V4 format (NDR)
 ***************************************************************************/

WERROR regdb_pack_values_v4(struct regval_ctr *values,
			    uint8_t **buf,
			    size_t *buflen,
			    TALLOC_CTX *mem_ctx)
{
	struct registry_value_list_blob blob;
	struct registry_value_list_v4 *v4;
	enum ndr_err_code ndr_err;
	DATA_BLOB ndr_blob;
	int i, num_values;

	if (values == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	num_values = regval_ctr_numvals(values);

	/* Validate input data */
	for (i = 0; i < num_values; i++) {
		struct regval_blob *val = regval_ctr_specific_value(values, i);
		if (val == NULL) {
			DEBUG(0, ("regdb_pack_values_v4: NULL value at index %d\n", i));
			return WERR_INVALID_PARAMETER;
		}
		if (regval_name(val) == NULL) {
			DEBUG(0, ("regdb_pack_values_v4: NULL value name at index %d\n", i));
			return WERR_INVALID_PARAMETER;
		}
		/* Check for reasonable value name length */
		if (strlen(regval_name(val)) > 16383) { /* Max registry value name length */
			DEBUG(0, ("regdb_pack_values_v4: value name too long at index %d: %zu\n",
				  i, strlen(regval_name(val))));
			return WERR_INVALID_PARAMETER;
		}
	}

	ZERO_STRUCT(blob);
	blob.version = REGDB_VERSION_V4;
	blob.reserved = 0;

	v4 = &blob.ctr.v4;
	v4->num_values = num_values;
	v4->seqnum = regval_ctr_get_seqnum(values);
	v4->values = NULL;

	if (!num_values) {
		goto ndr_push;
	}

	v4->values = talloc_array(mem_ctx,
				  struct registry_value_v4,
				  num_values);
	if (v4->values == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	for (i = 0; i < num_values; i++) {
		struct regval_blob *val = regval_ctr_specific_value(values, i);
		struct registry_value_v4 *v4_val = &v4->values[i];
		const char *name = regval_name(val);

		v4_val->valuename_len = strlen(name) + 1;
		v4_val->valuename = (uint8_t *)talloc_strdup(v4->values, name);
		if (v4_val->valuename == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		v4_val->type = regval_type(val);
		v4_val->size = regval_size(val);
		v4_val->data = NULL;
		if (!v4_val->size) {
			continue;
		}
		v4_val->data = talloc_memdup(v4->values,
					     regval_data_p(val),
					     v4_val->size);
		if (v4_val->data == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}

ndr_push:
	ndr_err = ndr_push_struct_blob(
		&ndr_blob,
		mem_ctx,
		&blob,
		(ndr_push_flags_fn_t)ndr_push_registry_value_list_blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("regdb_pack_values_v4: "
			  "ndr_push_registry_value_list_blob failed: %s\n",
			  ndr_errstr(ndr_err)));
		return WERR_INTERNAL_ERROR;
	}

	*buf = ndr_blob.data;
	*buflen = ndr_blob.length;

	return WERR_OK;
}

/****************************************************************************
 Unpack values from V4 format (NDR) or legacy formats (V1-V3)
 ***************************************************************************/

WERROR regdb_unpack_values_v4(struct regval_ctr *values,
			      uint8_t *buf,
			      size_t buflen)
{
	struct registry_value_list_blob blob;
	enum ndr_err_code ndr_err;
	DATA_BLOB ndr_blob;
	TALLOC_CTX *tmp_ctx = NULL;
	uint32_t i;
	WERROR werr = WERR_OK;

	if (buflen == 0) {
		DEBUG(10, ("regdb_unpack_values_v4: empty buffer is "
			   "treated as zero values\n"));
		werr = WERR_OK;
		goto done;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	ndr_blob.data = buf;
	ndr_blob.length = buflen;

	ZERO_STRUCT(blob);

	ndr_err = ndr_pull_struct_blob(
		&ndr_blob,
		tmp_ctx,
		&blob,
		(ndr_pull_flags_fn_t)ndr_pull_registry_value_list_blob);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		int ret;

		DEBUG(10, ("regdb_unpack_values_v4: NDR parsing failed for "
			   "buffer length %zu (%s), trying legacy format\n",
			   buflen, ndr_errstr(ndr_err)));
		ret = regdb_unpack_values(values, buf, buflen);
		if (ret == -1) {
			DEBUG(0, ("regdb_unpack_values_v4: both NDR and legacy "
				  "unpacking failed for buffer length %zu, "
				  "data may be corrupted\n",
				  buflen));
			werr = WERR_INTERNAL_DB_CORRUPTION;
		} else {
			DEBUG(5, ("regdb_unpack_values_v4: legacy unpack succeeded "
				  "after NDR parse failure for buffer length %zu\n",
				  buflen));
			werr = WERR_OK;
		}
		goto done;
	}

	/* Check version - if not V4, try legacy format */
	if (blob.version != REGDB_VERSION_V4) {
		int ret;

		DEBUG(10, ("regdb_unpack_values_v4: version %u found "
			   "(expected %u), trying legacy format\n",
			   blob.version, REGDB_VERSION_V4));
		ret = regdb_unpack_values(values, buf, buflen);
		if (ret == -1) {
			DEBUG(0, ("regdb_unpack_values_v4: legacy unpacking "
				  "failed for version %u, buffer length %zu\n",
				  blob.version, buflen));
			werr = WERR_INTERNAL_DB_CORRUPTION;
		} else {
			DEBUG(5, ("regdb_unpack_values_v4: legacy unpack succeeded "
				  "for version %u, buffer length %zu\n",
				  blob.version, buflen));
			werr = WERR_OK;
		}
		goto done;
	}

	for (i = 0; i < blob.ctr.v4.num_values; i++) {
		const struct registry_value_v4 *v4_val;
		int ret;

		v4_val = &blob.ctr.v4.values[i];
		ret = regval_ctr_addvalue(values,
					  (const char *)v4_val->valuename,
					  v4_val->type,
					  v4_val->data,
					  v4_val->size);
		if (ret == 0 && blob.ctr.v4.num_values != 0) {
			DEBUG(0, ("regdb_unpack_values_v4: regval_ctr_addvalue "
				  "failed at index %u for value [%s], type [%u], "
				  "size [%u]\n",
				  i,
				  v4_val->valuename != NULL ?
				  (const char *)v4_val->valuename : "<null>",
				  v4_val->type,
				  v4_val->size));
			werr = WERR_NOT_ENOUGH_MEMORY;
			goto done;
		}
	}

	werr = regval_ctr_set_seqnum(values, blob.ctr.v4.seqnum);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_unpack_values_v4: regval_ctr_set_seqnum "
			  "failed: %s\n",
			  win_errstr(werr)));
		goto done;
	}

	werr = WERR_OK;

done:
	TALLOC_FREE(tmp_ctx);
	return werr;
}

/****************************************************************************
 Pack subkeys using V4 format (NDR)
 ***************************************************************************/

static int regdb_subkey_cmp(const void *pa, const void *pb)
{
	const char *const *a = pa;
	const char *const *b = pb;

	return strcmp(*a, *b);
}

WERROR
regdb_pack_keys_v4(struct regsubkey_ctr *ctr,
		   uint8_t **buf,
		   size_t *buflen,
		   TALLOC_CTX *mem_ctx)
{
	struct registry_subkey_list_blob blob;
	struct registry_subkey_list_v4 *v4;
	enum ndr_err_code ndr_err;
	DATA_BLOB ndr_blob;
	uint32_t num_subkeys;
	uint32_t i;

	if (ctr == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	num_subkeys = regsubkey_ctr_numkeys(ctr);

	/* Validate input data */
	for (i = 0; i < num_subkeys; i++) {
		const char *subkey = regsubkey_ctr_specific_key(ctr, i);
		if (subkey == NULL) {
			DEBUG(0, ("regdb_pack_keys_v4: NULL subkey at index %u\n", i));
			return WERR_INVALID_PARAMETER;
		}
		/* Check for reasonable subkey name length */
		if (strlen(subkey) > 255) { /* Max registry key name length */
			DEBUG(0, ("regdb_pack_keys_v4: subkey name too long at index %u: %zu\n",
				  i, strlen(subkey)));
			return WERR_INVALID_PARAMETER;
		}
	}

	ZERO_STRUCT(blob);
	blob.version = REGDB_VERSION_V4;
	blob.reserved = 0;

	v4 = &blob.ctr.v4;
	v4->num_subkeys = num_subkeys;
	v4->seqnum = regsubkey_ctr_get_seqnum(ctr);
	v4->subkeys = NULL;

	if (!num_subkeys) {
		goto ndr_push;
	}

	v4->subkeys = talloc_array(mem_ctx, const char *, num_subkeys);
	if (v4->subkeys == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	for (i = 0; i < num_subkeys; i++) {
		const char *subkey = regsubkey_ctr_specific_key(ctr, i);

		v4->subkeys[i] = talloc_strdup(v4->subkeys, subkey);
		if (v4->subkeys[i] == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}

	TYPESAFE_QSORT(v4->subkeys, num_subkeys, regdb_subkey_cmp);

ndr_push:
	ndr_err = ndr_push_struct_blob(
		&ndr_blob,
		mem_ctx,
		&blob,
		(ndr_push_flags_fn_t)ndr_push_registry_subkey_list_blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("regdb_pack_keys_v4: "
			  "ndr_push_registry_subkey_list_blob failed: %s\n",
			  ndr_errstr(ndr_err)));
		return WERR_INTERNAL_ERROR;
	}

	*buf = ndr_blob.data;
	*buflen = ndr_blob.length;

	return WERR_OK;
}

/****************************************************************************
 Unpack subkeys from V4 format (NDR) or legacy format (V1-V3)
 ***************************************************************************/

WERROR
regdb_unpack_keys_v4(struct regsubkey_ctr *ctr, uint8_t *buf, size_t buflen)
{
	struct registry_subkey_list_blob blob;
	enum ndr_err_code ndr_err;
	DATA_BLOB ndr_blob;
	TALLOC_CTX *tmp_ctx;
	uint32_t i;
	WERROR werr = WERR_OK;
	uint32_t num_items;
	uint32_t len;
	fstring subkeyname;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	ndr_blob.data = buf;
	ndr_blob.length = buflen;

	ZERO_STRUCT(blob);

	ndr_err = ndr_pull_struct_blob(
		&ndr_blob,
		tmp_ctx,
		&blob,
		(ndr_pull_flags_fn_t)ndr_pull_registry_subkey_list_blob);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(10, ("regdb_unpack_keys_v4: NDR parsing failed for "
			   "buffer length %zu (%s), trying legacy format\n",
			   buflen, ndr_errstr(ndr_err)));
		goto legacy_format;
	}
	/* Check version - if not V4, try legacy format */
	if (blob.version != REGDB_VERSION_V4) {
		DEBUG(10, ("regdb_unpack_keys_v4: version %u found "
			   "(expected %u), trying legacy format\n",
			   blob.version, REGDB_VERSION_V4));
		goto legacy_format;
	}

	/* Set poper sequence number */
	werr = regsubkey_ctr_set_seqnum(ctr, blob.ctr.v4.seqnum);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_unpack_keys_v4: "
			  "regsubkey_ctr_set_seqnum failed: %s\n",
			  win_errstr(werr)));
		goto done;
	}

	for (i = 0; i < blob.ctr.v4.num_subkeys; i++) {
		werr = regsubkey_ctr_addkey(ctr, blob.ctr.v4.subkeys[i]);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(5, ("regdb_unpack_keys_v4: "
				  "regsubkey_ctr_addkey failed: %s\n",
				  win_errstr(werr)));
			goto done;
		}
	}
	goto done;

legacy_format:
	DEBUG(10, ("regdb_unpack_keys_v4: trying legacy formats\n"));

	/* Legacy unpacking code */
	len = tdb_unpack(buf, buflen, "d", &num_items);
	if (len == (uint32_t)-1) {
		werr = WERR_NOT_FOUND;
		goto done;
	}

	for (i = 0; i < num_items; i++) {
		int this_len;

		this_len = tdb_unpack(buf + len,
				      buflen - len,
				      "f",
				      subkeyname);
		if (this_len == -1) {
			DBG_WARNING("Invalid registry data: "
				    "tdb_unpack failed\n");
			werr = WERR_INTERNAL_DB_CORRUPTION;
			goto done;
		}
		len += this_len;
		if (len < this_len) {
			DBG_WARNING("Invalid registry data: "
				    "integer overflow\n");
			werr = WERR_INTERNAL_DB_CORRUPTION;
			goto done;
		}

		werr = regsubkey_ctr_addkey(ctr, subkeyname);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(5, ("regdb_unpack_keys_v4: "
				  "regsubkey_ctr_addkey failed: %s\n",
				  win_errstr(werr)));
			goto done;
		}
	}

done:
	TALLOC_FREE(tmp_ctx);
	return werr;
}

/***********************************************************************
 Retrieve an array of strings containing subkeys.  Memory should be
 released by the caller.
 ***********************************************************************/

static int regdb_fetch_values_internal(struct db_context *db, const char* key,
				       struct regval_ctr *values)
{
	char *keystr = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = 0;
	TDB_DATA value;
	WERROR werr;
	int seqnum[2], count;

	DEBUG(10,("regdb_fetch_values: Looking for values of key [%s]\n", key));

	if (!regdb_key_exists(db, key)) {
		DEBUG(10, ("regb_fetch_values: key [%s] does not exist\n",
			   key));
		ret = -1;
		goto done;
	}

	keystr = talloc_asprintf(ctx, "%s\\%s", REG_VALUE_PREFIX, key);
	if (!keystr) {
		goto done;
	}

	ZERO_STRUCT(value);
	count = 0;
	seqnum[0] = dbwrap_get_seqnum(db);

	do {
		count++;
		TALLOC_FREE(value.dptr);
		value = regdb_fetch_key_internal(db, ctx, keystr);
		seqnum[count % 2] = dbwrap_get_seqnum(db);
	} while (seqnum[0] != seqnum[1]);

	if (count > 1) {
		DEBUG(5, ("regdb_fetch_values_internal: it took %d attempts "
			  "to fetch key '%s' with constant seqnum\n",
			  count, key));
	}

	werr = regval_ctr_set_seqnum(values, seqnum[0]);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	if (!value.dptr) {
		/* all keys have zero values by default */
		ret = 0;
		goto done;
	}

	werr = regdb_unpack_values_v4(values, value.dptr, value.dsize);
	if (!W_ERROR_IS_OK(werr)) {
		DBG_WARNING("regdb_unpack_values_v4 failed for key [%s], "
			    "buffer length %zu: %s\n",
			    key,
			    value.dsize,
			    win_errstr(werr));
		ret = -1;
		goto done;
	}

	ret = regval_ctr_numvals(values);

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int regdb_fetch_values(const char* key, struct regval_ctr *values)
{
	return regdb_fetch_values_internal(regdb, key, values);
}

static NTSTATUS regdb_store_values_internal(struct db_context *db,
					    const char *key,
					    struct regval_ctr *values)
{
	TDB_DATA old_data, data;
	char *keystr = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	NTSTATUS status;
	WERROR werr;

	DEBUG(10,("regdb_store_values: Looking for values of key [%s]\n", key));

	if (!regdb_key_exists(db, key)) {
		status = NT_STATUS_NOT_FOUND;
		goto done;
	}

	if (regval_ctr_numvals(values) == 0) {
		werr = regdb_delete_values(db, key);
		if (!W_ERROR_IS_OK(werr)) {
			status = werror_to_ntstatus(werr);
			goto done;
		}

		/*
		 * update the seqnum in the cache to prevent the next read
		 * from going to disk
		 */
		werr = regval_ctr_set_seqnum(values, dbwrap_get_seqnum(db));
		status = werror_to_ntstatus(werr);
		goto done;
	}

	ZERO_STRUCT(data);

	werr = regdb_pack_values_v4(values, &data.dptr, &data.dsize, ctx);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,("regdb_store_values: unable to pack values for key [%s]: "
			 "%s\n",
			 key, win_errstr(werr)));
		status = werror_to_ntstatus(werr);
		goto done;
	}

	keystr = talloc_asprintf(ctx, "%s\\%s", REG_VALUE_PREFIX, key );
	if (!keystr) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	keystr = normalize_reg_path(ctx, keystr);
	if (!keystr) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	status = dbwrap_fetch_bystring(db, ctx, keystr, &old_data);

	if (NT_STATUS_IS_OK(status)
	    && (old_data.dptr != NULL)
	    && (old_data.dsize == data.dsize)
	    && (memcmp(old_data.dptr, data.dptr, data.dsize) == 0))
	{
		status = NT_STATUS_OK;
		goto done;
	}

	status = dbwrap_trans_store_bystring(db, keystr, data, TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("regdb_store_values_internal: error storing: %s\n", nt_errstr(status)));
		goto done;
	}

	/*
	 * update the seqnum in the cache to prevent the next read
	 * from going to disk
	 */
	werr = regval_ctr_set_seqnum(values, dbwrap_get_seqnum(db));
	status = werror_to_ntstatus(werr);

done:
	TALLOC_FREE(ctx);
	return status;
}

struct regdb_store_values_ctx {
	const char *key;
	struct regval_ctr *values;
};

static NTSTATUS regdb_store_values_action(struct db_context *db,
					  void *private_data)
{
	NTSTATUS status;
	struct regdb_store_values_ctx *ctx =
		(struct regdb_store_values_ctx *)private_data;

	status = regdb_store_values_internal(db, ctx->key, ctx->values);

	return status;
}

static bool regdb_store_values(const char *key, struct regval_ctr *values)
{
	WERROR werr;
	struct regdb_store_values_ctx ctx;

	ctx.key = key;
	ctx.values = values;

	werr = regdb_trans_do(regdb, regdb_store_values_action, &ctx);

	return W_ERROR_IS_OK(werr);
}

static WERROR regdb_get_secdesc(TALLOC_CTX *mem_ctx, const char *key,
				struct security_descriptor **psecdesc)
{
	char *tdbkey;
	TDB_DATA data;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	WERROR err = WERR_OK;

	DEBUG(10, ("regdb_get_secdesc: Getting secdesc of key [%s]\n", key));

	if (!regdb_key_exists(regdb, key)) {
		err = WERR_FILE_NOT_FOUND;
		goto done;
	}

	tdbkey = talloc_asprintf(tmp_ctx, "%s\\%s", REG_SECDESC_PREFIX, key);
	if (tdbkey == NULL) {
		err = WERR_NOT_ENOUGH_MEMORY;
		goto done;
	}

	tdbkey = normalize_reg_path(tmp_ctx, tdbkey);
	if (tdbkey == NULL) {
		err = WERR_NOT_ENOUGH_MEMORY;
		goto done;
	}

	status = dbwrap_fetch_bystring(regdb, tmp_ctx, tdbkey, &data);
	if (!NT_STATUS_IS_OK(status)) {
		err = WERR_FILE_NOT_FOUND;
		goto done;
	}

	status = unmarshall_sec_desc(mem_ctx, (uint8_t *)data.dptr, data.dsize,
				     psecdesc);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MEMORY)) {
		err = WERR_NOT_ENOUGH_MEMORY;
	} else if (!NT_STATUS_IS_OK(status)) {
		err = WERR_REGISTRY_CORRUPT;
	}

done:
	TALLOC_FREE(tmp_ctx);
	return err;
}

struct regdb_set_secdesc_ctx {
	const char *key;
	struct security_descriptor *secdesc;
};

static NTSTATUS regdb_set_secdesc_action(struct db_context *db,
					 void *private_data)
{
	char *tdbkey;
	NTSTATUS status;
	TDB_DATA tdbdata;
	struct regdb_set_secdesc_ctx *ctx =
		(struct regdb_set_secdesc_ctx *)private_data;
	TALLOC_CTX *frame = talloc_stackframe();

	tdbkey = talloc_asprintf(frame, "%s\\%s", REG_SECDESC_PREFIX, ctx->key);
	if (tdbkey == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	tdbkey = normalize_reg_path(frame, tdbkey);
	if (tdbkey == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (ctx->secdesc == NULL) {
		/* assuming a delete */
		status = dbwrap_delete_bystring(db, tdbkey);
		goto done;
	}

	status = marshall_sec_desc(frame, ctx->secdesc, &tdbdata.dptr,
				   &tdbdata.dsize);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = dbwrap_store_bystring(db, tdbkey, tdbdata, 0);

done:
	TALLOC_FREE(frame);
	return status;
}

static WERROR regdb_set_secdesc(const char *key,
				struct security_descriptor *secdesc)
{
	WERROR err;
	struct regdb_set_secdesc_ctx ctx;

	if (!regdb_key_exists(regdb, key)) {
		err = WERR_FILE_NOT_FOUND;
		goto done;
	}

	ctx.key = key;
	ctx.secdesc = secdesc;

	err = regdb_trans_do(regdb, regdb_set_secdesc_action, &ctx);

done:
	return err;
}

static bool regdb_subkeys_need_update(struct regsubkey_ctr *subkeys)
{
	return (regdb_get_seqnum() != regsubkey_ctr_get_seqnum(subkeys));
}

static bool regdb_values_need_update(struct regval_ctr *values)
{
	return (regdb_get_seqnum() != regval_ctr_get_seqnum(values));
}

/*
 * Table of function pointers for default access
 */

struct registry_ops regdb_ops = {
	.fetch_subkeys = regdb_fetch_keys,
	.fetch_values = regdb_fetch_values,
	.store_subkeys = regdb_store_keys,
	.store_values = regdb_store_values,
	.create_subkey = regdb_create_subkey,
	.delete_subkey = regdb_delete_subkey,
	.get_secdesc = regdb_get_secdesc,
	.set_secdesc = regdb_set_secdesc,
	.subkeys_need_update = regdb_subkeys_need_update,
	.values_need_update = regdb_values_need_update
};

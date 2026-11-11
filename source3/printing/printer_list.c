/*
   Unix SMB/CIFS implementation.
   Share Database of available printers.
   Copyright (C) Simo Sorce 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/filesys.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "util_tdb.h"
#include "printer_list.h"
#include "librpc/gen_ndr/ndr_printer_list.h"

#define PL_KEY_PREFIX "PRINTERLIST/PRN/"
#define PL_KEY_FORMAT PL_KEY_PREFIX"%s"
#define PL_TIMESTAMP_KEY "PRINTERLIST/GLOBAL/LAST_REFRESH"
/*
 * The formats are printer_list_printer_rec and
 * printer_list_last_refresh_rec, see
 * source3/librpc/idl/printer_list.idl, they must not
 * change as printer_list.tdb is shared by all
 * nodes in a cluster.
 *
 * Older versions used tdb_pack() with "ddPPP" and "dd",
 * like tdb_unpack() additional bytes are ignored.
 */
static bool printer_list_parse(TALLOC_CTX *mem_ctx,
			       TDB_DATA data,
			       struct printer_list_printer_rec *r)
{
	DATA_BLOB blob = data_blob_const(data.dptr, data.dsize);
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, r,
			(ndr_pull_flags_fn_t)ndr_pull_printer_list_printer_rec);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_INFO("ndr_pull_printer_list_printer_rec failed: %s\n",
			 ndr_errstr(ndr_err));
		return false;
	}

	return true;
}

static time_t printer_list_refresh_time(uint32_t time_h, uint32_t time_l)
{
	return (time_t)(((uint64_t)time_h << 32) + time_l);
}

static struct db_context *printerlist_db;

static struct db_context *get_printer_list_db(void)
{
	char *db_path;

	if (printerlist_db != NULL) {
		return printerlist_db;
	}

	db_path = lock_path(talloc_tos(), "printer_list.tdb");
	if (db_path == NULL) {
		return NULL;
	}

	printerlist_db = db_open(NULL,
				 db_path,
				 0,
				 TDB_DEFAULT|TDB_INCOMPATIBLE_HASH,
				 O_RDWR|O_CREAT,
				 0640,
				 DBWRAP_LOCK_ORDER_1,
				 DBWRAP_FLAG_NONE);
	TALLOC_FREE(db_path);
	if (printerlist_db == NULL) {
		DBG_ERR("Failed to open printer_list.tdb\n");
	}
	return printerlist_db;
}

NTSTATUS printer_list_get_printer(TALLOC_CTX *mem_ctx,
				  const char *name,
				  const char **comment,
				  const char **location,
				  time_t *last_refresh)
{
	struct db_context *db;
	char *key;
	TDB_DATA data;
	struct printer_list_printer_rec r = { .refresh_high = 0, };
	NTSTATUS status;
	bool ok;

	db = get_printer_list_db();
	if (db == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	key = talloc_asprintf(mem_ctx, PL_KEY_FORMAT, name);
	if (!key) {
		DEBUG(0, ("Failed to allocate key name!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	status = dbwrap_fetch_bystring_upper(db, key, key, &data);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(6, ("Failed to fetch record! "
			  "The printer database is empty?\n"));
		goto done;
	}

	ok = printer_list_parse(key, data, &r);
	if (!ok) {
		DEBUG(1, ("Failed to unpack printer data\n"));
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto done;
	}

	if (last_refresh) {
		*last_refresh = printer_list_refresh_time(r.refresh_high,
							  r.refresh_low);
	}

	if (comment) {
		*comment = talloc_strdup(mem_ctx, r.comment);
		if (!*comment) {
			DEBUG(1, ("Failed to strdup comment!\n"));
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}

	if (location) {
		*location = talloc_strdup(mem_ctx, r.location);
		if (*location == NULL) {
			DEBUG(1, ("Failed to strdup location!\n"));
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}

	status = NT_STATUS_OK;

done:
	TALLOC_FREE(key);
	return status;
}

bool printer_list_printername_exists(const char *name)
{
	struct db_context *db = get_printer_list_db();
	char *key = NULL;
	bool ok;

	if (db == NULL) {
		return false;
	}

	key = talloc_asprintf_strupper_m(
		talloc_tos(), PL_KEY_FORMAT, name);
	if (key == NULL) {
		return false;
	}

	ok = dbwrap_exists(db, string_term_tdb_data(key));
	TALLOC_FREE(key);
	return ok;
}

NTSTATUS printer_list_set_printer(TALLOC_CTX *mem_ctx,
				  const char *name,
				  const char *comment,
				  const char *location,
				  time_t last_refresh)
{
	struct db_context *db;
	char *key;
	TDB_DATA data;
	uint64_t time_64;
	struct printer_list_printer_rec r;
	DATA_BLOB blob = { .length = 0, };
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	db = get_printer_list_db();
	if (db == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	key = talloc_asprintf(mem_ctx, PL_KEY_FORMAT, name);
	if (!key) {
		DEBUG(0, ("Failed to allocate key name!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (comment == NULL) {
		comment = "";
	}

	if (location == NULL) {
		location = "";
	}

	time_64 = last_refresh;
	r = (struct printer_list_printer_rec) {
		.refresh_high = time_64 >> 32,
		.refresh_low = time_64 & 0xFFFFFFFFL,
		.name = name,
		.comment = comment,
		.location = location,
	};

	ndr_err = ndr_push_struct_blob(&blob, key, &r,
			(ndr_push_flags_fn_t)ndr_push_printer_list_printer_rec);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("Failed to pack printer data: %s\n",
			  ndr_errstr(ndr_err)));
		status = ndr_map_error2ntstatus(ndr_err);
		goto done;
	}
	data = make_tdb_data(blob.data, blob.length);

	status = dbwrap_store_bystring_upper(db, key, data, DBWRAP_REPLACE);

done:
	TALLOC_FREE(key);
	return status;
}

NTSTATUS printer_list_get_last_refresh(time_t *last_refresh)
{
	struct db_context *db;
	TDB_DATA data;
	struct printer_list_last_refresh_rec r = { .refresh_high = 0, };
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	db = get_printer_list_db();
	if (db == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ZERO_STRUCT(data);

	status = dbwrap_fetch_bystring(db, talloc_tos(), PL_TIMESTAMP_KEY, &data);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to fetch record!\n"));
		goto done;
	}

	/* like tdb_unpack() additional bytes are ignored */
	blob = data_blob_const(data.dptr, data.dsize);
	ndr_err = ndr_pull_struct_blob(&blob, talloc_tos(), &r,
		(ndr_pull_flags_fn_t)ndr_pull_printer_list_last_refresh_rec);
	TALLOC_FREE(data.dptr);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("Failed to unpack printer data\n"));
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto done;
	}

	*last_refresh = printer_list_refresh_time(r.refresh_high,
						  r.refresh_low);
	status = NT_STATUS_OK;

done:
	return status;
}

NTSTATUS printer_list_mark_reload(void)
{
	struct db_context *db;
	TDB_DATA data;
	time_t now = time_mono(NULL);
	struct printer_list_last_refresh_rec r = {
		.refresh_high = ((uint64_t)now) >> 32,
		.refresh_low = ((uint64_t)now) & 0xFFFFFFFFL,
	};
	DATA_BLOB blob = { .length = 0, };
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	db = get_printer_list_db();
	if (db == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ndr_err = ndr_push_struct_blob(&blob, talloc_tos(), &r,
		(ndr_push_flags_fn_t)ndr_push_printer_list_last_refresh_rec);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("Failed to pack the last refresh time: %s\n",
			  ndr_errstr(ndr_err)));
		return ndr_map_error2ntstatus(ndr_err);
	}
	data = make_tdb_data(blob.data, blob.length);

	status = dbwrap_store_bystring(db, PL_TIMESTAMP_KEY,
						data, DBWRAP_REPLACE);

	data_blob_free(&blob);
	return status;
}

typedef int (printer_list_trv_fn_t)(struct db_record *, void *);

static NTSTATUS printer_list_traverse(printer_list_trv_fn_t *fn,
				      void *private_data,
				      bool read_only)
{
	struct db_context *db;
	NTSTATUS status;

	db = get_printer_list_db();
	if (db == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (read_only) {
		status = dbwrap_traverse_read(db, fn, private_data, NULL);
	} else {
		status = dbwrap_traverse(db, fn, private_data, NULL);
	}

	return status;
}

struct printer_list_clean_state {
	time_t last_refresh;
	NTSTATUS status;
};

static int printer_list_clean_fn(struct db_record *rec, void *private_data)
{
	struct printer_list_clean_state *state =
			(struct printer_list_clean_state *)private_data;
	TALLOC_CTX *frame = NULL;
	struct printer_list_printer_rec r = { .refresh_high = 0, };
	time_t refresh;
	bool ok;
	TDB_DATA key;
	TDB_DATA value;

	key = dbwrap_record_get_key(rec);

	/* skip anything that does not contain printer_list_printer_rec data */
	if (strncmp((char *)key.dptr,
		    PL_KEY_PREFIX, sizeof(PL_KEY_PREFIX)-1)) {
		return 0;
	}

	value = dbwrap_record_get_value(rec);

	frame = talloc_stackframe();
	ok = printer_list_parse(frame, value, &r);
	if (!ok) {
		DEBUG(1, ("Failed to unpack printer data\n"));
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		TALLOC_FREE(frame);
		return -1;
	}

	refresh = printer_list_refresh_time(r.refresh_high, r.refresh_low);
	TALLOC_FREE(frame);

	if (refresh < state->last_refresh) {
		state->status = dbwrap_record_delete(rec);
		if (!NT_STATUS_IS_OK(state->status)) {
			return -1;
		}
	}

	return 0;
}

NTSTATUS printer_list_clean_old(void)
{
	struct printer_list_clean_state state;
	NTSTATUS status;

	status = printer_list_get_last_refresh(&state.last_refresh);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	state.status = NT_STATUS_OK;

	status = printer_list_traverse(printer_list_clean_fn, &state, false);
	if (NT_STATUS_EQUAL(status, NT_STATUS_UNSUCCESSFUL) &&
	    !NT_STATUS_IS_OK(state.status)) {
		status = state.status;
	}

	return status;
}

struct printer_list_exec_state {
	void (*fn)(const char *, const char *, const char *, void *);
	void *private_data;
	NTSTATUS status;
};

static int printer_list_exec_fn(struct db_record *rec, void *private_data)
{
	struct printer_list_exec_state *state =
			(struct printer_list_exec_state *)private_data;
	TALLOC_CTX *frame = NULL;
	struct printer_list_printer_rec r = { .refresh_high = 0, };
	bool ok;
	TDB_DATA key;
	TDB_DATA value;

	key = dbwrap_record_get_key(rec);

	/* always skip PL_TIMESTAMP_KEY key */
	if (strequal((const char *)key.dptr, PL_TIMESTAMP_KEY)) {
		return 0;
	}

	value = dbwrap_record_get_value(rec);

	frame = talloc_stackframe();
	ok = printer_list_parse(frame, value, &r);
	if (!ok) {
		DEBUG(1, ("Failed to unpack printer data\n"));
		state->status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		TALLOC_FREE(frame);
		return -1;
	}

	state->fn(r.name, r.comment, r.location, state->private_data);

	TALLOC_FREE(frame);
	return 0;
}

NTSTATUS printer_list_read_run_fn(void (*fn)(const char *, const char *, const char *, void *),
				  void *private_data)
{
	struct printer_list_exec_state state;
	NTSTATUS status;

	state.fn = fn;
	state.private_data = private_data;
	state.status = NT_STATUS_OK;

	status = printer_list_traverse(printer_list_exec_fn, &state, true);
	if (NT_STATUS_EQUAL(status, NT_STATUS_UNSUCCESSFUL) &&
	    !NT_STATUS_IS_OK(state.status)) {
		status = state.status;
	}

	return status;
}

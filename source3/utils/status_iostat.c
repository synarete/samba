
// forward declaration to reduce redundant includes
struct share_mode_data;
struct connections_data;

#include "includes.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "vfs_iostat.h"
#include "status_json.h"
#include "status_iostat.h"

static const struct vfs_iostat_dbkey *key_of(const struct db_record *rec)
{
	const TDB_DATA key = dbwrap_record_get_key(rec);
	const struct vfs_iostat_dbkey *dkbey = NULL;

	if (key.dsize == sizeof(*dkbey)) {
		dkbey = (const void *)(key.dptr);
	}
	return dkbey;
}

static const struct vfs_iostat_record *value_of(const struct db_record *rec)
{
	const TDB_DATA val = dbwrap_record_get_value(rec);
	const struct vfs_iostat_record *ios_rec = NULL;

	if (val.dsize > sizeof(*ios_rec)) {
		ios_rec = (const void *)(val.dptr);
	}
	return ios_rec;
}

static int iter_iostat_stdout(struct db_record *db_rec, void *private_data)
{
	const struct vfs_iostat_dbkey *key = key_of(db_rec);
	const struct vfs_iostat_record *rec = value_of(db_rec);

	if ((key == NULL) || (rec == NULL)) {
		goto out;
	}
	d_printf("%-16s %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64
		 " %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 "\n",
		 rec->service,
		 rec->read.count,
		 rec->read.bytes,
		 rec->read.time,
		 rec->write.count,
		 rec->write.bytes,
		 rec->write.time);
out:
	return 0;
}

static int prepare_iostat_dump(struct traverse_state *state)
{
	int ret = 0;

	if (!state->json_output) {
		d_printf("\n%-16s %-12s %-12s %-12s %-12s %-12s %-12s\n",
			 "Service",
			 "RD-Count",
			 "RD-Bytes",
			 "RD-Time",
			 "WR-Count",
			 "WR-Bytes",
			 "WR-Time");
		d_printf("-----------------------------------------------"
			 "-----------------------------------------------\n");
	} else {
		ret = add_section_to_json(state, "iostat");
	}
	return ret;
}

static int traverse_iostat_stdout(struct db_context *db,
				  struct traverse_state *state)
{
	NTSTATUS status;

	status = dbwrap_traverse_read(db, iter_iostat_stdout, state, NULL);
	return NT_STATUS_IS_ERR(status) ? -1 : 0;
}

#ifdef HAVE_JANSSON
struct iostat_traverse_state {
	struct traverse_state *state;
	TALLOC_CTX *mem_ctx;
	struct json_object iostat_jobj;
};

static int iter_iostat_json(struct db_record *db_rec, void *private_data)
{
	struct iostat_traverse_state *istate = private_data;
	const struct vfs_iostat_dbkey *key = key_of(db_rec);
	const struct vfs_iostat_record *rec = value_of(db_rec);
	struct json_object jobj;
	char *str = NULL;
	int ret = 0;

	if ((key == NULL) || (rec == NULL)) {
		return 0;
	}
	jobj = json_new_object();
	if (json_is_invalid(&jobj)) {
		return -1;
	}
	ret = json_add_string(&jobj, "service", rec->service);
	if (ret != 0) {
		goto failure;
	}
	str = talloc_asprintf(istate->mem_ctx, "%" PRIu64, rec->timestamp);
	if (str == NULL) {
		goto failure;
	}
	ret = json_add_string(&jobj, "timestamp", str);
	if (ret != 0) {
		goto failure;
	}
	str = talloc_asprintf(istate->mem_ctx, "%" PRIu64, rec->read.count);
	if (str == NULL) {
		goto failure;
	}
	ret = json_add_string(&jobj, "read_count", str);
	if (ret != 0) {
		goto failure;
	}
	str = talloc_asprintf(istate->mem_ctx, "%" PRIu64, rec->read.bytes);
	if (str == NULL) {
		goto failure;
	}
	ret = json_add_string(&jobj, "read_bytes", str);
	if (ret != 0) {
		goto failure;
	}
	str = talloc_asprintf(istate->mem_ctx, "%" PRIu64, rec->read.time);
	if (str == NULL) {
		goto failure;
	}
	ret = json_add_string(&jobj, "read_time", str);
	if (ret != 0) {
		goto failure;
	}

	str = talloc_asprintf(istate->mem_ctx, "%" PRIu64, rec->write.count);
	if (str == NULL) {
		goto failure;
	}
	ret = json_add_string(&jobj, "write_count", str);
	if (ret != 0) {
		goto failure;
	}
	str = talloc_asprintf(istate->mem_ctx, "%" PRIu64, rec->write.bytes);
	if (str == NULL) {
		goto failure;
	}
	ret = json_add_string(&jobj, "write_bytes", str);
	if (ret != 0) {
		goto failure;
	}
	str = talloc_asprintf(istate->mem_ctx, "%" PRIu64, rec->write.time);
	if (str == NULL) {
		goto failure;
	}
	ret = json_add_string(&jobj, "write_time", str);
	if (ret != 0) {
		goto failure;
	}
	str = talloc_asprintf(istate->mem_ctx,
			      "%" PRIu64 "-%" PRIu64,
			      key->k[0],
			      key->k[1]);
	if (str == NULL) {
		goto failure;
	}
	ret = json_add_object(&istate->iostat_jobj, str, &jobj);
	if (ret != 0) {
		goto failure;
	}
	return 0;
failure:
	json_free(&jobj);
	return -1;
}

static int traverse_iostat_json(struct db_context *db,
				struct traverse_state *state)
{
	struct iostat_traverse_state istate = {
		.state = state,
	};
	NTSTATUS status;
	int ret = 0;

	istate.mem_ctx = talloc_stackframe();
	if (istate.mem_ctx == NULL) {
		return -1;
	}

	istate.iostat_jobj = json_get_object(&state->root_json, "iostat");
	if (json_is_invalid(&istate.iostat_jobj)) {
		goto failure;
	}

	status = dbwrap_traverse_read(db, iter_iostat_json, &istate, NULL);
	if (NT_STATUS_IS_ERR(status) || (ret < 0)) {
		goto failure;
	}

	ret = json_update_object(&state->root_json,
				 "iostat",
				 &istate.iostat_jobj);
	if (ret != 0) {
		goto failure;
	}

	TALLOC_FREE(istate.mem_ctx);
	return 0;
failure:
	TALLOC_FREE(istate.mem_ctx);
	return -1;
}
#endif /* HAVE_JANSSON */

int status_iostat_dump(struct traverse_state *state)
{
	struct db_context *db = NULL;
	char *db_path = NULL;
	int ret = -1;

	db_path = state_path(talloc_tos(), VFS_IOSTAT_TDB_FILE);
	if (db_path == NULL) {
		errno = ENOSYS;
		goto out;
	}

	db = db_open(NULL,
		     db_path,
		     0,
		     TDB_MUTEX_LOCKING,
		     O_RDONLY,
		     0,
		     DBWRAP_LOCK_ORDER_1,
		     DBWRAP_FLAG_NONE);
	if (db == NULL) {
		goto out;
	}

	ret = prepare_iostat_dump(state);
	if (ret != 0) {
		goto out;
	}
#ifdef HAVE_JANSSON
	if (state->json_output) {
		ret = traverse_iostat_json(db, state);
		goto out;
	}
#endif
	ret = traverse_iostat_stdout(db, state);
out:
	TALLOC_FREE(db);
	return ret;
}

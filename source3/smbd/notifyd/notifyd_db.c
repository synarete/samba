/*
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

#include "replace.h"
#include "lib/util/debug.h"
#include "lib/util/server_id_db.h"
#include "lib/util/tevent_ntstatus.h"
#include "librpc/ndr/ndr_messaging.h"
#include "lib/cluster_support.h"
#include "notifyd_private.h"
#include "notifyd_db.h"

struct notifyd_parse_db_state {
	bool (*fn)(const char *path,
		   struct server_id server,
		   const struct notify_instance *instance,
		   void *private_data);
	void *private_data;
};

static bool notifyd_parse_db_parser(TDB_DATA key, TDB_DATA value,
				    void *private_data)
{
	struct notifyd_parse_db_state *state = private_data;
	char path[key.dsize+1];
	struct notifyd_instance *instances = NULL;
	size_t num_instances = 0;
	size_t i;
	bool ok;

	memcpy(path, key.dptr, key.dsize);
	path[key.dsize] = 0;

	ok = notifyd_parse_entry(value.dptr,
				 value.dsize,
				 NULL,
				 &instances,
				 &num_instances);
	if (!ok) {
		DBG_DEBUG("Could not parse entry for path %s\n", path);
		return true;
	}

	for (i=0; i<num_instances; i++) {
		ok = state->fn(path, instances[i].client,
			       &instances[i].instance,
			       state->private_data);
		if (!ok) {
			return false;
		}
	}

	return true;
}

static NTSTATUS notifyd_parse_db(
	const uint8_t *buf,
	size_t buflen,
	uint64_t *log_index,
	bool (*fn)(const char *path,
		   struct server_id server,
		   const struct notify_instance *instance,
		   void *private_data),
	void *private_data)
{
	struct notifyd_parse_db_state state = {
		.fn = fn, .private_data = private_data
	};
	NTSTATUS status;

	if (buflen < 8) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	*log_index = BVAL(buf, 0);

	buf += 8;
	buflen -= 8;

	status = dbwrap_parse_marshall_buf(
		buf, buflen, notifyd_parse_db_parser, &state);
	return status;
}

static NTSTATUS notifyd_parse_db_v1(
	const DATA_BLOB *data,
	uint64_t *log_index,
	bool (*fn)(const char *path,
		   struct server_id server,
		   const struct notify_instance *instance,
		   void *private_data),
	void *private_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_smb_notify_db m = {};
	struct notifyd_parse_db_state state = {
		.fn = fn, .private_data = private_data
	};
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_smb_notify_db_pull(frame, data, &m);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto out;
	}

	*log_index = m.info.info1.rec_index;

	status = dbwrap_parse_marshall_buf(
		m.info.info1.db.data,
		m.info.info1.db.length,
		notifyd_parse_db_parser,
		&state);
out:
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS notifyd_get_db_send_v1(struct messaging_context *msg_ctx,
				       struct server_id dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_smb_notify_get_db m = {};
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ndr_err = messaging_smb_notify_get_db_push(frame, &m, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		goto out;
	}

	status = messaging_send(msg_ctx, dst, MSG_SMB_NOTIFY_GET_DB_V1, &blob);
out:
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS notifyd_get_db_send(struct messaging_context *msg_ctx,
				     struct server_id dst)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return notifyd_get_db_send_v1(msg_ctx, dst);
	}

	return messaging_send_buf(
		msg_ctx, dst, MSG_SMB_NOTIFY_GET_DB, NULL, 0);
}

static NTSTATUS notifyd_parse_db_rec(
	const struct messaging_rec *rec,
	uint64_t *log_index,
	bool (*fn)(const char *path,
		   struct server_id server,
		   const struct notify_instance *instance,
		   void *private_data),
	void *private_data)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return notifyd_parse_db_v1(
			&rec->buf, log_index, fn, private_data);
	}

	return notifyd_parse_db(
		rec->buf.data, rec->buf.length, log_index, fn, private_data);
}

NTSTATUS notify_walk(struct messaging_context *msg_ctx,
		     bool (*fn)(const char *path, struct server_id server,
				const struct notify_instance *instance,
				void *private_data),
		     void *private_data)
{
	struct server_id_db *names_db = NULL;
	struct server_id notifyd = { .pid = 0, };
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	struct messaging_rec *rec = NULL;
	uint64_t log_idx;
	uint32_t resp_type;
	NTSTATUS status;
	int ret;
	bool ok;

	names_db = messaging_names_db(msg_ctx);
	ok = server_id_db_lookup_one(names_db, "notify-daemon", &notifyd);
	if (!ok) {
		DBG_WARNING("No notify daemon around\n");
		return NT_STATUS_SERVER_UNAVAILABLE;
	}

	ev = samba_tevent_context_init(msg_ctx);
	if (ev == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	resp_type = CLUSTER_LEVEL_ACTIVE(2, 0) ?
		MSG_SMB_NOTIFY_DB_V1 : MSG_SMB_NOTIFY_DB;

	req = messaging_read_send(ev, ev, msg_ctx, resp_type);
	if (req == NULL) {
		TALLOC_FREE(ev);
		return NT_STATUS_NO_MEMORY;
	}

	ok = tevent_req_set_endtime(req, ev, timeval_current_ofs(10, 0));
	if (!ok) {
		TALLOC_FREE(ev);
		return NT_STATUS_NO_MEMORY;
	}

	status = notifyd_get_db_send(msg_ctx, notifyd);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("notifyd_get_db_send failed: %s\n",
			  nt_errstr(status));
		TALLOC_FREE(ev);
		return status;
	}

	ok = tevent_req_poll(req, ev);
	if (!ok) {
		DBG_DEBUG("tevent_req_poll failed\n");
		TALLOC_FREE(ev);
		return NT_STATUS_INTERNAL_ERROR;
	}

	ret = messaging_read_recv(req, ev, &rec);
	if (ret != 0) {
		DBG_DEBUG("messaging_read_recv failed: %s\n",
			  strerror(ret));
		TALLOC_FREE(ev);
		return map_nt_error_from_unix(ret);
	}

	status = notifyd_parse_db_rec(rec, &log_idx, fn, private_data);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("notifyd_parse_db failed: %s\n",
			  nt_errstr(status));
		TALLOC_FREE(ev);
		return status;
	}

	TALLOC_FREE(ev);
	return NT_STATUS_OK;
}

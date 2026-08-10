/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Volker Lendecke 2014
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
#include "librpc/gen_ndr/notify.h"
#include "librpc/gen_ndr/messaging.h"
#include "librpc/ndr/ndr_messaging.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_rbt.h"
#include "lib/util/server_id.h"
#include "messages.h"
#include "proto.h"
#include "globals.h"
#include "tdb.h"
#include "util_tdb.h"
#include "lib/util/server_id_db.h"
#include "smbd/notifyd/notifyd.h"

struct notify_context {
	struct server_id notifyd;
	struct messaging_context *msg_ctx;

	struct smbd_server_connection *sconn;
	void (*callback)(struct smbd_server_connection *sconn,
			 void *private_data, struct timespec when,
			 const struct notify_event *ctx);
};

static void notify_handler(struct messaging_context *msg, void *private_data,
			   uint32_t msg_type, struct server_id src,
			   DATA_BLOB *data);
static int notify_context_destructor(struct notify_context *ctx);

struct notify_context *notify_init(
	TALLOC_CTX *mem_ctx, struct messaging_context *msg,
	struct smbd_server_connection *sconn,
	void (*callback)(struct smbd_server_connection *sconn,
			 void *, struct timespec,
			 const struct notify_event *))
{
	struct server_id_db *names_db;
	struct notify_context *ctx;
	NTSTATUS status;

	ctx = talloc(mem_ctx, struct notify_context);
	if (ctx == NULL) {
		return NULL;
	}
	ctx->msg_ctx = msg;

	ctx->sconn = sconn;
	ctx->callback = callback;

	names_db = messaging_names_db(msg);
	if (!server_id_db_lookup_one(names_db, "notify-daemon",
				     &ctx->notifyd)) {
		DBG_WARNING("No notify daemon around\n");
		TALLOC_FREE(ctx);
		return NULL;
	}

	{
		struct server_id_buf tmp;
		DBG_DEBUG("notifyd=%s\n",
			  server_id_str_buf(ctx->notifyd, &tmp));
	}

	if (callback != NULL) {
		status = messaging_register(msg, ctx, MSG_PVFS_NOTIFY,
					    notify_handler);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("messaging_register failed: %s\n",
				    nt_errstr(status));
			TALLOC_FREE(ctx);
			return NULL;
		}
	}

	talloc_set_destructor(ctx, notify_context_destructor);

	return ctx;
}

static int notify_context_destructor(struct notify_context *ctx)
{
	if (ctx->callback != NULL) {
		messaging_deregister(ctx->msg_ctx, MSG_PVFS_NOTIFY, ctx);
	}

	return 0;
}

static void notify_handler(struct messaging_context *msg, void *private_data,
			   uint32_t msg_type, struct server_id src,
			   DATA_BLOB *data)
{
	struct notify_context *ctx = talloc_get_type_abort(
		private_data, struct notify_context);
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_pvfs_notify event_msg = {};
	struct notify_event event;
	struct timespec when;
	enum ndr_err_code ndr_err;

	ndr_err = messaging_pvfs_notify_pull(frame, data, &event_msg);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("messaging_pvfs_notify_pull failed: %s\n",
			    ndr_errstr(ndr_err));
		TALLOC_FREE(frame);
		return;
	}

	event.action = event_msg.action;
	event.path = event_msg.path;
	event.private_data = (void *)(uintptr_t)event_msg.private_data;

	DBG_DEBUG("Got notify_event action=%"PRIu32", private_data=%p, "
		   "path=%s\n",
		  event.action,
		  event.private_data,
		  event.path);

	when.tv_sec = event_msg.when_sec;
	when.tv_nsec = event_msg.when_nsec;

	ctx->callback(ctx->sconn, event.private_data, when, &event);

	TALLOC_FREE(frame);
}

NTSTATUS notify_add(struct notify_context *ctx,
		    const char *path, uint32_t filter, uint32_t subdir_filter,
		    void *private_data)
{
	struct messaging_smb_notify_rec_change msg = {
		.filter = filter,
		.subdir_filter = subdir_filter,
		.private_data = (uint64_t)(uintptr_t)private_data,
		.path = discard_const_p(char, path),
	};
	TALLOC_CTX *frame = NULL;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	if (ctx == NULL) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	DBG_DEBUG("path=[%s], filter=%"PRIu32", subdir_filter=%"PRIu32", "
		  "private_data=%p\n",
		  path,
		  filter,
		  subdir_filter,
		  private_data);

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("sending notify_rec_change to notifyd\n");
		NDR_PRINT_DEBUG(messaging_smb_notify_rec_change, &msg);
	}

	frame = talloc_stackframe();

	ndr_err = messaging_smb_notify_rec_change_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_DEBUG("messaging_smb_notify_rec_change_push failed: %s\n",
			  ndr_errstr(ndr_err));
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_buf(ctx->msg_ctx,
				    ctx->notifyd,
				    MSG_SMB_NOTIFY_REC_CHANGE,
				    blob.data,
				    blob.length);
	TALLOC_FREE(frame);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("messaging_send_buf returned %s\n",
			  nt_errstr(status));
	}

	return status;
}

NTSTATUS notify_remove(struct notify_context *ctx, void *private_data,
		       char *path)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_smb_notify_rec_change msg = {
		.private_data = (uint64_t)(uintptr_t)private_data,
		.path = path,
	};
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status = NT_STATUS_OK;

	/* see if change notify is enabled at all */
	if (ctx == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	ndr_err = messaging_smb_notify_rec_change_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_DEBUG("messaging_smb_notify_rec_change_push failed: %s\n",
			  ndr_errstr(ndr_err));
		goto done;
	}

	status = messaging_send_buf(ctx->msg_ctx,
				    ctx->notifyd,
				    MSG_SMB_NOTIFY_REC_CHANGE,
				    blob.data,
				    blob.length);

done:
	TALLOC_FREE(frame);
	return status;
}

void notify_trigger(struct notify_context *ctx,
		    uint32_t action, uint32_t filter,
		    const char *dir, const char *name)
{
	TALLOC_CTX *frame = NULL;
	struct timespec when;
	char *path = NULL;
	struct messaging_smb_notify_trigger msg;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;

	DBG_DEBUG("notify_trigger called action=0x%"PRIx32", "
		  "filter=0x%"PRIx32", dir=%s, name=%s\n",
		  action,
		  filter,
		  dir,
		  name);

	if (ctx == NULL) {
		return;
	}

	frame = talloc_stackframe();

	when = timespec_current();
	path = talloc_asprintf(frame, "%s/%s", dir, name);
	if (path == NULL) {
		DBG_WARNING("talloc_asprintf failed\n");
		goto done;
	}

	msg = (struct messaging_smb_notify_trigger){
		.when_sec = when.tv_sec,
		.when_nsec = when.tv_nsec,
		.action = action,
		.filter = filter,
		.path = path,
	};

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("sending notify_trigger to notifyd\n");
		NDR_PRINT_DEBUG(messaging_smb_notify_trigger, &msg);
	}

	ndr_err = messaging_smb_notify_trigger_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("messaging_smb_notify_trigger_push failed: %s\n",
			    ndr_errstr(ndr_err));
		goto done;
	}

	messaging_send_buf(ctx->msg_ctx,
			   ctx->notifyd,
			   MSG_SMB_NOTIFY_TRIGGER,
			   blob.data,
			   blob.length);
done:
	TALLOC_FREE(frame);
}

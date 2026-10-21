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
#include "librpc/ndr/ndr_messaging.h"
#include "lib/cluster_support.h"

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
	struct notify_event_msg *event_msg;
	struct notify_event event;

	if (data->length < offsetof(struct notify_event_msg, path) + 1) {
		DBG_WARNING("message too short: %zu\n", data->length);
		return;
	}
	if (data->data[data->length-1] != 0) {
		DBG_WARNING("path not 0-terminated\n");
		return;
	}

	event_msg = (struct notify_event_msg *)data->data;

	event.action = event_msg->action;
	event.path = event_msg->path;
	event.private_data = event_msg->private_data;

	DBG_DEBUG("Got notify_event action=%"PRIu32", private_data=%p, "
		   "path=%s\n",
		  event.action,
		  event.private_data,
		  event.path);

	ctx->callback(ctx->sconn, event.private_data, event_msg->when, &event);
}

static NTSTATUS notify_rec_change_send_v1(struct messaging_context *msg_ctx,
					  struct server_id dst,
					  struct timespec creation_time,
					  uint32_t filter,
					  uint32_t subdir_filter,
					  void *private_data,
					  const char *path)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_smb_notify_rec_change m = {};
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_smb_notify_rec_change_push(frame,
						       &m,
						       creation_time,
						       filter,
						       subdir_filter,
						       private_data,
						       path,
						       &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING(
			"messaging_smb_notify_rec_change_push failed: %s\n",
			ndr_errstr(ndr_err));
		status = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	status = messaging_send(msg_ctx,
				dst,
				MSG_SMB_NOTIFY_REC_CHANGE_V1,
				&blob);
out:
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS notify_rec_change_send(struct messaging_context *msg_ctx,
				       struct server_id dst,
				       struct timespec creation_time,
				       uint32_t filter,
				       uint32_t subdir_filter,
				       void *private_data,
				       const char *path)
{
	struct notify_rec_change_msg msg = {};
	struct iovec iov[2];
	size_t pathlen;
	NTSTATUS status;

	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return notify_rec_change_send_v1(msg_ctx,
						 dst,
						 creation_time,
						 filter,
						 subdir_filter,
						 private_data,
						 path);
	}

	pathlen = strlen(path) + 1;

	msg.instance.creation_time = creation_time;
	msg.instance.filter = filter;
	msg.instance.subdir_filter = subdir_filter;
	msg.instance.private_data = private_data;

	iov[0].iov_base = &msg;
	iov[0].iov_len = offsetof(struct notify_rec_change_msg, path);
	iov[1].iov_base = discard_const_p(char, path);
	iov[1].iov_len = pathlen;

	status = messaging_send_iov(msg_ctx,
				    dst,
				    MSG_SMB_NOTIFY_REC_CHANGE,
				    iov,
				    ARRAY_SIZE(iov),
				    NULL,
				    0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("messaging_send_iov returned %s\n",
			  nt_errstr(status));
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS notify_add(struct notify_context *ctx,
		    const char *path,
		    uint32_t filter,
		    uint32_t subdir_filter,
		    void *private_data)
{
	struct timespec creation_time;

	if (ctx == NULL) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	DBG_DEBUG("path=[%s], filter=%" PRIu32 ", subdir_filter=%" PRIu32 ", "
		  "private_data=%p\n",
		  path,
		  filter,
		  subdir_filter,
		  private_data);

	clock_gettime_mono(&creation_time);
	return notify_rec_change_send(ctx->msg_ctx,
				      ctx->notifyd,
				      creation_time,
				      filter,
				      subdir_filter,
				      private_data,
				      path);
}

NTSTATUS notify_remove(struct notify_context *ctx,
		       void *private_data,
		       char *path)
{
	struct timespec creation_time = {0};

	/* see if change notify is enabled at all */
	if (ctx == NULL) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return notify_rec_change_send(ctx->msg_ctx,
				      ctx->notifyd,
				      creation_time,
				      0,
				      0,
				      private_data,
				      path);
}

static NTSTATUS notify_trigger_send_v1(struct messaging_context *msg_ctx,
				       struct server_id dst,
				       struct timespec when,
				       uint32_t action,
				       uint32_t filter,
				       const char *path)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_smb_notify_trigger m = {};
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_smb_notify_trigger_push(frame,
						    &m,
						    when,
						    action,
						    filter,
						    path,
						    &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("messaging_smb_notify_trigger_push failed: %s\n",
			    ndr_errstr(ndr_err));
		status = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	status = messaging_send(msg_ctx,
				dst,
				MSG_SMB_NOTIFY_TRIGGER_V1,
				&blob);
out:
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS notify_trigger_send(struct messaging_context *msg_ctx,
				    struct server_id dst,
				    struct timespec when,
				    uint32_t action,
				    uint32_t filter,
				    const char *dir,
				    const char *name)
{
	struct notify_trigger_msg msg;
	struct iovec iov[4];
	char slash = '/';
	char *path = NULL;
	NTSTATUS status;

	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		TALLOC_CTX *frame = talloc_stackframe();

		path = talloc_asprintf(frame, "%s/%s", dir, name);
		if (path == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		status = notify_trigger_send_v1(msg_ctx,
						dst,
						when,
						action,
						filter,
						path);
		TALLOC_FREE(frame);
		return status;
	}

	msg.when = when;
	msg.action = action;
	msg.filter = filter;

	iov[0].iov_base = &msg;
	iov[0].iov_len = offsetof(struct notify_trigger_msg, path);
	iov[1].iov_base = discard_const_p(char, dir);
	iov[1].iov_len = strlen(dir);
	iov[2].iov_base = &slash;
	iov[2].iov_len = 1;
	iov[3].iov_base = discard_const_p(char, name);
	iov[3].iov_len = strlen(name)+1;

	return messaging_send_iov(
		msg_ctx, dst, MSG_SMB_NOTIFY_TRIGGER,
		iov, ARRAY_SIZE(iov), NULL, 0);
}

void notify_trigger(struct notify_context *ctx,
		    uint32_t action, uint32_t filter,
		    const char *dir, const char *name)
{
	struct timespec when;

	DBG_DEBUG("notify_trigger called action=0x%"PRIx32", "
		  "filter=0x%"PRIx32", dir=%s, name=%s\n",
		  action,
		  filter,
		  dir,
		  name);

	if (ctx == NULL) {
		return;
	}

	when = timespec_current();
	notify_trigger_send(ctx->msg_ctx, ctx->notifyd, when, action, filter,
			    dir, name);
}

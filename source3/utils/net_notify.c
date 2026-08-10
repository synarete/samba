/*
 * Samba Unix/Linux notifyd client code
 * Copyright (C) 2015 Volker Lendecke <vl@samba.org>
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
#include "utils/net.h"
#include "lib/util/server_id.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/server_id_db.h"
#include "messages.h"
#include "source3/smbd/notifyd/notifyd.h"
#include "librpc/ndr/ndr_messaging.h"

static void net_notify_got_event(struct messaging_context *msg,
				 void *private_data,
				 uint32_t msg_type,
				 struct server_id server_id,
				 DATA_BLOB *data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_pvfs_notify event_msg = {};
	enum ndr_err_code ndr_err;

	ndr_err = messaging_pvfs_notify_pull(frame, data, &event_msg);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		d_fprintf(stderr,
			  "messaging_pvfs_notify_pull failed: %s\n",
			  ndr_errstr(ndr_err));
		TALLOC_FREE(frame);
		return;
	}

	d_printf("%u %s\n", (unsigned)event_msg.action, event_msg.path);

	TALLOC_FREE(frame);
}

static int net_notify_listen(struct net_context *c, int argc,
			     const char **argv)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_context *msg_ctx = c->msg_ctx;
	struct tevent_context *ev = messaging_tevent_context(msg_ctx);
	struct server_id_db *names_db = messaging_names_db(msg_ctx);
	struct server_id notifyd;
	struct server_id_buf idbuf;
	struct messaging_smb_notify_rec_change msg;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	bool ok;
	int ret = -1;

	if (argc != 3) {
		d_printf("Usage: net notify listen <path> <filter> "
			 "<subdir-filter>\n");
		goto done;
	}

	ok = server_id_db_lookup_one(names_db, "notify-daemon", &notifyd);
	if (!ok) {
		fprintf(stderr, "no notify daemon found\n");
		goto done;
	}

	printf("notify daemon: %s\n", server_id_str_buf(notifyd, &idbuf));

	msg = (struct messaging_smb_notify_rec_change){
		.filter = atoi(argv[1]),
		.subdir_filter = atoi(argv[2]),
		.path = discard_const_p(char, argv[0])};

	status = messaging_register(c->msg_ctx, NULL, MSG_PVFS_NOTIFY,
				    net_notify_got_event);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "messaging_register failed: %s\n",
			  nt_errstr(status));
		goto done;
	}

	ndr_err = messaging_smb_notify_rec_change_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		d_fprintf(stderr,
			  "messaging_smb_notify_rec_change_push failed: %s\n",
			  ndr_errstr(ndr_err));
		goto done;
	}

	status = messaging_send_buf(c->msg_ctx,
				    notifyd,
				    MSG_SMB_NOTIFY_REC_CHANGE,
				    blob.data,
				    blob.length);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Sending rec_change to %s returned %s\n",
			  server_id_str_buf(notifyd, &idbuf),
			  nt_errstr(status));
		goto done;
	}

	ret = 0;
	while (true) {
		int loop_ret;

		loop_ret = tevent_loop_once(ev);
		if (loop_ret != 0) {
			d_fprintf(stderr, "tevent_loop_once failed: %s\n",
				  strerror(errno));
			break;
		}
	}

done:
	TALLOC_FREE(frame);
	return ret;
}

static int net_notify_trigger(struct net_context *c, int argc,
			      const char **argv)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_context *msg_ctx = c->msg_ctx;
	struct server_id_db *names_db = messaging_names_db(msg_ctx);
	struct server_id notifyd;
	struct server_id_buf idbuf;
	struct messaging_smb_notify_trigger msg;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	bool ok;
	int ret = -1;

	if (argc != 3) {
		d_printf("Usage: net notify trigger <path> <action> "
			 "<filter>\n");
		goto done;
	}

	ok = server_id_db_lookup_one(names_db, "notify-daemon", &notifyd);
	if (!ok) {
		fprintf(stderr, "no notify daemon found\n");
		goto done;
	}

	printf("notify daemon: %s\n", server_id_str_buf(notifyd, &idbuf));

	msg = (struct messaging_smb_notify_trigger){
		.action = atoi(argv[1]),
		.filter = atoi(argv[2]),
		.path = discard_const_p(char, argv[0]),
	};

	ndr_err = messaging_smb_notify_trigger_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		d_fprintf(stderr,
			  "messaging_smb_notify_trigger_push failed: %s\n",
			  ndr_errstr(ndr_err));
		goto done;
	}

	status = messaging_send_buf(c->msg_ctx,
				    notifyd,
				    MSG_SMB_NOTIFY_TRIGGER,
				    blob.data,
				    blob.length);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr,
			  "Sending trigger to %s returned %s\n",
			  server_id_str_buf(notifyd, &idbuf),
			  nt_errstr(status));
		goto done;
	}

	ret = 0;
done:
	TALLOC_FREE(frame);
	return ret;
}

int net_notify(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{ "listen",
		  net_notify_listen,
		  NET_TRANSPORT_LOCAL,
		  N_("Register for a path and listen for changes"),
		  N_("net notify listen <path>")
		},
		{ "trigger",
		  net_notify_trigger,
		  NET_TRANSPORT_LOCAL,
		  N_("Simulate a trigger action"),
		  N_("net notify trigger <path> <action> <filter>")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	if (c->msg_ctx == NULL) {
		d_fprintf(stderr, "No connection to messaging, need to run "
			  "as root\n");
		return -1;
	}

	return net_run_function(c, argc, argv, "net notify", func);
}

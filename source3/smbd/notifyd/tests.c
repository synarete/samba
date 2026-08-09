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

#include "replace.h"
#include "notifyd.h"
#include "messages.h"
#include "lib/util/server_id_db.h"
#include "librpc/ndr/ndr_messaging.h"

int main(int argc, const char *argv[])
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	struct server_id_db *names;
	struct server_id notifyd;
	struct tevent_req *req;
	struct messaging_ping ping = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	unsigned i;
	bool ok;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <smb.conf-file>\n", argv[0]);
		exit(1);
	}

	setup_logging(argv[0], DEBUG_STDOUT);
	lp_load_global(argv[1]);

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		exit(1);
	}

	msg_ctx = messaging_init(ev, ev);
	if (msg_ctx == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		exit(1);
	}

	names = messaging_names_db(msg_ctx);

	ok = server_id_db_lookup_one(names, "notify-daemon", &notifyd);
	if (!ok) {
		fprintf(stderr, "no notifyd\n");
		exit(1);
	}

	for (i=0; i<50000; i++) {
		TALLOC_CTX *loop_frame = talloc_stackframe();
		struct messaging_smb_notify_rec_change msg;
		char path[64];
		DATA_BLOB msg_blob;
		enum ndr_err_code send_ndr_err;
		NTSTATUS status;

		snprintf(path, sizeof(path), "/tmp%u", i);

		msg = (struct messaging_smb_notify_rec_change){
			.filter = UINT32_MAX,
			.subdir_filter = UINT32_MAX,
			.path = path};

		send_ndr_err = messaging_smb_notify_rec_change_push(loop_frame,
								    &msg,
								    &msg_blob);
		if (!NDR_ERR_CODE_IS_SUCCESS(send_ndr_err)) {
			fprintf(stderr,
				"messaging_smb_notify_rec_change_push "
				"returned %s\n",
				ndr_errstr(send_ndr_err));
			exit(1);
		}

		status = messaging_send_buf(msg_ctx,
					    notifyd,
					    MSG_SMB_NOTIFY_REC_CHANGE,
					    msg_blob.data,
					    msg_blob.length);
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr,
				"messaging_send_buf returned %s\n",
				nt_errstr(status));
			exit(1);
		}

		msg.filter = 0;
		msg.subdir_filter = 0;

		send_ndr_err = messaging_smb_notify_rec_change_push(loop_frame,
								    &msg,
								    &msg_blob);
		if (!NDR_ERR_CODE_IS_SUCCESS(send_ndr_err)) {
			fprintf(stderr,
				"messaging_smb_notify_rec_change_push "
				"returned %s\n",
				ndr_errstr(send_ndr_err));
			exit(1);
		}

		status = messaging_send_buf(msg_ctx,
					    notifyd,
					    MSG_SMB_NOTIFY_REC_CHANGE,
					    msg_blob.data,
					    msg_blob.length);
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr,
				"messaging_send_buf returned %s\n",
				nt_errstr(status));
			exit(1);
		}

		TALLOC_FREE(loop_frame);
	}

	req = messaging_read_send(ev, ev, msg_ctx, MSG_PONG);
	if (req == NULL) {
		fprintf(stderr, "messaging_read_send failed\n");
		exit(1);
	}

	ndr_err = messaging_ping_push(frame, &ping, "", &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		fprintf(stderr, "messaging_ping_push failed\n");
		exit(1);
	}
	messaging_send_buf(msg_ctx, notifyd, MSG_PING, blob.data, blob.length);

	ok = tevent_req_poll(req, ev);
	if (!ok) {
		fprintf(stderr, "tevent_req_poll failed\n");
		exit(1);
	}

	TALLOC_FREE(frame);
	return 0;
}

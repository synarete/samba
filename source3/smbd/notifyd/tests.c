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
		struct messaging_smb_notify_rec_change rec_msg = {};
		char path[64];
		DATA_BLOB blob_rec = data_blob_null;
		NTSTATUS status;

		snprintf(path, sizeof(path), "/tmp%u", i);

		ndr_err = messaging_smb_notify_rec_change_push(
			frame,
			&rec_msg,
			(struct timespec){0},
			UINT32_MAX,
			UINT32_MAX,
			NULL,
			path,
			&blob_rec);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			fprintf(stderr,
				"messaging_smb_notify_rec_change_push "
				"failed\n");
			exit(1);
		}

		status = messaging_send(msg_ctx,
					notifyd,
					MSG_SMB_NOTIFY_REC_CHANGE_V1,
					&blob_rec);
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr,
				"messaging_send returned %s\n",
				nt_errstr(status));
			exit(1);
		}

		ndr_err = messaging_smb_notify_rec_change_push(
			frame,
			&rec_msg,
			(struct timespec){0},
			0,
			0,
			NULL,
			path,
			&blob_rec);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			fprintf(stderr,
				"messaging_smb_notify_rec_change_push "
				"failed\n");
			exit(1);
		}

		status = messaging_send(msg_ctx,
					notifyd,
					MSG_SMB_NOTIFY_REC_CHANGE_V1,
					&blob_rec);
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr,
				"messaging_send returned %s\n",
				nt_errstr(status));
			exit(1);
		}
	}

	req = messaging_read_send(ev, ev, msg_ctx, MSG_PONG_V1);
	if (req == NULL) {
		fprintf(stderr, "messaging_read_send failed\n");
		exit(1);
	}

	ndr_err = messaging_ping_push(frame, &ping, "", &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		fprintf(stderr, "messaging_ping_v1_push failed\n");
		exit(1);
	}
	messaging_send_buf(
		msg_ctx, notifyd, MSG_PING_V1, blob.data, blob.length);

	ok = tevent_req_poll(req, ev);
	if (!ok) {
		fprintf(stderr, "tevent_req_poll failed\n");
		exit(1);
	}

	TALLOC_FREE(frame);
	return 0;
}

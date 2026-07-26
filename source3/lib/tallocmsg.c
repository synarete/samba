/* 
   samba -- Unix SMB/CIFS implementation.
   Copyright (C) 2001, 2002 by Martin Pool

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

#include "replace.h"
#include "lib/util/talloc_stack.h"
#include "source3/include/messages.h"
#include "source3/lib/tallocmsg.h"
#include "lib/util/talloc_report_printf.h"
#include "lib/util/debug.h"
#include "lib/util/util_file.h"
#include "librpc/ndr/ndr_messaging.h"

static bool pool_usage_filter(struct messaging_rec *rec, void *private_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_req_pool_usage req = {};
	enum ndr_err_code ndr_err;
	FILE *f = NULL;

	if (rec->msg_type != MSG_REQ_POOL_USAGE) {
		TALLOC_FREE(frame);
		return false;
	}

	DBG_DEBUG("Got MSG_REQ_POOL_USAGE\n");

	ndr_err = messaging_req_pool_usage_pull(frame, &rec->buf, &req);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_DEBUG("Invalid req_pool_usage message: %s\n",
			  ndr_errstr(ndr_err));
		TALLOC_FREE(frame);
		return false;
	}

	if (rec->num_fds != 1) {
		DBG_DEBUG("Got %"PRIu8" fds, expected one\n", rec->num_fds);
		TALLOC_FREE(frame);
		return false;
	}

	f = fdopen_keepfd(rec->fds[0], "w");
	if (f == NULL) {
		DBG_DEBUG("fdopen failed: %s\n", strerror(errno));
		TALLOC_FREE(frame);
		return false;
	}

	talloc_full_report_printf(NULL, f);

	fclose(f);
	TALLOC_FREE(frame);
	/*
	 * Returning false, means messaging_dispatch_waiters()
	 * won't call messaging_filtered_read_done() and
	 * our messaging_filtered_read_send() stays alive
	 * and will get messages.
	 */
	return false;
}

/**
 * Register handler for MSG_REQ_POOL_USAGE
 **/
void register_msg_pool_usage(
	TALLOC_CTX *mem_ctx, struct messaging_context *msg_ctx)
{
	struct tevent_req *req = NULL;

	req = messaging_filtered_read_send(
		mem_ctx,
		messaging_tevent_context(msg_ctx),
		msg_ctx,
		pool_usage_filter,
		NULL);
	if (req == NULL) {
		DBG_WARNING("messaging_filtered_read_send failed\n");
		return;
	}
	DBG_INFO("Registered MSG_REQ_POOL_USAGE\n");
}

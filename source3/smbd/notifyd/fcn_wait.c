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
#include "fcn_wait.h"
#include "notifyd.h"
#include "lib/util/tevent_ntstatus.h"

struct fcn_event {
	struct fcn_event *prev, *next;
	struct notify_event_msg msg;
};

struct fcn_wait_state {
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	struct server_id notifyd;
	const char *path;

	struct tevent_req *recv_subreq;

	struct fcn_event *events;
};

static bool fcn_wait_cancel(struct tevent_req *req);
static void fcn_wait_cleanup(
	struct tevent_req *req, enum tevent_req_state req_state);
static bool fcn_wait_filter(struct messaging_rec *rec, void *private_data);
static void fcn_wait_done(struct tevent_req *subreq);

struct tevent_req *fcn_wait_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct messaging_context *msg_ctx,
	struct server_id notifyd,
	const char *path,
	uint32_t filter,
	uint32_t subdir_filter)
{
	struct tevent_req *req = NULL;
	struct fcn_wait_state *state = NULL;
	struct notify_instance instance = {
		.filter = filter,
		.subdir_filter = subdir_filter,
	};
	uint8_t hdr[NOTIFY_REC_CHANGE_HDR_SIZE];
	size_t hdr_len;
	uint32_t msg_type;
	struct iovec iov[2];
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct fcn_wait_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->msg_ctx = msg_ctx;
	state->notifyd = notifyd;
	state->path = path;

	state->recv_subreq = messaging_filtered_read_send(
		state, ev, msg_ctx, fcn_wait_filter, req);
	if (tevent_req_nomem(state->recv_subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->recv_subreq, fcn_wait_done, req);
	tevent_req_set_cleanup_fn(req, fcn_wait_cleanup);

	clock_gettime_mono(&instance.creation_time);
	instance.private_data = state;

	msg_type = notify_rec_change_msg_push_hdr(&instance, hdr, &hdr_len);

	iov[0].iov_base = hdr;
	iov[0].iov_len = hdr_len;
	iov[1].iov_base = discard_const_p(char, path);
	iov[1].iov_len = strlen(path)+1;

	status = messaging_send_iov(
		msg_ctx,			/* msg_ctx */
		notifyd,			/* dst */
		msg_type,			/* mst_type */
		iov,				/* iov */
		ARRAY_SIZE(iov),		/* iovlen */
		NULL,				/* fds */
		0);				/* num_fds */
	if (tevent_req_nterror(req, status)) {
		DBG_DEBUG("messaging_send_iov failed: %s\n",
			  nt_errstr(status));
		return tevent_req_post(req, ev);
	}
	tevent_req_set_cancel_fn(req, fcn_wait_cancel);

	return req;
}

static bool fcn_wait_cancel(struct tevent_req *req)
{
	struct fcn_wait_state *state = tevent_req_data(
		req, struct fcn_wait_state);
	struct notify_instance instance = {
		.filter = 0, /* filter==0 is a delete msg */
		.subdir_filter = 0,
	};
	uint8_t hdr[NOTIFY_REC_CHANGE_HDR_SIZE];
	size_t hdr_len;
	uint32_t msg_type;
	struct iovec iov[2];
	NTSTATUS status;

	clock_gettime_mono(&instance.creation_time);
	instance.private_data = state;

	msg_type = notify_rec_change_msg_push_hdr(&instance, hdr, &hdr_len);

	iov[0].iov_base = hdr;
	iov[0].iov_len = hdr_len;
	iov[1].iov_base = discard_const_p(char, state->path);
	iov[1].iov_len = strlen(state->path)+1;

	status = messaging_send_iov(
		state->msg_ctx,			/* msg_ctx */
		state->notifyd,			/* dst */
		msg_type,			/* mst_type */
		iov,				/* iov */
		ARRAY_SIZE(iov),		/* iovlen */
		NULL,				/* fds */
		0);				/* num_fds */
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("messaging_send_iov failed: %s\n",
			  nt_errstr(status));
		return false;
	}

	fcn_wait_cleanup(req, 0); /* fcn_wait_cleanup ignores req_state */
	tevent_req_defer_callback(req, state->ev);
	tevent_req_nterror(req, NT_STATUS_CANCELLED);

	return true;
}

static void fcn_wait_cleanup(
	struct tevent_req *req, enum tevent_req_state req_state)
{
	struct fcn_wait_state *state = tevent_req_data(
		req, struct fcn_wait_state);
	TALLOC_FREE(state->recv_subreq);
}

static bool fcn_wait_filter(struct messaging_rec *rec, void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct fcn_wait_state *state = tevent_req_data(
		req, struct fcn_wait_state);
	struct notify_event_msg msg = { .action = 0 };
	struct fcn_event *evt = NULL;
	bool ok;

	if (rec->msg_type != MSG_PVFS_NOTIFY &&
	    rec->msg_type != MSG_PVFS_NOTIFY_LE)
	{
		DBG_DEBUG("Ignoring msg %"PRIu32"\n", rec->msg_type);
		return false;
	}

	ok = notify_event_msg_parse(rec->msg_type,
				    rec->buf.data,
				    rec->buf.length,
				    &msg);
	if (!ok) {
		DBG_DEBUG("Ignoring invalid (%zu) msg\n", rec->buf.length);
		return false;
	}

	if (msg.private_data != state) {
		DBG_DEBUG("Got private_data=%p, expected %p\n",
			  msg.private_data,
			  state);
		return false;
	}

	evt = talloc_zero(state, struct fcn_event);
	if (evt == NULL) {
		DBG_DEBUG("talloc_zero failed\n");
		return false;
	}
	evt->msg = msg;
	evt->msg.path = talloc_strdup(evt, msg.path);
	if (evt->msg.path == NULL) {
		DBG_DEBUG("talloc_strdup failed\n");
		TALLOC_FREE(evt);
		return false;
	}

	/*
	 * TODO: Sort by timestamp
	 */

	DLIST_ADD_END(state->events, evt);

	tevent_req_defer_callback(req, state->ev);
	tevent_req_notify_callback(req);

	return false;
}

static void fcn_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;

	ret = messaging_filtered_read_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		DBG_DEBUG("messaging_filtered_read failed: %s\n",
			  strerror(ret));
		tevent_req_nterror(req, map_nt_error_from_unix(ret));
		return;
	}

	/*
	 * We should never have gotten here, all work is done from the
	 * filter function.
	 */
	tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
}

NTSTATUS fcn_wait_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct timespec *when,
	uint32_t *action,
	char **path)
{
	struct fcn_wait_state *state = tevent_req_data(
		req, struct fcn_wait_state);
	struct fcn_event *evt = NULL;
	NTSTATUS status;

	if (!tevent_req_is_in_progress(req) &&
	    tevent_req_is_nterror(req, &status)) {
		return status;
	}
	evt = state->events;
	if (evt == NULL) {
		return NT_STATUS_RETRY;
	}

	if (path != NULL) {
		*path = talloc_strdup(mem_ctx, evt->msg.path);
		if ((*path) == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	if (when != NULL) {
		*when = evt->msg.when;
	}
	if (action != NULL) {
		*action = evt->msg.action;
	}

	DLIST_REMOVE(state->events, evt);
	TALLOC_FREE(evt);

	if (state->events != NULL) {
		tevent_req_defer_callback(req, state->ev);
		tevent_req_notify_callback(req);
	}

	return NT_STATUS_OK;
}

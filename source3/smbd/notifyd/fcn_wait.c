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
#include "librpc/ndr/ndr_messaging.h"
#include "lib/cluster_support.h"
#include "source3/include/messages_send.h"

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

static NTSTATUS fcn_wait_send_rec_change(struct messaging_context *msg_ctx,
					 struct server_id notifyd,
					 struct timespec creation_time,
					 uint32_t filter,
					 uint32_t subdir_filter,
					 void *private_data,
					 const char *path)
{
	return messaging_send_notify_rec_change(msg_ctx,
						notifyd,
						creation_time,
						filter,
						subdir_filter,
						private_data,
						path);
}

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
	struct timespec creation_time;
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

	clock_gettime_mono(&creation_time);
	status = fcn_wait_send_rec_change(msg_ctx,
					  notifyd,
					  creation_time,
					  filter,
					  subdir_filter,
					  state,
					  path);
	if (tevent_req_nterror(req, status)) {
		DBG_DEBUG("fcn_wait_send_rec_change failed: %s\n",
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
	struct timespec creation_time;
	NTSTATUS status;

	clock_gettime_mono(&creation_time);
	status = fcn_wait_send_rec_change(state->msg_ctx,
					  state->notifyd,
					  creation_time,
					  0,
					  0,
					  state,
					  state->path);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("fcn_wait_send_rec_change failed: %s\n",
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

	if (rec->msg_type != MSG_PVFS_NOTIFY) {
		DBG_DEBUG("Ignoring msg %"PRIu32"\n", rec->msg_type);
		return false;
	}

	/*
	 * We need at least the trailing '\0' for the path
	 */
	if (rec->buf.length < (offsetof(struct notify_event_msg, path) + 1)) {
		DBG_DEBUG("Ignoring short (%zu) msg\n", rec->buf.length);
		return false;
	}
	if (rec->buf.data[rec->buf.length-1] != '\0') {
		DBG_DEBUG("Expected 0-terminated path\n");
		return false;
	}

	memcpy(&msg, rec->buf.data, sizeof(msg));

	if (msg.private_data != state) {
		DBG_DEBUG("Got private_data=%p, expected %p\n",
			  msg.private_data,
			  state);
		return false;
	}

	evt = talloc_memdup(state, rec->buf.data, rec->buf.length);
	if (evt == NULL) {
		DBG_DEBUG("talloc_memdup failed\n");
		return false;
	}
	talloc_set_name_const(evt, "struct fcn_event");

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

	if (state->events != NULL) {
		tevent_req_defer_callback(req, state->ev);
		tevent_req_notify_callback(req);
	}

	return NT_STATUS_OK;
}

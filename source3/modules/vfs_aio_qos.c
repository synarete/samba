/*
 * Quality-of-service (QoS) as a stackable Samba module.
 *
 * Copyright (c) 2025 Shachar sharon <ssharon@redhat.com>
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "lib/util/time.h"
#include "lib/util/tevent_unix.h"

/* Delay values for IOPS/BYTES overflow, in milliseconds */
#define DELAY_DEFAULT (1000)
#define DELAY_MAX (30000)

/* Token bucket-based rate limiter */
struct ratelimiter {
	struct timespec timestamp;
	uint64_t iops_limit;
	uint64_t iops_curr;
	uint64_t bytes_limit;
	uint64_t bytes_curr;
	uint32_t msec_delay;
	bool write;
};

/* In-memory QoS entry per connection */
struct aio_qos_config {
	struct ratelimiter rd_ratelimiter;
	struct ratelimiter wr_ratelimiter;
	int snum;
};

static void timestamp_now(struct timespec *ts)
{
	clock_gettime_mono(ts);
}

static void ratelimiter_init(struct ratelimiter *rl,
			     uint64_t iops_limit,
			     uint64_t bytes_limit,
			     uint64_t msec_delay,
			     bool write)
{
	ZERO_STRUCTP(rl);
	rl->iops_limit = iops_limit;
	rl->bytes_limit = bytes_limit;
	rl->iops_curr = 0;
	rl->bytes_curr = 0;
	rl->msec_delay = (uint32_t)MIN(msec_delay, DELAY_MAX);
	rl->write = write;
}

static uint32_t ratelimiter_delay(const struct ratelimiter *rl)
{
	/* IOPS overflow */
	if ((rl->iops_limit > 0) && (rl->iops_curr > rl->iops_limit)) {
		return rl->msec_delay;
	}
	/* Bytes-per-second overflow */
	if ((rl->bytes_limit > 0) && (rl->bytes_curr > rl->bytes_limit)) {
		return rl->msec_delay;
	}
	return 0;
}

static void ratelimiter_update(struct ratelimiter *rl, size_t bytes)
{
	struct timespec ts;

	timestamp_now(&ts);
	if ((rl->iops_curr == 0) || (rl->timestamp.tv_sec != ts.tv_sec)) {
		/* first time or new 1-sec cycle */
		rl->iops_curr = 1;
		rl->bytes_curr = bytes;
		rl->timestamp = ts;
	} else {
		/* update within current 1-sec slot */
		rl->iops_curr++;
		rl->bytes_curr += bytes;
	}
}

static struct ratelimiter *aio_qos_ratelimiter_of(
	struct vfs_handle_struct *handle,
	bool write)
{
	struct aio_qos_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct aio_qos_config,
				return NULL);

	return write ? &config->wr_ratelimiter : &config->rd_ratelimiter;
}

static unsigned long aio_qos_lp_parm(const struct aio_qos_config *config,
				     const char *option,
				     unsigned long def)
{
	return lp_parm_ulong(config->snum, "aio_qos", option, def);
}

static void aio_qos_setup_ratelimiters(struct aio_qos_config *config)
{
	unsigned long iops, bytes, delay;

	iops = aio_qos_lp_parm(config, "read_iops_limit", 0);
	bytes = aio_qos_lp_parm(config, "read_bw_limit", 0);
	delay = aio_qos_lp_parm(config, "read_msec_delay", DELAY_DEFAULT);
	ratelimiter_init(&config->rd_ratelimiter, iops, bytes, delay, false);
	DBG_DEBUG("[QOS] init read-ratelimiter: iops=%" PRIu64 " bytes=%" PRIu64
		  " delay=%" PRIu64 "\n",
		  iops,
		  bytes,
		  delay);

	iops = aio_qos_lp_parm(config, "write_iops_limit", 0);
	bytes = aio_qos_lp_parm(config, "write_bw_limit", 0);
	delay = aio_qos_lp_parm(config, "write_msec_delay", DELAY_DEFAULT);
	ratelimiter_init(&config->wr_ratelimiter, iops, bytes, delay, true);
	DBG_DEBUG("[QOS] init write-ratelimiter: iops=%" PRIu64
		  " bytes=%" PRIu64 " delay=%" PRIu64 "\n",
		  iops,
		  bytes,
		  delay);
}

static void aio_qos_free_config(void **ptr)
{
	TALLOC_FREE(*ptr);
}

static int
aio_qos_new_config(struct vfs_handle_struct *handle)
{
	struct aio_qos_config *config = NULL;

	config = talloc_zero(handle->conn, struct aio_qos_config);
	if (config == NULL) {
		return -1;
	}
	config->snum = SNUM(handle->conn);
	aio_qos_setup_ratelimiters(config);

	SMB_VFS_HANDLE_SET_DATA(handle,
				config,
				aio_qos_free_config,
				struct aio_qos_config,
				return -1);
	return 0;
}

static int aio_qos_connect(struct vfs_handle_struct *handle,
			   const char *service,
			   const char *user)
{
	int ret;

	DBG_INFO("[QOS] connect: service=%s snum=%d\n",
		 service,
		 SNUM(handle->conn));
	ret = aio_qos_new_config(handle);
	if (ret != 0) {
		return ret;
	}

	return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static void aio_qos_disconnect(struct vfs_handle_struct *handle)
{
	DBG_INFO("[QOS] disconnect: snum=%d\n", SNUM(handle->conn));
	SMB_VFS_NEXT_DISCONNECT(handle);
	SMB_VFS_HANDLE_FREE_DATA(handle);
}

struct aio_qos_state {
	struct vfs_aio_state vfs_aio_state;
	struct ratelimiter *rl;
	struct tevent_context *ev;
	struct tevent_req *req;
	ssize_t result;
};

static void aio_qos_setup_state(struct aio_qos_state *state,
				struct vfs_handle_struct *handle,
				struct tevent_context *ev,
				struct tevent_req *req,
				size_t bytes,
				bool write)
{
	state->ev = ev;
	state->req = req;
	state->rl = aio_qos_ratelimiter_of(handle, write);
	state->result = 0;
}

static uint32_t aio_qos_post(struct aio_qos_state *state)
{
	uint32_t msec_delay = 0;

	if ((state->rl != NULL) && (state->result > 0)) {
		ratelimiter_update(state->rl, (size_t)state->result);
		msec_delay = ratelimiter_delay(state->rl);
	}
	return msec_delay;
}

static struct timeval aio_qos_delay_tv(uint32_t delay_msec)
{
	const uint32_t secs = delay_msec / 1000;
	const uint32_t usecs = (delay_msec * 1000) % 1000000;

	return timeval_current_ofs(secs, usecs);
}

static void aio_qos_pread_done(struct tevent_req *subreq);

static struct tevent_req *aio_qos_pread_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp,
					     void *data,
					     size_t n,
					     off_t off)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct aio_qos_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct aio_qos_state);
	if (req == NULL) {
		return NULL;
	}
	aio_qos_setup_state(state, handle, ev, req, n, false);

	subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp, data, n, off);
	if (tevent_req_nomem(req, subreq)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, aio_qos_pread_done, req);
	return req;
}

static void aio_qos_done(struct aio_qos_state *state)
{
	struct tevent_req *req = state->req;

	if (state->result == -1) {
		tevent_req_error(req, state->vfs_aio_state.error);
		return;
	}

	tevent_req_done(req);
}

static void aio_qos_done_delayed(struct tevent_context *ev,
				 struct tevent_timer *te,
				 struct timeval current_time,
				 void *private_data)
{
	struct aio_qos_state *state = talloc_get_type_abort(
		private_data, struct aio_qos_state);

	aio_qos_done(state);
}

static void aio_qos_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct aio_qos_state *state = tevent_req_data(req,
						      struct aio_qos_state);
	uint32_t delay_msec = 0;

	state->result = SMB_VFS_NEXT_PREAD_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	delay_msec = aio_qos_post(state);
	if (delay_msec > 0) {
		tevent_add_timer(state->ev,
				 state->req,
				 aio_qos_delay_tv(delay_msec),
				 aio_qos_done_delayed,
				 state);
		return;
	}
	aio_qos_done(state);
}

static ssize_t aio_qos_pread_recv(struct tevent_req *req,
				  struct vfs_aio_state *vfs_aio_state)
{
	struct aio_qos_state *state = tevent_req_data(req,
						      struct aio_qos_state);
	ssize_t result = -1;

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	result = state->result;
	tevent_req_received(req);
	return result;
}

static void aio_qos_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *aio_qos_pwrite_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      const void *data,
					      size_t n,
					      off_t off)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct aio_qos_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct aio_qos_state);
	if (req == NULL) {
		return NULL;
	}
	aio_qos_setup_state(state, handle, ev, req, n, true);

	subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp, data, n, off);
	if (tevent_req_nomem(req, subreq)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, aio_qos_pwrite_done, req);
	return req;
}

static void aio_qos_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct aio_qos_state *state = tevent_req_data(req,
						      struct aio_qos_state);
	uint32_t delay_msec = 0;

	state->result = SMB_VFS_NEXT_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	delay_msec = aio_qos_post(state);
	if (delay_msec > 0) {
		tevent_add_timer(state->ev,
				 state->req,
				 aio_qos_delay_tv(delay_msec),
				 aio_qos_done_delayed,
				 state);
		return;
	}
	aio_qos_done(state);
}

static ssize_t aio_qos_pwrite_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct aio_qos_state *state = tevent_req_data(req,
						      struct aio_qos_state);
	ssize_t result = -1;

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	result = state->result;
	tevent_req_received(req);
	return result;
}

static struct vfs_fn_pointers vfs_aio_qos_fns = {
	.connect_fn = aio_qos_connect,
	.disconnect_fn = aio_qos_disconnect,
	.pread_send_fn = aio_qos_pread_send,
	.pread_recv_fn = aio_qos_pread_recv,
	.pwrite_send_fn = aio_qos_pwrite_send,
	.pwrite_recv_fn = aio_qos_pwrite_recv,
};

static_decl_vfs;
NTSTATUS vfs_aio_qos_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"aio_qos",
				&vfs_aio_qos_fns);
}

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
#define DELAY_MAX (30000)

/* Token bucket-based rate limiter */
struct ratelimiter {
	struct timespec timestamp;
	uint64_t iops_limit;
	uint64_t iops_curr;
	uint64_t bps_limit;
	uint64_t bps_curr;
	uint32_t delay_msec;
};

/* In-memory QoS entry per connection */
struct aio_qos_config {
	struct ratelimiter rd_ratelimiter;
	struct ratelimiter wr_ratelimiter;
	int snum;
};

static void ratelimiter_init(struct ratelimiter *rl,
			     uint64_t iops_limit,
			     uint64_t bps_limit,
			     uint32_t delay_msec)
{
	ZERO_STRUCTP(rl);
	rl->iops_limit = iops_limit;
	rl->bps_limit = bps_limit;
	rl->iops_curr = 0;
	rl->bps_curr = 0;
	rl->delay_msec = delay_msec;
}

static void ratelimiter_update(struct ratelimiter *rl, size_t n)
{
	struct timespec ts;

	clock_gettime_mono(&ts);
	if (rl->timestamp.tv_sec != ts.tv_sec) {
		rl->iops_curr = 1;
		rl->bps_curr = n;
		rl->timestamp = ts;
	} else {
		rl->iops_curr += 1;
		rl->bps_curr += n;
	}
}

static uint32_t ratelimiter_calc_delay(const struct ratelimiter *rl)
{
	uint64_t delay = 0;
	uint32_t delay_msec = 0;

	if (rl->bps_limit && (rl->bps_curr > rl->bps_limit)) {
		if (rl->delay_msec > 0) {
			delay_msec = rl->delay_msec;
		} else {
			delay = (rl->bps_curr / rl->bps_limit);
			delay_msec = (uint32_t)(1000 * delay);
		}
	} else if (rl->iops_limit && (rl->iops_curr > rl->iops_limit)) {
		if (rl->delay_msec > 0) {
			delay_msec = rl->delay_msec;
		} else {
			delay = ((rl->iops_curr - 1) / rl->iops_limit);
			delay_msec = (uint32_t)(1000 * delay);
		}
	}
	return MIN(delay_msec, DELAY_MAX);
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
	unsigned long iops_limit, bps_limit, delay;

	iops_limit = aio_qos_lp_parm(config, "read_iops_limit", 0);
	bps_limit = aio_qos_lp_parm(config, "read_bps_limit", 0);
	delay = aio_qos_lp_parm(config, "read_delay", 0);
	ratelimiter_init(&config->rd_ratelimiter,
			 iops_limit,
			 bps_limit,
			 (uint32_t)delay);
	DBG_DEBUG("[QoS] init read-ratelimiter: iops_limit=%lu bps_limit=%lu "
		  "delay=%lu\n",
		  iops_limit,
		  bps_limit,
		  delay);

	iops_limit = aio_qos_lp_parm(config, "write_iops_limit", 0);
	bps_limit = aio_qos_lp_parm(config, "write_bps_limit", 0);
	delay = aio_qos_lp_parm(config, "write_delay", 0);
	ratelimiter_init(&config->wr_ratelimiter,
			 iops_limit,
			 bps_limit,
			 (uint32_t)delay);
	DBG_DEBUG("[QoS] init write-ratelimiter: iops_limit=%lu bps_limit=%lu "
		  "delay=%lu\n",
		  iops_limit,
		  bps_limit,
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

	DBG_INFO("[QoS] connect: service=%s snum=%d\n",
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
	DBG_INFO("[QoS] disconnect: snum=%d\n", SNUM(handle->conn));
	SMB_VFS_NEXT_DISCONNECT(handle);
	SMB_VFS_HANDLE_FREE_DATA(handle);
}

static struct timeval aio_qos_delay_tv(uint32_t delay_msec)
{
	return timeval_current_ofs(delay_msec / 1000,
				   (delay_msec * 1000) % 1000000);
}

struct aio_qos_pread_state {
	struct tevent_context *ev;
	struct vfs_handle_struct *handle;
	struct files_struct *fsp;
	void *data;
	size_t n;
	off_t offset;
	ssize_t result;
	struct vfs_aio_state vfs_aio_state;
	struct ratelimiter *rl;
	struct timeval wakeup;
	uint32_t delay;
};

static void aio_qos_pread_wait_done(struct tevent_req *subreq);
static void aio_qos_pread_done(struct tevent_req *subreq);

static void aio_qos_pread_pre_send(struct aio_qos_pread_state *state)
{
	if (likely(state->rl != NULL)) {
		ratelimiter_update(state->rl, state->n);
		state->delay = ratelimiter_calc_delay(state->rl);
	}
}

static struct tevent_req *aio_qos_pread_send_or_delay(struct tevent_req *req)
{
	struct tevent_req *subreq = NULL;
	struct aio_qos_pread_state *state = tevent_req_data(
		req, struct aio_qos_pread_state);

	if (state->delay > 0) {
		subreq = tevent_wakeup_send(state,
					    state->ev,
					    aio_qos_delay_tv(state->delay));
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, state->ev);
		}
		tevent_req_set_callback(subreq, aio_qos_pread_wait_done, req);
		return req;
	}

	subreq = SMB_VFS_NEXT_PREAD_SEND(state,
					 state->ev,
					 state->handle,
					 state->fsp,
					 state->data,
					 state->n,
					 state->offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, state->ev);
	}
	tevent_req_set_callback(subreq, aio_qos_pread_done, req);
	return req;
}

static struct tevent_req *aio_qos_pread_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp,
					     void *data,
					     size_t n,
					     off_t offset)
{
	struct tevent_req *req = NULL;
	struct aio_qos_pread_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct aio_qos_pread_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct aio_qos_pread_state){
		.ev = ev,
		.handle = handle,
		.fsp = fsp,
		.data = data,
		.n = n,
		.offset = offset,
		.rl = aio_qos_ratelimiter_of(handle, false),
		.delay = 0,
	};

	aio_qos_pread_pre_send(state);
	return aio_qos_pread_send_or_delay(req);
}

static void aio_qos_pread_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct aio_qos_pread_state *state = tevent_req_data(
		req, struct aio_qos_pread_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, EIO);
		return;
	}
	state->delay = 0;
	aio_qos_pread_send_or_delay(req);
}

static void aio_qos_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct aio_qos_pread_state *state = tevent_req_data(
		req, struct aio_qos_pread_state);

	state->result = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);

	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t aio_qos_pread_recv(struct tevent_req *req,
				  struct vfs_aio_state *vfs_aio_state)
{
	struct aio_qos_pread_state *state = tevent_req_data(
		req, struct aio_qos_pread_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->result;
}

struct aio_qos_pwrite_state {
	struct tevent_context *ev;
	struct vfs_handle_struct *handle;
	struct files_struct *fsp;
	const void *data;
	size_t n;
	off_t offset;
	ssize_t result;
	struct vfs_aio_state vfs_aio_state;
	struct ratelimiter *rl;
	struct timeval wakeup;
	uint32_t delay;
};

static void aio_qos_pwrite_wait_done(struct tevent_req *subreq);
static void aio_qos_pwrite_done(struct tevent_req *subreq);

static void aio_qos_pwrite_pre_send(struct aio_qos_pwrite_state *state)
{
	if (likely(state->rl != NULL)) {
		ratelimiter_update(state->rl, state->n);
		state->delay = ratelimiter_calc_delay(state->rl);
	}
}

static struct tevent_req *aio_qos_pwrite_send_or_delay(struct tevent_req *req)
{
	struct tevent_req *subreq = NULL;
	struct aio_qos_pwrite_state *state = tevent_req_data(
		req, struct aio_qos_pwrite_state);

	if (state->delay > 0) {
		subreq = tevent_wakeup_send(state,
					    state->ev,
					    aio_qos_delay_tv(state->delay));
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, state->ev);
		}
		tevent_req_set_callback(subreq, aio_qos_pwrite_wait_done, req);
		return req;
	}

	subreq = SMB_VFS_NEXT_PWRITE_SEND(state,
					  state->ev,
					  state->handle,
					  state->fsp,
					  state->data,
					  state->n,
					  state->offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, state->ev);
	}
	tevent_req_set_callback(subreq, aio_qos_pwrite_done, req);
	return req;
}

static struct tevent_req *aio_qos_pwrite_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      const void *data,
					      size_t n,
					      off_t offset)
{
	struct tevent_req *req = NULL;
	struct aio_qos_pwrite_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct aio_qos_pwrite_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct aio_qos_pwrite_state){
		.ev = ev,
		.handle = handle,
		.fsp = fsp,
		.data = data,
		.n = n,
		.offset = offset,
		.rl = aio_qos_ratelimiter_of(handle, true),
		.delay = 0,
	};

	aio_qos_pwrite_pre_send(state);
	return aio_qos_pwrite_send_or_delay(req);
}

static void aio_qos_pwrite_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct aio_qos_pwrite_state *state = tevent_req_data(
		req, struct aio_qos_pwrite_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, EIO);
		return;
	}
	state->delay = 0;
	aio_qos_pwrite_send_or_delay(req);
}

static void aio_qos_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct aio_qos_pwrite_state *state = tevent_req_data(
		req, struct aio_qos_pwrite_state);

	state->result = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);

	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t aio_qos_pwrite_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct aio_qos_pwrite_state *state = tevent_req_data(
		req, struct aio_qos_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->result;
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

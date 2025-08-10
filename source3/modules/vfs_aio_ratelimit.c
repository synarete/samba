/*
 * Async I/O rate-limiting stackable Samba module.
 *
 * Copyright (c) 2025 Shachar Sharon <ssharon@redhat.com>
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

/* Maximal delay value for IOPS/BYTES overflow, in milliseconds */
#define DELAY_MAX (30000)

/* Refill-token interval, in milliseconds */
#define TOKEN_REFILL_INTERVAL_MSEC (100)

/* Token-based rate-limiter control state */
struct ratelimiter {
	uint64_t timestamp_msec;
	uint64_t iops_limit;
	uint64_t iops_curr;
	uint64_t bytes_limit;
	uint64_t bytes_curr;
	float iops_tokens;
	float bytes_tokens;
};

/* In-memory rate-limiting entry per connection */
struct aio_rlim_config {
	struct ratelimiter rd_ratelimiter;
	struct ratelimiter wr_ratelimiter;
};

static uint64_t timestamp_msec(const struct timespec *ts)
{
	return (ts->tv_sec * 1000) + (ts->tv_nsec / 1000000);
}

static uint64_t timestamp_msec_now(void)
{
	struct timespec ts;

	clock_gettime_mono(&ts);
	return timestamp_msec(&ts);
}

static void ratelimiter_init(struct ratelimiter *rl,
			     uint64_t iops_limit,
			     uint64_t bytes_limit)
{
	ZERO_STRUCTP(rl);
	rl->iops_limit = iops_limit;
	rl->bytes_limit = bytes_limit;
}

static bool ratelimiter_enabled(const struct ratelimiter *rl)
{
	return (rl->iops_limit > 0) || (rl->bytes_limit > 0);
}

static void ratelimiter_renew_tokens(struct ratelimiter *rl)
{
	rl->iops_tokens = (float)rl->iops_limit;
	rl->bytes_tokens = (float)rl->bytes_limit;
}

static void ratelimiter_fill_tokens(struct ratelimiter *rl,
				    uint64_t elapsed_msec)
{
	float factor = (float)elapsed_msec / (float)TOKEN_REFILL_INTERVAL_MSEC;
	float refill, tokens_max;

	if (rl->iops_limit > 0) {
		tokens_max = (float)rl->iops_limit;
		refill = tokens_max * factor;
		rl->iops_tokens = MIN(rl->iops_tokens + refill, tokens_max);
	}

	if (rl->bytes_limit > 0) {
		tokens_max = (float)rl->bytes_limit;
		refill = tokens_max * factor;
		rl->bytes_tokens = MIN(rl->bytes_tokens + refill, tokens_max);
	}
}

static void ratelimiter_take_tokens(struct ratelimiter *rl, size_t nbytes)
{
	if (rl->iops_limit > 0) {
		if (rl->iops_tokens > 1.0) {
			rl->iops_tokens -= 1.0;
		} else {
			rl->iops_tokens = 0.0;
		}
	}

	if (rl->bytes_limit > 0) {
		const float nb = (float)nbytes;

		if (rl->bytes_tokens > nb) {
			rl->bytes_tokens -= nb;
		} else {
			rl->bytes_tokens = 0.0;
		}
	}
}

static uint32_t clap_delay(float delay)
{
	if (delay < 0.0) {
		return 0;
	}
	if (delay > (float)DELAY_MAX) {
		return DELAY_MAX;
	}
	return (uint32_t)delay;
}

static uint32_t ratelimiter_calc_delay(const struct ratelimiter *rl,
				       size_t nbytes)
{
	uint32_t delay_iops = 0;
	uint32_t delay_bytes = 0;
	float deficit, limit;

	if ((rl->iops_limit > 0) && (rl->iops_tokens < 1.0)) {
		deficit = 1.0 - rl->iops_tokens;
		limit = (float)rl->iops_limit;
		delay_iops = clap_delay((deficit / limit) * 1000.0);
	}

	if ((rl->bytes_limit > 0) && (rl->bytes_tokens < (float)nbytes)) {
		deficit = (float)nbytes - rl->bytes_tokens;
		limit = (float)rl->bytes_limit;
		delay_bytes = clap_delay((deficit / limit) * 1000.0);
	}

	return MAX(delay_iops, delay_bytes);
}

static uint32_t ratelimiter_pre_io(struct ratelimiter *rl, size_t nbytes)
{
	const uint64_t now_msec = timestamp_msec_now();
	const uint64_t dif = now_msec - rl->timestamp_msec;
	uint32_t delay = 0;

	if ((rl->timestamp_msec == 0) || (dif > 60000)) {
		/* First I/O or 1-min idle */
		ratelimiter_renew_tokens(rl);
		rl->iops_curr = 0;
		rl->bytes_curr = 0;
	} else {
		/* Normal case */
		delay = ratelimiter_calc_delay(rl, nbytes);
		ratelimiter_fill_tokens(rl, dif);
		ratelimiter_take_tokens(rl, nbytes);
	}
	rl->timestamp_msec = now_msec;
	rl->iops_curr += 1;
	rl->bytes_curr += nbytes;

	return delay;
}

static struct ratelimiter *ratelimiter_of(struct vfs_handle_struct *handle,
					  bool write)
{
	struct aio_rlim_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct aio_rlim_config,
				return NULL);

	return write ? &config->wr_ratelimiter : &config->rd_ratelimiter;
}

static unsigned long aio_rlim_lp_parm(int snum,
				      const char *option,
				      unsigned long def)
{
	return lp_parm_ulong(snum, "aio_ratelimit", option, def);
}

static void aio_rlim_setup(struct aio_rlim_config *config, int snum)
{
	unsigned long iops_limit, bytes_limit;

	iops_limit = aio_rlim_lp_parm(snum, "read_iops_limit", 0);
	bytes_limit = aio_rlim_lp_parm(snum, "read_bytes_limit", 0);
	ratelimiter_init(&config->rd_ratelimiter, iops_limit, bytes_limit);
	DBG_DEBUG("[aio_rlim] init read-ratelimiter: snum=%d "
		  "iops_limit=%lu bytes_limit=%lu\n",
		  snum,
		  iops_limit,
		  bytes_limit);

	iops_limit = aio_rlim_lp_parm(snum, "write_iops_limit", 0);
	bytes_limit = aio_rlim_lp_parm(snum, "write_bytes_limit", 0);
	ratelimiter_init(&config->wr_ratelimiter, iops_limit, bytes_limit);
	DBG_DEBUG("[aio_rlim] init write-ratelimiter: snum=%d "
		  "iops_limit=%lu bytes_limit=%lu\n",
		  snum,
		  iops_limit,
		  bytes_limit);
}

static void aio_rlim_free_config(void **ptr)
{
	TALLOC_FREE(*ptr);
}

static int
aio_rlim_new_config(struct vfs_handle_struct *handle)
{
	struct aio_rlim_config *config = NULL;

	config = talloc_zero(handle->conn, struct aio_rlim_config);
	if (config == NULL) {
		return -1;
	}
	aio_rlim_setup(config, SNUM(handle->conn));

	SMB_VFS_HANDLE_SET_DATA(handle,
				config,
				aio_rlim_free_config,
				struct aio_rlim_config,
				return -1);
	return 0;
}

static int aio_rlim_connect(struct vfs_handle_struct *handle,
			    const char *service,
			    const char *user)
{
	int ret;

	DBG_INFO("[aio_rlim] connect: service=%s snum=%d\n",
		 service,
		 SNUM(handle->conn));
	ret = aio_rlim_new_config(handle);
	if (ret != 0) {
		return ret;
	}

	return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static void aio_rlim_disconnect(struct vfs_handle_struct *handle)
{
	DBG_INFO("[aio_rlim] disconnect: snum=%d\n", SNUM(handle->conn));
	SMB_VFS_NEXT_DISCONNECT(handle);
	SMB_VFS_HANDLE_FREE_DATA(handle);
}

static struct timeval aio_rlim_delay_tv(uint32_t delay_msec)
{
	return timeval_current_ofs(delay_msec / 1000,
				   (delay_msec * 1000) % 1000000);
}

struct aio_rlim_pread_state {
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

static void aio_rlim_pread_wait_done(struct tevent_req *subreq);
static void aio_rlim_pread_done(struct tevent_req *subreq);

static void aio_rlim_pread_pre_send(struct aio_rlim_pread_state *state)
{
	if (likely(state->rl != NULL) && ratelimiter_enabled(state->rl)) {
		state->delay = ratelimiter_pre_io(state->rl, state->n);
	}
}

static struct tevent_req *aio_rlim_pread_send_or_delay(struct tevent_req *req)
{
	struct tevent_req *subreq = NULL;
	struct aio_rlim_pread_state *state = tevent_req_data(
		req, struct aio_rlim_pread_state);

	if (state->delay > 0) {
		subreq = tevent_wakeup_send(state,
					    state->ev,
					    aio_rlim_delay_tv(state->delay));
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, state->ev);
		}
		tevent_req_set_callback(subreq, aio_rlim_pread_wait_done, req);
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
	tevent_req_set_callback(subreq, aio_rlim_pread_done, req);
	return req;
}

static struct tevent_req *aio_rlim_pread_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      void *data,
					      size_t n,
					      off_t offset)
{
	struct tevent_req *req = NULL;
	struct aio_rlim_pread_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct aio_rlim_pread_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct aio_rlim_pread_state){
		.ev = ev,
		.handle = handle,
		.fsp = fsp,
		.data = data,
		.n = n,
		.offset = offset,
		.rl = ratelimiter_of(handle, false),
		.delay = 0,
	};

	aio_rlim_pread_pre_send(state);
	return aio_rlim_pread_send_or_delay(req);
}

static void aio_rlim_pread_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct aio_rlim_pread_state *state = tevent_req_data(
		req, struct aio_rlim_pread_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, EIO);
		return;
	}
	state->delay = 0;
	aio_rlim_pread_send_or_delay(req);
}

static void aio_rlim_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct aio_rlim_pread_state *state = tevent_req_data(
		req, struct aio_rlim_pread_state);

	state->result = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);

	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t aio_rlim_pread_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct aio_rlim_pread_state *state = tevent_req_data(
		req, struct aio_rlim_pread_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->result;
}

struct aio_rlim_pwrite_state {
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

static void aio_rlim_pwrite_wait_done(struct tevent_req *subreq);
static void aio_rlim_pwrite_done(struct tevent_req *subreq);

static void aio_rlim_pwrite_pre_send(struct aio_rlim_pwrite_state *state)
{
	if (likely(state->rl != NULL)) {
		state->delay = ratelimiter_pre_io(state->rl, state->n);
	}
}

static struct tevent_req *aio_rlim_pwrite_send_or_delay(struct tevent_req *req)
{
	struct tevent_req *subreq = NULL;
	struct aio_rlim_pwrite_state *state = tevent_req_data(
		req, struct aio_rlim_pwrite_state);

	if (state->delay > 0) {
		subreq = tevent_wakeup_send(state,
					    state->ev,
					    aio_rlim_delay_tv(state->delay));
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, state->ev);
		}
		tevent_req_set_callback(subreq, aio_rlim_pwrite_wait_done, req);
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
	tevent_req_set_callback(subreq, aio_rlim_pwrite_done, req);
	return req;
}

static struct tevent_req *aio_rlim_pwrite_send(struct vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct files_struct *fsp,
					       const void *data,
					       size_t n,
					       off_t offset)
{
	struct tevent_req *req = NULL;
	struct aio_rlim_pwrite_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct aio_rlim_pwrite_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct aio_rlim_pwrite_state){
		.ev = ev,
		.handle = handle,
		.fsp = fsp,
		.data = data,
		.n = n,
		.offset = offset,
		.rl = ratelimiter_of(handle, true),
		.delay = 0,
	};

	aio_rlim_pwrite_pre_send(state);
	return aio_rlim_pwrite_send_or_delay(req);
}

static void aio_rlim_pwrite_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct aio_rlim_pwrite_state *state = tevent_req_data(
		req, struct aio_rlim_pwrite_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, EIO);
		return;
	}
	state->delay = 0;
	aio_rlim_pwrite_send_or_delay(req);
}

static void aio_rlim_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct aio_rlim_pwrite_state *state = tevent_req_data(
		req, struct aio_rlim_pwrite_state);

	state->result = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);

	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t aio_rlim_pwrite_recv(struct tevent_req *req,
				    struct vfs_aio_state *vfs_aio_state)
{
	struct aio_rlim_pwrite_state *state = tevent_req_data(
		req, struct aio_rlim_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->result;
}

static struct vfs_fn_pointers vfs_aio_ratelimit_fns = {
	.connect_fn = aio_rlim_connect,
	.disconnect_fn = aio_rlim_disconnect,
	.pread_send_fn = aio_rlim_pread_send,
	.pread_recv_fn = aio_rlim_pread_recv,
	.pwrite_send_fn = aio_rlim_pwrite_send,
	.pwrite_recv_fn = aio_rlim_pwrite_recv,
};

static_decl_vfs;
NTSTATUS vfs_aio_ratelimit_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"aio_ratelimit",
				&vfs_aio_ratelimit_fns);
}

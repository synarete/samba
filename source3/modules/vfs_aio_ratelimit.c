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

/* Maximal delay value for IOPS/BYTES overflow (10-seconds) */
#define DELAY_USEC_MAX (10000000)

/* Token-based rate-limiter control state */
struct ratelimiter {
	const char *tag;
	struct timespec ts_base;
	struct timespec ts_last;
	uint64_t iops_limit;
	uint64_t bytes_limit;
	int64_t iops_tokens;
	int64_t bytes_tokens;
	size_t op_total;
	size_t nb_total;
	long epoch;
	int snum;
};

static const char mod_name[] = "aio_ratelimit";

/* In-memory rate-limiting entry per connection */
struct aio_rlim_config {
	struct ratelimiter rd_ratelimiter;
	struct ratelimiter wr_ratelimiter;
};

static void time_now(struct timespec *ts)
{
	clock_gettime_mono(ts);
}

static int64_t time_diff(const struct timespec *now,
			 const struct timespec *prev)
{
	return nsec_time_diff(now, prev) / 1000; /* usec */
}

static void ratelimiter_init(struct ratelimiter *rl,
			     int snum,
			     const char *tag,
			     uint64_t iops_limit,
			     uint64_t bytes_limit)
{
	ZERO_STRUCTP(rl);
	rl->tag = tag;
	rl->snum = snum;
	rl->iops_limit = iops_limit;
	rl->bytes_limit = bytes_limit;
	rl->op_total = 0;
	rl->nb_total = 0;
	rl->epoch = 0;
}

static bool ratelimiter_enabled(const struct ratelimiter *rl)
{
	return (rl->iops_limit > 0) || (rl->bytes_limit > 0);
}

static void ratelimiter_renew_tokens(struct ratelimiter *rl)
{
	rl->iops_tokens = (int64_t)rl->iops_limit * 1000000;
	rl->bytes_tokens = (int64_t)rl->bytes_limit * 1000000;
}

static void ratelimiter_take_tokens(struct ratelimiter *rl, ssize_t nbytes)
{
	rl->iops_tokens -= 1000000;
	rl->bytes_tokens -= nbytes * 1000000;
}

static void ratelimiter_give_bytes_tokens(struct ratelimiter *rl,
					  ssize_t nbytes)
{
	rl->bytes_tokens += nbytes * 1000000;
}

static void ratelimiter_fill_tokens(struct ratelimiter *rl, int64_t dif_usec)
{
	if (rl->iops_limit > 0) {
		rl->iops_tokens += dif_usec;
	}
	if (rl->bytes_limit > 0) {
		rl->bytes_tokens += (int64_t)rl->bytes_limit * dif_usec;
	}
}

static int64_t clap_delay(int64_t delay)
{
	return MAX(0, MIN(delay, DELAY_USEC_MAX));
}

static int64_t ratelimiter_calc_delay(const struct ratelimiter *rl)
{
	int64_t iops_delay_usec = 0;
	int64_t bytes_delay_usec = 0;

	if ((rl->iops_limit > 0) && (rl->iops_tokens < 0)) {
		iops_delay_usec = clap_delay(-rl->iops_tokens);
	}

	if ((rl->bytes_limit > 0) && (rl->bytes_tokens < 0)) {
		bytes_delay_usec = clap_delay(-rl->bytes_tokens);
	}

	return MAX(iops_delay_usec, bytes_delay_usec);
}

static void ratelimiter_dbg(const struct ratelimiter *rl,
			    size_t nbytes,
			    int64_t delay_usec)
{
	if (rl->iops_limit > 0) {
		DBG_DEBUG("[%s %d-%s] delay_usec=%" PRId64
			  " op_total=%zu iops_limit=%" PRIu64
			  " iops_tokens=%" PRId64 "\n",
			  mod_name,
			  rl->snum,
			  rl->tag,
			  delay_usec,
			  rl->op_total,
			  rl->iops_limit,
			  rl->iops_tokens);
	}
	if (rl->bytes_limit > 0) {
		DBG_DEBUG("[%s %d-%s] delay_usec=%" PRId64 " nbytes=%zu "
			  " nb_total=%zu bytes_limit=%" PRIu64
			  " bytes_tokens=%" PRId64 "\n",
			  mod_name,
			  rl->snum,
			  rl->tag,
			  delay_usec,
			  nbytes,
			  rl->nb_total,
			  rl->bytes_limit,
			  rl->bytes_tokens);
	}
}

static int64_t ratelimiter_pre_io(struct ratelimiter *rl, size_t nbytes)
{
	struct timespec now;
	int64_t tdiff_usec = 0;
	int64_t delay_usec = 0;

	time_now(&now);
	tdiff_usec = time_diff(&now, &rl->ts_base);

	if (!rl->epoch || (tdiff_usec > DELAY_USEC_MAX)) {
		/* Renew state */
		ratelimiter_renew_tokens(rl);
		rl->epoch += 1;
		rl->ts_base = now;
	} else {
		/* Update tokens based on elapsed time */
		tdiff_usec = time_diff(&now, &rl->ts_last);
		ratelimiter_fill_tokens(rl, tdiff_usec);
	}
	/* Take tokens and calc delay based on deficit */
	ratelimiter_take_tokens(rl, nbytes);
	delay_usec = ratelimiter_calc_delay(rl);

	rl->ts_last = now;
	rl->op_total += 1;
	rl->nb_total += nbytes;

	ratelimiter_dbg(rl, nbytes, delay_usec);

	return delay_usec;
}

static void ratelimiter_post_io(struct ratelimiter *rl,
				long epoch,
				size_t nbytes,
				ssize_t io_result)
{
	const ssize_t ndif = (ssize_t)nbytes - io_result;

	if ((rl->epoch == epoch) && (io_result >= 0) && (ndif > 0)) {
		ratelimiter_give_bytes_tokens(rl, ndif);
	}
}

static struct ratelimiter *ratelimiter_of(struct vfs_handle_struct *handle,
					  bool write)
{
	struct aio_rlim_config *config = NULL;
	struct ratelimiter *rl = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct aio_rlim_config,
				return rl);

	if (write) {
		rl = &config->wr_ratelimiter;
	} else {
		rl = &config->rd_ratelimiter;
	}

	return ratelimiter_enabled(rl) ? rl : NULL;
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
	ratelimiter_init(
		&config->rd_ratelimiter, snum, "read", iops_limit, bytes_limit);
	DBG_DEBUG("[%s] init read-ratelimiter: snum=%d "
		  "iops_limit=%lu bytes_limit=%lu\n",
		  mod_name,
		  snum,
		  iops_limit,
		  bytes_limit);

	iops_limit = aio_rlim_lp_parm(snum, "write_iops_limit", 0);
	bytes_limit = aio_rlim_lp_parm(snum, "write_bytes_limit", 0);
	ratelimiter_init(&config->wr_ratelimiter,
			 snum,
			 "write",
			 iops_limit,
			 bytes_limit);
	DBG_DEBUG("[%s] init write-ratelimiter: snum=%d "
		  "iops_limit=%lu bytes_limit=%lu\n",
		  mod_name,
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

	DBG_INFO("[%s] connect: service=%s snum=%d\n",
		 mod_name,
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
	DBG_INFO("[%s] disconnect: snum=%d\n", mod_name, SNUM(handle->conn));
	SMB_VFS_NEXT_DISCONNECT(handle);
	SMB_VFS_HANDLE_FREE_DATA(handle);
}

static struct timeval aio_rlim_delay_tv(int64_t delay_usec)
{
	uint32_t secs = 0, usecs = 0;

	if (delay_usec > 0) {
		secs = (uint32_t)(delay_usec / 1000000);
		usecs = (uint32_t)(delay_usec % 1000000);
	}
	return timeval_current_ofs(secs, usecs);
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
	int64_t delay;
	long epoch;
};

static void aio_rlim_pread_wait_done(struct tevent_req *subreq);
static void aio_rlim_pread_done(struct tevent_req *subreq);

static void aio_rlim_pread_pre_send(struct aio_rlim_pread_state *state)
{
	if (state->rl != NULL) {
		state->delay = ratelimiter_pre_io(state->rl, state->n);
		state->epoch = state->rl->epoch;
	}
}

static void aio_rlim_pread_post_recv(struct aio_rlim_pread_state *state)
{
	if (state->rl != NULL) {
		ratelimiter_post_io(state->rl,
				    state->epoch,
				    state->n,
				    state->result);
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
	aio_rlim_pread_post_recv(state);

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
	int64_t delay;
	long epoch;
};

static void aio_rlim_pwrite_wait_done(struct tevent_req *subreq);
static void aio_rlim_pwrite_done(struct tevent_req *subreq);

static void aio_rlim_pwrite_pre_send(struct aio_rlim_pwrite_state *state)
{
	if (state->rl != NULL) {
		state->delay = ratelimiter_pre_io(state->rl, state->n);
		state->epoch = state->rl->epoch;
	}
}

static void aio_rlim_pwrite_post_recv(struct aio_rlim_pwrite_state *state)
{
	if (state->rl != NULL) {
		ratelimiter_post_io(state->rl,
				    state->epoch,
				    state->n,
				    state->result);
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
	aio_rlim_pwrite_post_recv(state);

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
				mod_name,
				&vfs_aio_ratelimit_fns);
}

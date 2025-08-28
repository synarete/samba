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

/*
  Token-base rate-limiter using Samba's VFS stack-able module. For each smb
  share a user may define READ/WRITE thresholds in terms of IOPS or BYTES
  per-second. If one of those thresholds is exceeded along the asynchronous
  I/O path, a delay is injected before the sending back a reply to the caller,
  thus causing a rate-limit ceiling.

  An example to smb.conf segment (zero value implies ignore-this-option):

  [share]
  vfs objects = aio_ratelimit ...
  aio_ratelimit: read_iops_limit = 2000
  aio_ratelimit: read_bw_limit = 2000000
  aio_ratelimit: write_iops_limit = 0
  aio_ratelimit: write_bw_limit = 1000000
  ...

  Upon successful completion of async I/O request, tokens are produced based on
  the time which elapsed from previous requests, and tokens are consumed based
  on actual I/O size. When current tokens value is negative, a delay is
  calculated end injected to in-flight request. The delay value (microseconds)
  is calculated based on the current tokens deficit.
 */

#include "includes.h"
#include "lib/util/time.h"
#include "lib/util/tevent_unix.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

/* Default and maximal delay values, in seconds */
#define DELAY_SEC_DEF (10L)
#define DELAY_SEC_MAX (100L)

/* Avoid precision loss by multiply tokens with fixed factor */
#define TOKENS_FACTOR (1000L)

/* Maximal value for iops_limit */
#define IOPS_LIMIT_MAX (1000000L)

/* Maximal value for bw_limit */
#define BYTES_LIMIT_MAX (1L << 40)

/* Module type-name in smb.conf & debug logging */
static const char vfs_aio_ratelimit_name[] = "aio_ratelimit";

/* Token-based rate-limiter control state */
struct ratelimiter {
	const char *oper;
	struct timespec ts_base;
	struct timespec ts_last;
	int64_t iops_limit;
	int64_t iops_total;
	int64_t iops_tokens;
	int64_t iops_tokens_max;
	int64_t iops_tokens_min;
	int64_t bw_limit;
	int64_t bytes_total;
	int64_t bytes_tokens;
	int64_t bytes_tokens_max;
	int64_t bytes_tokens_min;
	int64_t delay_sec_max;
	int snum;
};

/* In-memory rate-limiting entry per connection */
struct vfs_aio_ratelimit_config {
	struct ratelimiter rd_ratelimiter;
	struct ratelimiter wr_ratelimiter;
};

static int64_t max64(int64_t x, int64_t y)
{
	return MAX(x, y);
}

static int64_t min64(int64_t x, int64_t y)
{
	return MIN(x, y);
}

static struct timespec time_now(void)
{
	struct timespec ts;

	clock_gettime_mono(&ts);
	return ts;
}

static int64_t time_diff(const struct timespec *now,
			 const struct timespec *prev)
{
	return nsec_time_diff(now, prev) / 1000; /* usec */
}

static void ratelimiter_init(struct ratelimiter *rl,
			     int snum,
			     const char *oper_name,
			     int64_t iops_limit,
			     int64_t bw_limit,
			     int64_t delay_sec_max)
{
	ZERO_STRUCTP(rl);
	rl->oper = oper_name;
	rl->iops_total = 0;
	rl->iops_limit = iops_limit;
	rl->iops_tokens = 0;
	rl->iops_tokens_max = rl->iops_limit * TOKENS_FACTOR;
	rl->iops_tokens_min = -rl->iops_tokens_max;
	rl->bytes_total = 0;
	rl->bw_limit = bw_limit;
	rl->bytes_tokens = 0;
	rl->bytes_tokens_max = rl->bw_limit * TOKENS_FACTOR;
	rl->bytes_tokens_min = -rl->bytes_tokens_max;
	rl->delay_sec_max = delay_sec_max;
	rl->snum = snum;

	DBG_DEBUG("[%s snum:%d %s] init ratelimiter:" //
		  " iops_limit=%" PRId64	      //
		  " bw_limit=%" PRId64		      //
		  " delay_sec_max=%" PRId64	      //
		  "\n",
		  vfs_aio_ratelimit_name,
		  rl->snum,
		  rl->oper,
		  rl->iops_limit,
		  rl->bw_limit,
		  rl->delay_sec_max);
}

static bool ratelimiter_enabled(const struct ratelimiter *rl)
{
	return (rl->delay_sec_max > 0) &&
	       ((rl->iops_limit > 0) || (rl->bw_limit > 0));
}

static void ratelimiter_renew_tokens(struct ratelimiter *rl)
{
	if (rl->iops_limit > 0) {
		rl->iops_tokens = rl->iops_tokens_max;
	}
	if (rl->bw_limit > 0) {
		rl->bytes_tokens = rl->bytes_tokens_max;
	}
}

static void ratelimiter_take_tokens(struct ratelimiter *rl, int64_t nbytes)
{
	int64_t take;

	if (rl->iops_limit > 0) {
		take = TOKENS_FACTOR;
		rl->iops_tokens = max64(rl->iops_tokens - take,
					rl->iops_tokens_min);
	}
	if (rl->bw_limit > 0) {
		take = TOKENS_FACTOR * nbytes;
		rl->bytes_tokens = max64(rl->bytes_tokens - take,
					 rl->bytes_tokens_min);
	}
}

static void ratelimiter_fill_tokens(struct ratelimiter *rl, int64_t dif_usec)
{
	int64_t fill;

	if (rl->iops_limit > 0) {
		fill = (dif_usec * rl->iops_tokens_max) / 1000000L;
		rl->iops_tokens = min64(rl->iops_tokens + fill,
					rl->iops_tokens_max);
	}
	if (rl->bw_limit > 0) {
		fill = (dif_usec * rl->bytes_tokens_max) / 1000000L;
		rl->bytes_tokens = min64(rl->bytes_tokens + fill,
					 rl->bytes_tokens_max);
	}
}

static uint32_t ratelimiter_calc_delay(const struct ratelimiter *rl)
{
	int64_t iops_delay_usec = 0;
	int64_t bytes_delay_usec = 0;
	int64_t delay_usec = 0;

	/* Calculate delay for 1-second window */
	if ((rl->iops_limit > 0) && (rl->iops_tokens < 0)) {
		iops_delay_usec = (rl->iops_tokens * 1000000L) /
				  rl->iops_tokens_min;
	}
	if ((rl->bw_limit > 0) && (rl->bytes_tokens < 0)) {
		bytes_delay_usec = (rl->bytes_tokens * 1000000L) /
				   rl->bytes_tokens_min;
	}
	/* Normalize delay within valid span */
	delay_usec = max64(iops_delay_usec, bytes_delay_usec);
	return (uint32_t)(delay_usec * rl->delay_sec_max);
}

static bool ratelimiter_need_renew(const struct ratelimiter *rl,
				   const struct timespec *now)
{
	time_t sec_dif = 0;

	if (rl->ts_base.tv_sec == 0) {
		/* First time */
		DBG_DEBUG("[%s snum:%d %s] init\n",
			  vfs_aio_ratelimit_name,
			  rl->snum,
			  rl->oper);
		return true;
	}
	sec_dif = (now->tv_sec - rl->ts_last.tv_sec);
	if (sec_dif >= 60) {
		/* Force renew after 1-minutes idle */
		DBG_DEBUG("[%s snum:%d %s] idle sec_dif=%ld\n",
			  vfs_aio_ratelimit_name,
			  rl->snum,
			  rl->oper,
			  (long)sec_dif);
		return true;
	}
	sec_dif = (now->tv_sec - rl->ts_base.tv_sec);
	if (sec_dif >= 1200) {
		/* Force renew every 20-minutes to avoid skew */
		DBG_DEBUG("[%s snum:%d %s] renew sec_dif=%ld\n",
			  vfs_aio_ratelimit_name,
			  rl->snum,
			  rl->oper,
			  (long)sec_dif);
		return true;
	}
	return false;
}

static void ratelimiter_dbg(const struct ratelimiter *rl,
			    int64_t nbytes,
			    int64_t tdiff_usec,
			    uint32_t delay_usec)
{
	if (rl->iops_limit > 0) {
		DBG_DEBUG("[%s snum:%d %s]"	      //
			  " iops_total=%" PRId64      //
			  " iops_limit=%" PRId64      //
			  " iops_tokens_max=%" PRId64 //
			  " iops_tokens=%" PRId64     //
			  " tdiff_usec=%" PRId64      //
			  " delay_usec=%" PRIu32      //
			  " \n",
			  vfs_aio_ratelimit_name,
			  rl->snum,
			  rl->oper,
			  rl->iops_total,
			  rl->iops_limit,
			  rl->iops_tokens_max,
			  rl->iops_tokens,
			  tdiff_usec,
			  delay_usec);
	}
	if (rl->bw_limit > 0) {
		DBG_DEBUG("[%s snum:%d %s]"	       //
			  " bytes_total=%" PRId64      //
			  " bw_limit=%" PRId64	       //
			  " bytes_tokens_max=%" PRId64 //
			  " bytes_tokens=%" PRId64     //
			  " nbytes=%" PRId64	       //
			  " tdiff_usec=%" PRId64       //
			  " delay_usec=%" PRIu32       //
			  " \n",
			  vfs_aio_ratelimit_name,
			  rl->snum,
			  rl->oper,
			  rl->bytes_total,
			  rl->bw_limit,
			  rl->bytes_tokens_max,
			  rl->bytes_tokens,
			  nbytes,
			  tdiff_usec,
			  delay_usec);
	}
}

static uint32_t ratelimiter_update_io(struct ratelimiter *rl, int64_t nbytes)
{
	const struct timespec now = time_now();
	int64_t tdiff_usec = 0;
	uint32_t delay_usec = 0;

	if (ratelimiter_need_renew(rl, &now)) {
		/* Renew state */
		ratelimiter_renew_tokens(rl);
		rl->ts_base = now;
	} else {
		/* Produce tokens based on elapsed time */
		tdiff_usec = time_diff(&now, &rl->ts_last);
		ratelimiter_fill_tokens(rl, tdiff_usec);
	}

	/* Consume tokens based on I/O size */
	ratelimiter_take_tokens(rl, nbytes);

	/* Calculate delay based on current tokens deficit */
	delay_usec = ratelimiter_calc_delay(rl);

	/* Update time-stamp for next operation */
	rl->ts_last = now;
	rl->iops_total += 1;
	rl->bytes_total += nbytes;

	ratelimiter_dbg(rl, nbytes, tdiff_usec, delay_usec);

	return delay_usec;
}

static struct ratelimiter *ratelimiter_of(struct vfs_handle_struct *handle,
					  bool write)
{
	struct vfs_aio_ratelimit_config *config = NULL;
	struct ratelimiter *rl = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_aio_ratelimit_config,
				return rl);

	if (write) {
		rl = &config->wr_ratelimiter;
	} else {
		rl = &config->rd_ratelimiter;
	}

	return ratelimiter_enabled(rl) ? rl : NULL;
}

static int64_t vfs_aio_ratelimit_lp_parm(int snum,
					 const char *option,
					 int64_t def,
					 int64_t lim)
{
	const char *type = vfs_aio_ratelimit_name;

	return min64((int64_t)lp_parm_ulong(snum, type, option, def), lim);
}

static void vfs_aio_ratelimit_setup(struct vfs_aio_ratelimit_config *config,
				    int snum)
{
	int64_t iops_limit, bw_limit, delay_max;

	iops_limit = vfs_aio_ratelimit_lp_parm(snum,
					       "read_iops_limit",
					       0,
					       IOPS_LIMIT_MAX);
	bw_limit = vfs_aio_ratelimit_lp_parm(snum,
					     "read_bw_limit",
					     0,
					     BYTES_LIMIT_MAX);
	delay_max = vfs_aio_ratelimit_lp_parm(snum,
					      "read_delay_max",
					      DELAY_SEC_DEF,
					      DELAY_SEC_MAX);
	ratelimiter_init(&config->rd_ratelimiter, //
			 snum,
			 "read",
			 iops_limit,
			 bw_limit,
			 (int32_t)delay_max);

	iops_limit = vfs_aio_ratelimit_lp_parm(snum,
					       "write_iops_limit",
					       0,
					       IOPS_LIMIT_MAX);
	bw_limit = vfs_aio_ratelimit_lp_parm(snum,
					     "write_bw_limit",
					     0,
					     BYTES_LIMIT_MAX);
	delay_max = vfs_aio_ratelimit_lp_parm(snum,
					      "write_delay_max",
					      DELAY_SEC_DEF,
					      DELAY_SEC_MAX);
	ratelimiter_init(&config->wr_ratelimiter, //
			 snum,
			 "write",
			 iops_limit,
			 bw_limit,
			 (int32_t)delay_max);
}

static void vfs_aio_ratelimit_free_config(void **ptr)
{
	TALLOC_FREE(*ptr);
}

static int vfs_aio_ratelimit_new_config(struct vfs_handle_struct *handle)
{
	struct vfs_aio_ratelimit_config *config = NULL;

	config = talloc_zero(handle->conn, struct vfs_aio_ratelimit_config);
	if (config == NULL) {
		return -1;
	}
	vfs_aio_ratelimit_setup(config, SNUM(handle->conn));

	SMB_VFS_HANDLE_SET_DATA(handle,
				config,
				vfs_aio_ratelimit_free_config,
				struct vfs_aio_ratelimit_config,
				return -1);
	return 0;
}

static int vfs_aio_ratelimit_connect(struct vfs_handle_struct *handle,
				     const char *service,
				     const char *user)
{
	int ret;

	DBG_INFO("[%s] connect: service=%s snum=%d\n",
		 vfs_aio_ratelimit_name,
		 service,
		 SNUM(handle->conn));
	ret = vfs_aio_ratelimit_new_config(handle);
	if (ret != 0) {
		return ret;
	}

	return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static void vfs_aio_ratelimit_disconnect(struct vfs_handle_struct *handle)
{
	DBG_INFO("[%s] disconnect: snum=%d\n",
		 vfs_aio_ratelimit_name,
		 SNUM(handle->conn));
	SMB_VFS_HANDLE_FREE_DATA(handle);
	SMB_VFS_NEXT_DISCONNECT(handle);
}

static struct timeval vfs_aio_ratelimit_delay_tv(uint32_t delay_usec)
{
	return timeval_current_ofs(delay_usec / 1000000, delay_usec % 1000000);
}

struct vfs_aio_ratelimit_state {
	struct tevent_context *ev;
	struct ratelimiter *rl;
	ssize_t result;
	uint32_t delay;
	struct vfs_aio_state vfs_aio_state;
};

static bool vfs_aio_ratelimit_update_done(struct vfs_aio_ratelimit_state *state)
{
	if ((state->rl != NULL) && (state->result >= 0)) {
		state->delay = ratelimiter_update_io(state->rl, state->result);
	}
	return (state->delay == 0);
}

static void vfs_aio_ratelimit_pread_done(struct tevent_req *subreq);
static void vfs_aio_ratelimit_pread_waited(struct tevent_req *subreq);

static struct tevent_req *vfs_aio_ratelimit_pread_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp,
	void *data,
	size_t n,
	off_t off)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct vfs_aio_ratelimit_state *state = NULL;

	req = tevent_req_create(mem_ctx,
				&state,
				struct vfs_aio_ratelimit_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct vfs_aio_ratelimit_state){
		.ev = ev,
		.rl = ratelimiter_of(handle, false),
		.result = 0,
		.delay = 0,
	};

	subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp, data, n, off);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_aio_ratelimit_pread_done, req);
	return req;
}

static void vfs_aio_ratelimit_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct vfs_aio_ratelimit_state *state = tevent_req_data(
		req, struct vfs_aio_ratelimit_state);

	state->result = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	if (vfs_aio_ratelimit_update_done(state)) {
		tevent_req_done(req);
		return;
	}

	subreq = tevent_wakeup_send(state,
				    state->ev,
				    vfs_aio_ratelimit_delay_tv(state->delay));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, vfs_aio_ratelimit_pread_waited, req);
}

static void vfs_aio_ratelimit_pread_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, EIO);
		return;
	}
	tevent_req_done(req);
}

static ssize_t vfs_aio_ratelimit_pread_recv(struct tevent_req *req,
					    struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_aio_ratelimit_state *state = tevent_req_data(
		req, struct vfs_aio_ratelimit_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->result;
}

static void vfs_aio_ratelimit_pwrite_done(struct tevent_req *subreq);
static void vfs_aio_ratelimit_pwrite_waited(struct tevent_req *subreq);

static struct tevent_req *vfs_aio_ratelimit_pwrite_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp,
	const void *data,
	size_t n,
	off_t off)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct vfs_aio_ratelimit_state *state = NULL;

	req = tevent_req_create(mem_ctx,
				&state,
				struct vfs_aio_ratelimit_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct vfs_aio_ratelimit_state){
		.ev = ev,
		.rl = ratelimiter_of(handle, true),
		.result = 0,
		.delay = 0,
	};

	subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp, data, n, off);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_aio_ratelimit_pwrite_done, req);
	return req;
}

static void vfs_aio_ratelimit_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct vfs_aio_ratelimit_state *state = tevent_req_data(
		req, struct vfs_aio_ratelimit_state);

	state->result = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	if (vfs_aio_ratelimit_update_done(state)) {
		tevent_req_done(req);
		return;
	}

	subreq = tevent_wakeup_send(state,
				    state->ev,
				    vfs_aio_ratelimit_delay_tv(state->delay));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, vfs_aio_ratelimit_pwrite_waited, req);
}

static void vfs_aio_ratelimit_pwrite_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, EIO);
		return;
	}
	tevent_req_done(req);
}

static ssize_t vfs_aio_ratelimit_pwrite_recv(
	struct tevent_req *req,
	struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_aio_ratelimit_state *state = tevent_req_data(
		req, struct vfs_aio_ratelimit_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->result;
}

static struct vfs_fn_pointers vfs_aio_ratelimit_fns = {
	.connect_fn = vfs_aio_ratelimit_connect,
	.disconnect_fn = vfs_aio_ratelimit_disconnect,
	.pread_send_fn = vfs_aio_ratelimit_pread_send,
	.pread_recv_fn = vfs_aio_ratelimit_pread_recv,
	.pwrite_send_fn = vfs_aio_ratelimit_pwrite_send,
	.pwrite_recv_fn = vfs_aio_ratelimit_pwrite_recv,
};

static_decl_vfs;
NTSTATUS vfs_aio_ratelimit_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				vfs_aio_ratelimit_name,
				&vfs_aio_ratelimit_fns);
}

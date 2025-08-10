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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

/* Maximal delay value, in seconds */
#define DELAY_MAX_SEC (10L)

/* Token factor to avoid precision loss */
#define TOKENS_FACTOR (1000L)

/* Maximal value for iops_limit */
#define IOPS_LIMIT_MAX (1L << 40)

/* Maximal value for bytes_limit */
#define BYTES_LIMIT_MAX (1L << 40)

/* Module type-name in smb.conf & debug logging */
static const char vfs_aio_ratelimit_name[] = "aio_ratelimit";

/* Token-based rate-limiter control state */
struct ratelimiter {
	const char *oper;
	struct timespec ts_base;
	struct timespec ts_last;
	int64_t iops_total;
	int64_t iops_limit;
	int64_t iops_tokens;
	int64_t iops_tokens_max;
	int64_t iops_tokens_min;
	int64_t bytes_total;
	int64_t bytes_limit;
	int64_t bytes_tokens;
	int64_t bytes_tokens_max;
	int64_t bytes_tokens_min;
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
			     int64_t bytes_limit)
{
	ZERO_STRUCTP(rl);
	rl->oper = oper_name;
	rl->snum = snum;
	rl->iops_limit = iops_limit;
	rl->bytes_limit = bytes_limit;
	rl->iops_tokens_max = TOKENS_FACTOR * rl->iops_limit;
	rl->bytes_tokens_max = TOKENS_FACTOR * rl->bytes_limit;
	rl->iops_tokens_min = -rl->iops_tokens_max;
	rl->bytes_tokens_min = -rl->bytes_tokens_max;
}

static bool ratelimiter_enabled(const struct ratelimiter *rl)
{
	return (rl->iops_limit > 0) || (rl->bytes_limit > 0);
}

static void ratelimiter_renew_tokens(struct ratelimiter *rl)
{
	if (rl->iops_limit > 0) {
		rl->iops_tokens = rl->iops_tokens_max;
	}
	if (rl->bytes_limit > 0) {
		rl->bytes_tokens = rl->bytes_tokens_max;
	}
}

static void ratelimiter_take_tokens(struct ratelimiter *rl, ssize_t nbytes)
{
	int64_t take;

	if (rl->iops_limit > 0) {
		take = TOKENS_FACTOR;
		rl->iops_tokens = max64(rl->iops_tokens - take,
					rl->iops_tokens_min);
	}
	if (rl->bytes_limit > 0) {
		take = TOKENS_FACTOR * nbytes;
		rl->bytes_tokens = max64(rl->bytes_tokens - take,
					 rl->bytes_tokens_min);
	}
}

static void ratelimiter_fill_tokens(struct ratelimiter *rl, int64_t dif_usec)
{
	int64_t fill;

	if (rl->iops_limit > 0) {
		fill = (dif_usec * rl->iops_tokens_max) / 1000000;
		rl->iops_tokens = min64(rl->iops_tokens + fill,
					rl->iops_tokens_max);
	}
	if (rl->bytes_limit > 0) {
		fill = (dif_usec * rl->bytes_tokens_max) / 1000000;
		rl->bytes_tokens = min64(rl->bytes_tokens + fill,
					 rl->bytes_tokens_max);
	}
}

static uint32_t ratelimiter_calc_delay(const struct ratelimiter *rl)
{
	int64_t iops_delay = 0;
	int64_t bytes_delay = 0;
	int64_t debt = 0;

	/* Calculate micro-seconds delay within 1-second frame */
	if ((rl->iops_limit > 0) && (rl->iops_tokens < 0)) {
		debt = -rl->iops_tokens * 1000000;
		iops_delay = debt / rl->iops_tokens_max;
	}
	if ((rl->bytes_limit > 0) && (rl->bytes_tokens < 0)) {
		debt = -rl->bytes_tokens * 1000000;
		bytes_delay = debt / rl->bytes_tokens_max;
	}

	/* Normalize delay within valid range */
	return (uint32_t)(max64(iops_delay, bytes_delay) * DELAY_MAX_SEC);
}

static bool ratelimiter_need_renew(const struct ratelimiter *rl,
				   const struct timespec *now)
{
	const char *mode = "";
	time_t sec_dif = 0;

	if (rl->ts_base.tv_sec == 0) {
		/* First time */
		mode = "init";
		goto out_renew;
	}
	sec_dif = (now->tv_sec - rl->ts_last.tv_sec);
	if (sec_dif >= 60) {
		/* Force renew after 1-minutes idle */
		mode = "idle";
		goto out_renew;
	}
	sec_dif = (now->tv_sec - rl->ts_base.tv_sec);
	if (sec_dif >= 300) {
		/* Force renew every 5-minutes */
		mode = "renew";
		goto out_renew;
	}
	return false;
out_renew:
	DBG_DEBUG("[%s snum:%d %s] %s ratelimiter" //
		  " iops_limit=%" PRId64	   //
		  " bytes_limit=%" PRId64	   //
		  " sec_dif=%" PRId64		   //
		  "\n",
		  vfs_aio_ratelimit_name,
		  rl->snum,
		  rl->oper,
		  mode,
		  rl->iops_limit,
		  rl->bytes_limit,
		  (int64_t)sec_dif);
	return true;
}

static void ratelimiter_dbg(const struct ratelimiter *rl,
			    size_t nbytes,
			    int64_t tdiff_usec,
			    uint32_t delay_usec)
{
	if (rl->iops_limit > 0) {
		DBG_DEBUG("[%s snum:%d %s]"	  //
			  " iops_total=%" PRId64  //
			  " iops_limit=%" PRId64  //
			  " iops_tokens=%" PRId64 //
			  " tdiff_usec=%" PRId64  //
			  " delay_usec=%" PRIu32  //
			  " \n",
			  vfs_aio_ratelimit_name,
			  rl->snum,
			  rl->oper,
			  rl->iops_total,
			  rl->iops_limit,
			  rl->iops_tokens,
			  tdiff_usec,
			  delay_usec);
	}
	if (rl->bytes_limit > 0) {
		DBG_DEBUG("[%s snum:%d %s]"	   //
			  " bytes_total=%" PRId64  //
			  " bytes_limit=%" PRId64  //
			  " bytes_tokens=%" PRId64 //
			  " nbytes=%zu"		   //
			  " tdiff_usec=%" PRId64   //
			  " delay_usec=%" PRIu32   //
			  " \n",
			  vfs_aio_ratelimit_name,
			  rl->snum,
			  rl->oper,
			  rl->bytes_total,
			  rl->bytes_limit,
			  rl->bytes_tokens,
			  nbytes,
			  tdiff_usec,
			  delay_usec);
	}
}

static uint32_t ratelimiter_update_io(struct ratelimiter *rl, size_t nbytes)
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
					 int64_t lim)
{
	const char *type = vfs_aio_ratelimit_name;

	return min64((int64_t)lp_parm_ulong(snum, type, option, 0), lim);
}

static void vfs_aio_ratelimit_setup(struct vfs_aio_ratelimit_config *config,
				    int snum)
{
	int64_t iops_limit, bytes_limit;

	iops_limit = vfs_aio_ratelimit_lp_parm(snum,
					       "read_iops_limit",
					       IOPS_LIMIT_MAX);
	bytes_limit = vfs_aio_ratelimit_lp_parm(snum,
						"read_bytes_limit",
						BYTES_LIMIT_MAX);
	ratelimiter_init(&config->rd_ratelimiter, //
			 snum,
			 "read",
			 iops_limit,
			 bytes_limit);
	DBG_DEBUG("[%s] init read-ratelimiter: snum=%d "
		  "iops_limit=%" PRId64 " bytes_limit=%" PRId64 "\n",
		  vfs_aio_ratelimit_name,
		  snum,
		  iops_limit,
		  bytes_limit);

	iops_limit = vfs_aio_ratelimit_lp_parm(snum,
					       "write_iops_limit",
					       IOPS_LIMIT_MAX);
	bytes_limit = vfs_aio_ratelimit_lp_parm(snum,
						"write_bytes_limit",
						BYTES_LIMIT_MAX);
	ratelimiter_init(&config->wr_ratelimiter, //
			 snum,
			 "write",
			 iops_limit,
			 bytes_limit);
	DBG_DEBUG("[%s] init write-ratelimiter: snum=%d "
		  "iops_limit=%" PRId64 " bytes_limit=%" PRId64 "\n",
		  vfs_aio_ratelimit_name,
		  snum,
		  iops_limit,
		  bytes_limit);
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
		state->delay = ratelimiter_update_io(state->rl,
						     (size_t)state->result);
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

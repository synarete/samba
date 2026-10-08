/*
   Unix SMB/CIFS implementation.

   Send messaging requests, using the NDR format on clusters with
   functional level 2.0 and the legacy format otherwise.

   Copyright (C) Shachar Sharon 2026 <ssharon@redhat.com>

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

#include "includes.h"
#include "lib/util/server_id.h"
#include "messages_send.h"

/*
 * Send a message to a single destination, or to all processes when
 * the destination pid is zero.
 */
static NTSTATUS messaging_send_one_or_all(struct messaging_context *msg_ctx,
					  struct server_id dst,
					  uint32_t msg_type,
					  const uint8_t *buf,
					  size_t len)
{
	if (procid_to_pid(&dst) != 0) {
		return messaging_send_buf(msg_ctx, dst, msg_type, buf, len);
	}

	messaging_send_all(msg_ctx, msg_type, buf, len);
	return NT_STATUS_OK;
}

/* MSG_DEBUG */

static NTSTATUS messaging_send_debug_v1(struct messaging_context *msg_ctx,
					struct server_id dst,
					const char *debug_string)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_debug msg = {
		.info.info1.debug_string = debug_string,
	};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_debug_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(
		msg_ctx, dst, MSG_DEBUG_V1, blob.data, blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_debug_legacy(struct messaging_context *msg_ctx,
					    struct server_id dst,
					    const char *debug_string)
{
	return messaging_send_one_or_all(msg_ctx,
					 dst,
					 MSG_DEBUG,
					 (const uint8_t *)debug_string,
					 strlen(debug_string) + 1);
}

NTSTATUS messaging_send_debug(struct messaging_context *msg_ctx,
			      struct server_id dst,
			      const char *debug_string)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_debug_v1(msg_ctx, dst, debug_string);
	}
	return messaging_send_debug_legacy(msg_ctx, dst, debug_string);
}

/* MSG_REQ_DEBUGLEVEL */

static NTSTATUS messaging_send_req_debuglevel_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_req_debuglevel msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_req_debuglevel_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(
		msg_ctx, dst, MSG_REQ_DEBUGLEVEL_V1, blob.data, blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_req_debuglevel_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	return messaging_send_one_or_all(
		msg_ctx, dst, MSG_REQ_DEBUGLEVEL, NULL, 0);
}

NTSTATUS messaging_send_req_debuglevel(struct messaging_context *msg_ctx,
				       struct server_id dst)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_req_debuglevel_v1(msg_ctx, dst);
	}
	return messaging_send_req_debuglevel_legacy(msg_ctx, dst);
}

/* MSG_PROFILE */

static NTSTATUS messaging_send_profile_v1(struct messaging_context *msg_ctx,
					  struct server_id dst,
					  int level)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_profile msg = {
		.info.info1.level = level,
	};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_profile_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(
		msg_ctx, dst, MSG_PROFILE_V1, blob.data, blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_profile_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	int level)
{
	return messaging_send_one_or_all(msg_ctx,
					 dst,
					 MSG_PROFILE,
					 (const uint8_t *)&level,
					 sizeof(int));
}

NTSTATUS messaging_send_profile(struct messaging_context *msg_ctx,
				struct server_id dst,
				int level)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_profile_v1(msg_ctx, dst, level);
	}
	return messaging_send_profile_legacy(msg_ctx, dst, level);
}

/* MSG_REQ_PROFILELEVEL */

static NTSTATUS messaging_send_req_profilelevel_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_req_profilelevel msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_req_profilelevel_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(msg_ctx,
					   dst,
					   MSG_REQ_PROFILELEVEL_V1,
					   blob.data,
					   blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_req_profilelevel_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	return messaging_send_one_or_all(
		msg_ctx, dst, MSG_REQ_PROFILELEVEL, NULL, 0);
}

NTSTATUS messaging_send_req_profilelevel(struct messaging_context *msg_ctx,
					 struct server_id dst)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_req_profilelevel_v1(msg_ctx, dst);
	}
	return messaging_send_req_profilelevel_legacy(msg_ctx, dst);
}

/* MSG_PING */

static NTSTATUS messaging_send_ping_v1(struct messaging_context *msg_ctx,
				       struct server_id dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_ping msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_ping_push(frame, &msg, "", &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(
		msg_ctx, dst, MSG_PING_V1, blob.data, blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_ping_legacy(struct messaging_context *msg_ctx,
					   struct server_id dst)
{
	return messaging_send_one_or_all(msg_ctx, dst, MSG_PING, NULL, 0);
}

NTSTATUS messaging_send_ping(struct messaging_context *msg_ctx,
			     struct server_id dst)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_ping_v1(msg_ctx, dst);
	}
	return messaging_send_ping_legacy(msg_ctx, dst);
}

/* MSG_SHUTDOWN */

static NTSTATUS messaging_send_shutdown_v1(struct messaging_context *msg_ctx,
					   struct server_id dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_shutdown msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_shutdown_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(
		msg_ctx, dst, MSG_SHUTDOWN_V1, blob.data, blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_shutdown_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	return messaging_send_one_or_all(msg_ctx, dst, MSG_SHUTDOWN, NULL, 0);
}

NTSTATUS messaging_send_shutdown(struct messaging_context *msg_ctx,
				 struct server_id dst)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_shutdown_v1(msg_ctx, dst);
	}
	return messaging_send_shutdown_legacy(msg_ctx, dst);
}

/* MSG_REQ_POOL_USAGE */

static NTSTATUS messaging_send_req_pool_usage_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	int fd)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_req_pool_usage msg = {};
	DATA_BLOB blob = data_blob_null;
	struct iovec iov;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_req_pool_usage_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	iov = (struct iovec){.iov_base = blob.data, .iov_len = blob.length};
	status = messaging_send_iov(
		msg_ctx, dst, MSG_REQ_POOL_USAGE_V1, &iov, 1, &fd, 1);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_req_pool_usage_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	int fd)
{
	return messaging_send_iov(
		msg_ctx, dst, MSG_REQ_POOL_USAGE, NULL, 0, &fd, 1);
}

NTSTATUS messaging_send_req_pool_usage(struct messaging_context *msg_ctx,
				       struct server_id dst,
				       int fd)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_req_pool_usage_v1(msg_ctx, dst, fd);
	}
	return messaging_send_req_pool_usage_legacy(msg_ctx, dst, fd);
}

/* MSG_REQ_DMALLOC_MARK */

static NTSTATUS messaging_send_req_dmalloc_mark_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_req_dmalloc_mark msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_req_dmalloc_mark_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(msg_ctx,
					   dst,
					   MSG_REQ_DMALLOC_MARK_V1,
					   blob.data,
					   blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_req_dmalloc_mark_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	return messaging_send_one_or_all(
		msg_ctx, dst, MSG_REQ_DMALLOC_MARK, NULL, 0);
}

NTSTATUS messaging_send_req_dmalloc_mark(struct messaging_context *msg_ctx,
					 struct server_id dst)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_req_dmalloc_mark_v1(msg_ctx, dst);
	}
	return messaging_send_req_dmalloc_mark_legacy(msg_ctx, dst);
}

/* MSG_REQ_DMALLOC_LOG_CHANGED */

static NTSTATUS messaging_send_req_dmalloc_log_changed_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_req_dmalloc_log_changed msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_req_dmalloc_log_changed_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(msg_ctx,
					   dst,
					   MSG_REQ_DMALLOC_LOG_CHANGED_V1,
					   blob.data,
					   blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_req_dmalloc_log_changed_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	return messaging_send_one_or_all(
		msg_ctx, dst, MSG_REQ_DMALLOC_LOG_CHANGED, NULL, 0);
}

NTSTATUS messaging_send_req_dmalloc_log_changed(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_req_dmalloc_log_changed_v1(msg_ctx,
								 dst);
	}
	return messaging_send_req_dmalloc_log_changed_legacy(msg_ctx, dst);
}

/* ID_CACHE_DELETE */

static NTSTATUS messaging_send_id_cache_delete_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	const char *id_string)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_id_cache_delete msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_id_cache_delete_push(frame, &msg, id_string, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(
		msg_ctx, dst, ID_CACHE_DELETE_V1, blob.data, blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_id_cache_delete_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	const char *id_string)
{
	size_t len = (id_string != NULL) ? strlen(id_string) + 1 : 0;

	return messaging_send_one_or_all(msg_ctx,
					 dst,
					 ID_CACHE_DELETE,
					 (const uint8_t *)id_string,
					 len);
}

NTSTATUS messaging_send_id_cache_delete(struct messaging_context *msg_ctx,
					struct server_id dst,
					const char *id_string)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_id_cache_delete_v1(msg_ctx,
							 dst,
							 id_string);
	}
	return messaging_send_id_cache_delete_legacy(msg_ctx, dst, id_string);
}

/* ID_CACHE_KILL */

static NTSTATUS messaging_send_id_cache_kill_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	const char *id_string)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_id_cache_kill msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_id_cache_kill_push(frame, &msg, id_string, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(
		msg_ctx, dst, ID_CACHE_KILL_V1, blob.data, blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_id_cache_kill_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	const char *id_string)
{
	size_t len = (id_string != NULL) ? strlen(id_string) + 1 : 0;

	return messaging_send_one_or_all(msg_ctx,
					 dst,
					 ID_CACHE_KILL,
					 (const uint8_t *)id_string,
					 len);
}

NTSTATUS messaging_send_id_cache_kill(struct messaging_context *msg_ctx,
				      struct server_id dst,
				      const char *id_string)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_id_cache_kill_v1(msg_ctx,
						       dst,
						       id_string);
	}
	return messaging_send_id_cache_kill_legacy(msg_ctx, dst, id_string);
}

/* MSG_SMB_CONF_UPDATED */

static NTSTATUS messaging_send_smb_conf_updated_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_smb_conf_updated msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_smb_conf_updated_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(msg_ctx,
					   dst,
					   MSG_SMB_CONF_UPDATED_V1,
					   blob.data,
					   blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_smb_conf_updated_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	return messaging_send_one_or_all(
		msg_ctx, dst, MSG_SMB_CONF_UPDATED, NULL, 0);
}

NTSTATUS messaging_send_smb_conf_updated(struct messaging_context *msg_ctx,
					 struct server_id dst)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_smb_conf_updated_v1(msg_ctx, dst);
	}
	return messaging_send_smb_conf_updated_legacy(msg_ctx, dst);
}

static NTSTATUS messaging_send_all_smb_conf_updated_v1(
	struct messaging_context *msg_ctx)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_smb_conf_updated msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;

	ndr_err = messaging_smb_conf_updated_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	messaging_send_all(
		msg_ctx, MSG_SMB_CONF_UPDATED_V1, blob.data, blob.length);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static NTSTATUS messaging_send_all_smb_conf_updated_legacy(
	struct messaging_context *msg_ctx)
{
	messaging_send_all(msg_ctx, MSG_SMB_CONF_UPDATED, NULL, 0);
	return NT_STATUS_OK;
}

NTSTATUS messaging_send_all_smb_conf_updated(
	struct messaging_context *msg_ctx)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_all_smb_conf_updated_v1(msg_ctx);
	}
	return messaging_send_all_smb_conf_updated_legacy(msg_ctx);
}

/* MSG_RELOAD_TLS_CERTIFICATES */

static NTSTATUS messaging_send_reload_tls_certificates_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_reload_tls_certificates msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_reload_tls_certificates_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(msg_ctx,
					   dst,
					   MSG_RELOAD_TLS_CERTIFICATES_V1,
					   blob.data,
					   blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_reload_tls_certificates_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	return messaging_send_one_or_all(
		msg_ctx, dst, MSG_RELOAD_TLS_CERTIFICATES, NULL, 0);
}

NTSTATUS messaging_send_reload_tls_certificates(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_reload_tls_certificates_v1(msg_ctx,
								 dst);
	}
	return messaging_send_reload_tls_certificates_legacy(msg_ctx, dst);
}

/* MSG_REQ_RINGBUF_LOG */

static NTSTATUS messaging_send_req_ringbuf_log_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_req_ringbuf_log msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_req_ringbuf_log_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(msg_ctx,
					   dst,
					   MSG_REQ_RINGBUF_LOG_V1,
					   blob.data,
					   blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_req_ringbuf_log_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	return messaging_send_one_or_all(
		msg_ctx, dst, MSG_REQ_RINGBUF_LOG, NULL, 0);
}

NTSTATUS messaging_send_req_ringbuf_log(struct messaging_context *msg_ctx,
					struct server_id dst)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_req_ringbuf_log_v1(msg_ctx, dst);
	}
	return messaging_send_req_ringbuf_log_legacy(msg_ctx, dst);
}

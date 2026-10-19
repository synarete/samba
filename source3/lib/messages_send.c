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
#include "librpc/gen_ndr/ndr_open_files.h"
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

/* MSG_FORCE_ELECTION */

static NTSTATUS messaging_send_force_election_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_force_election msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_force_election_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(
		msg_ctx, dst, MSG_FORCE_ELECTION_V1, blob.data, blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_force_election_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	return messaging_send_one_or_all(
		msg_ctx, dst, MSG_FORCE_ELECTION, NULL, 0);
}

NTSTATUS messaging_send_force_election(struct messaging_context *msg_ctx,
				       struct server_id dst)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_force_election_v1(msg_ctx, dst);
	}
	return messaging_send_force_election_legacy(msg_ctx, dst);
}

/* MSG_SMB_KILL_CLIENT_IP */

static NTSTATUS messaging_send_kill_client_ip_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	const char *ip_address)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_kill_client_ip msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_kill_client_ip_push(frame, &msg, ip_address, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(msg_ctx,
					   dst,
					   MSG_SMB_KILL_CLIENT_IP_V1,
					   blob.data,
					   blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_kill_client_ip_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	const char *ip_address)
{
	return messaging_send_one_or_all(msg_ctx,
					 dst,
					 MSG_SMB_KILL_CLIENT_IP,
					 (const uint8_t *)ip_address,
					 strlen(ip_address) + 1);
}

NTSTATUS messaging_send_kill_client_ip(struct messaging_context *msg_ctx,
				       struct server_id dst,
				       const char *ip_address)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_kill_client_ip_v1(msg_ctx,
							dst,
							ip_address);
	}
	return messaging_send_kill_client_ip_legacy(msg_ctx, dst, ip_address);
}

/* MSG_SMB_FORCE_TDIS */

static NTSTATUS messaging_send_force_tdis_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	const char *sharename)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_force_tdis msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_force_tdis_push(frame, &msg, sharename, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(
		msg_ctx, dst, MSG_SMB_FORCE_TDIS_V1, blob.data, blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_force_tdis_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	const char *sharename)
{
	return messaging_send_one_or_all(msg_ctx,
					 dst,
					 MSG_SMB_FORCE_TDIS,
					 (const uint8_t *)sharename,
					 strlen(sharename) + 1);
}

NTSTATUS messaging_send_force_tdis(struct messaging_context *msg_ctx,
				   struct server_id dst,
				   const char *sharename)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_force_tdis_v1(msg_ctx, dst, sharename);
	}
	return messaging_send_force_tdis_legacy(msg_ctx, dst, sharename);
}

NTSTATUS messaging_send_all_force_tdis(struct messaging_context *msg_ctx,
				       const char *sharename)
{
	/* A zero server_id (pid == 0) selects messaging_send_all() */
	return messaging_send_force_tdis(
		msg_ctx, (struct server_id){.pid = 0}, sharename);
}

/* MSG_SMB_FORCE_TDIS_DENIED */

static NTSTATUS messaging_send_force_tdis_denied_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	const char *sharename)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_force_tdis_denied msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_force_tdis_denied_push(frame,
						   &msg,
						   sharename,
						   &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(msg_ctx,
					   dst,
					   MSG_SMB_FORCE_TDIS_DENIED_V1,
					   blob.data,
					   blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_force_tdis_denied_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	const char *sharename)
{
	return messaging_send_one_or_all(msg_ctx,
					 dst,
					 MSG_SMB_FORCE_TDIS_DENIED,
					 (const uint8_t *)sharename,
					 strlen(sharename) + 1);
}

NTSTATUS messaging_send_force_tdis_denied(struct messaging_context *msg_ctx,
					  struct server_id dst,
					  const char *sharename)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_force_tdis_denied_v1(msg_ctx,
							   dst,
							   sharename);
	}
	return messaging_send_force_tdis_denied_legacy(msg_ctx, dst, sharename);
}

/* MSG_SMB_IP_DROPPED */

static NTSTATUS messaging_send_ip_dropped_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	const char *ip_address)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_smb_ip_dropped msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_smb_ip_dropped_push(frame, &msg, ip_address, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(
		msg_ctx, dst, MSG_SMB_IP_DROPPED_V1, blob.data, blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_ip_dropped_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	const char *ip_address)
{
	return messaging_send_one_or_all(msg_ctx,
					 dst,
					 MSG_SMB_IP_DROPPED,
					 (const uint8_t *)ip_address,
					 strlen(ip_address) + 1);
}

NTSTATUS messaging_send_ip_dropped(struct messaging_context *msg_ctx,
				   struct server_id dst,
				   const char *ip_address)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_ip_dropped_v1(msg_ctx, dst, ip_address);
	}
	return messaging_send_ip_dropped_legacy(msg_ctx, dst, ip_address);
}

/* MSG_SMB_SLEEP */

static NTSTATUS messaging_send_smb_sleep_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	unsigned int seconds)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_smb_sleep msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_smb_sleep_push(frame, &msg, seconds, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(
		msg_ctx, dst, MSG_SMB_SLEEP_V1, blob.data, blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_smb_sleep_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	unsigned int seconds)
{
	return messaging_send_one_or_all(msg_ctx,
					 dst,
					 MSG_SMB_SLEEP,
					 (const uint8_t *)&seconds,
					 sizeof(unsigned int));
}

NTSTATUS messaging_send_smb_sleep(struct messaging_context *msg_ctx,
				  struct server_id dst,
				  unsigned int seconds)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_smb_sleep_v1(msg_ctx, dst, seconds);
	}
	return messaging_send_smb_sleep_legacy(msg_ctx, dst, seconds);
}

/* MSG_SMB_TELL_NUM_CHILDREN */

static NTSTATUS messaging_send_tell_num_children_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_smb_tell_num_children msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_smb_tell_num_children_push(frame, &msg, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(msg_ctx,
					   dst,
					   MSG_SMB_TELL_NUM_CHILDREN_V1,
					   blob.data,
					   blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_tell_num_children_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst)
{
	return messaging_send_one_or_all(
		msg_ctx, dst, MSG_SMB_TELL_NUM_CHILDREN, NULL, 0);
}

NTSTATUS messaging_send_tell_num_children(struct messaging_context *msg_ctx,
					  struct server_id dst)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_tell_num_children_v1(msg_ctx, dst);
	}
	return messaging_send_tell_num_children_legacy(msg_ctx, dst);
}

/* MSG_SMB_INJECT_FAULT */

static NTSTATUS messaging_send_inject_fault_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	int32_t sig)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_smb_inject_fault msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_smb_inject_fault_push(frame, &msg, sig, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_one_or_all(msg_ctx,
					   dst,
					   MSG_SMB_INJECT_FAULT_V1,
					   blob.data,
					   blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_inject_fault_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	int32_t sig)
{
	return messaging_send_one_or_all(
		msg_ctx,
		dst,
		MSG_SMB_INJECT_FAULT,
		(const uint8_t *)&sig,
		sizeof(int32_t));
}

NTSTATUS messaging_send_inject_fault(struct messaging_context *msg_ctx,
				     struct server_id dst,
				     int32_t sig)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_inject_fault_v1(msg_ctx, dst, sig);
	}
	return messaging_send_inject_fault_legacy(msg_ctx, dst, sig);
}

/* MSG_SMB_CLOSE_FILE */

static NTSTATUS messaging_send_close_file_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	struct file_id id,
	uint64_t share_file_id)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_smb_close_file msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_smb_close_file_push(
		frame, &msg, id, share_file_id, &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_buf(msg_ctx,
				    dst,
				    MSG_SMB_CLOSE_FILE_V1,
				    blob.data,
				    blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_close_file_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	struct file_id id,
	uint64_t share_file_id)
{
	struct oplock_break_message brk = {
		.id = id,
		.share_file_id = share_file_id,
	};
	uint8_t msgbuf[33];
	DATA_BLOB blob = { .data = msgbuf, .length = sizeof(msgbuf) };
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_into_fixed_blob(
		&blob,
		&brk,
		(ndr_push_flags_fn_t)ndr_push_oplock_break_message);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	return messaging_send_buf(msg_ctx,
				  dst,
				  MSG_SMB_CLOSE_FILE,
				  blob.data,
				  blob.length);
}

NTSTATUS messaging_send_close_file(struct messaging_context *msg_ctx,
				   struct server_id dst,
				   struct file_id id,
				   uint64_t share_file_id)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_close_file_v1(
			msg_ctx, dst, id, share_file_id);
	}
	return messaging_send_close_file_legacy(
		msg_ctx, dst, id, share_file_id);
}

/* MSG_SMB_FILE_RENAME */

static NTSTATUS messaging_send_file_rename_v1(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	struct file_id id,
	uint64_t share_file_id,
	const char *servicepath,
	const char *base_name,
	const char *stream_name)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct messaging_smb_file_rename msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = messaging_smb_file_rename_push(frame,
						 &msg,
						 id,
						 share_file_id,
						 servicepath,
						 base_name,
						 stream_name,
						 &blob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_buf(msg_ctx,
				    dst,
				    MSG_SMB_FILE_RENAME_V1,
				    blob.data,
				    blob.length);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS messaging_send_file_rename_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst,
	struct file_id id,
	uint64_t share_file_id,
	const char *servicepath,
	const char *base_name,
	const char *stream_name)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct file_rename_message frm = {
		.id = id,
		.share_file_id = share_file_id,
		.servicepath = servicepath,
		.base_name = base_name,
		.stream_name = stream_name,
	};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	ndr_err = ndr_push_struct_blob(
		&blob,
		frame,
		&frm,
		(ndr_push_flags_fn_t)ndr_push_file_rename_message);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	status = messaging_send_buf(msg_ctx,
				    dst,
				    MSG_SMB_FILE_RENAME,
				    blob.data,
				    blob.length);
	TALLOC_FREE(frame);
	return status;
}

NTSTATUS messaging_send_file_rename(struct messaging_context *msg_ctx,
				    struct server_id dst,
				    struct file_id id,
				    uint64_t share_file_id,
				    const char *servicepath,
				    const char *base_name,
				    const char *stream_name)
{
	if (CLUSTER_LEVEL_ACTIVE(2, 0)) {
		return messaging_send_file_rename_v1(msg_ctx,
						     dst,
						     id,
						     share_file_id,
						     servicepath,
						     base_name,
						     stream_name);
	}
	return messaging_send_file_rename_legacy(msg_ctx,
						 dst,
						 id,
						 share_file_id,
						 servicepath,
						 base_name,
						 stream_name);
}

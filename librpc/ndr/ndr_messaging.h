/*
   Unix SMB/CIFS implementation.

   Helper routines for messaging IDL-based messages

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

#ifndef __LIBRPC_NDR_NDR_MESSAGING_H__
#define __LIBRPC_NDR_NDR_MESSAGING_H__

#include "librpc/gen_ndr/messaging.h"

/* MSG_PING_V1 / MSG_PONG_V1 */

enum ndr_err_code messaging_ping_v1_push(TALLOC_CTX *mem_ctx,
					 struct messaging_ping_v1 *msg,
					 const char *payload,
					 DATA_BLOB *blob);

enum ndr_err_code messaging_ping_v1_pull(TALLOC_CTX *mem_ctx,
					 const DATA_BLOB *blob,
					 struct messaging_ping_v1 *msg);

enum ndr_err_code messaging_pong_v1_push(TALLOC_CTX *mem_ctx,
					 struct messaging_pong_v1 *msg,
					 DATA_BLOB *blob);

enum ndr_err_code messaging_pong_v1_pull(TALLOC_CTX *mem_ctx,
					 const DATA_BLOB *blob,
					 struct messaging_pong_v1 *msg);

/* MSG_DEBUG_V1 */

enum ndr_err_code messaging_debug_v1_push(TALLOC_CTX *mem_ctx,
					  struct messaging_debug_v1 *msg,
					  DATA_BLOB *blob);

enum ndr_err_code messaging_debug_v1_pull(TALLOC_CTX *mem_ctx,
					  const DATA_BLOB *blob,
					  struct messaging_debug_v1 *msg);

/* MSG_PROFILE_V1 */

enum ndr_err_code messaging_profile_v1_push(TALLOC_CTX *mem_ctx,
					    struct messaging_profile_v1 *msg,
					    DATA_BLOB *blob);

enum ndr_err_code messaging_profile_v1_pull(TALLOC_CTX *mem_ctx,
					    const DATA_BLOB *blob,
					    struct messaging_profile_v1 *msg);

/* MSG_REQ_DEBUGLEVEL_V1 / MSG_DEBUGLEVEL_V1 */

enum ndr_err_code messaging_req_debuglevel_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_debuglevel *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_req_debuglevel_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_debuglevel *msg);

enum ndr_err_code messaging_debuglevel_push(TALLOC_CTX *mem_ctx,
					    struct messaging_debuglevel *msg,
					    DATA_BLOB *blob);

enum ndr_err_code messaging_debuglevel_pull(TALLOC_CTX *mem_ctx,
					    const DATA_BLOB *blob,
					    struct messaging_debuglevel *msg);

/* MSG_REQ_PROFILELEVEL_V1 / MSG_PROFILELEVEL_V1 */

enum ndr_err_code messaging_req_pool_usage_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_pool_usage *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_req_pool_usage_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_pool_usage *msg);

enum ndr_err_code messaging_req_dmalloc_mark_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_dmalloc_mark *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_req_dmalloc_mark_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_dmalloc_mark *msg);

enum ndr_err_code messaging_req_dmalloc_log_changed_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_dmalloc_log_changed *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_req_dmalloc_log_changed_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_dmalloc_log_changed *msg);

enum ndr_err_code messaging_req_profilelevel_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_profilelevel *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_req_profilelevel_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_profilelevel *msg);

enum ndr_err_code messaging_profilelevel_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_profilelevel *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_profilelevel_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_profilelevel *msg);

/* ID_CACHE_DELETE_V1 / ID_CACHE_KILL_V1 */

enum ndr_err_code messaging_id_cache_delete_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_id_cache_delete *msg,
	const char *id,
	DATA_BLOB *blob);

enum ndr_err_code messaging_id_cache_delete_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_id_cache_delete *msg);

enum ndr_err_code messaging_id_cache_kill_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_id_cache_kill *msg,
	const char *id,
	DATA_BLOB *blob);

enum ndr_err_code messaging_id_cache_kill_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_id_cache_kill *msg);

/* MSG_REQ_RINGBUF_LOG_V1 / MSG_RINGBUF_LOG_V1 */

enum ndr_err_code messaging_req_ringbuf_log_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_ringbuf_log *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_req_ringbuf_log_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_ringbuf_log *msg);

enum ndr_err_code messaging_ringbuf_log_push(TALLOC_CTX *mem_ctx,
					     struct messaging_ringbuf_log *msg,
					     const char *log,
					     DATA_BLOB *blob);

enum ndr_err_code messaging_ringbuf_log_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_ringbuf_log *msg);

/* MSG_DAEMON_READY_FD_V1 */

enum ndr_err_code messaging_daemon_ready_fd_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_daemon_ready_fd *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_daemon_ready_fd_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_daemon_ready_fd *msg);

/* MSG_FORCE_ELECTION_V1 */

enum ndr_err_code messaging_force_election_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_force_election *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_force_election_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_force_election *msg);

/* MSG_RELOAD_TLS_CERTIFICATES_V1 */

enum ndr_err_code messaging_reload_tls_certificates_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_reload_tls_certificates *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_reload_tls_certificates_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_reload_tls_certificates *msg);

/* MSG_SMB_CONF_UPDATED_V1 */

enum ndr_err_code messaging_smb_conf_updated_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_conf_updated *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_smb_conf_updated_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_conf_updated *msg);

/* MSG_SHUTDOWN_V1 */

enum ndr_err_code messaging_shutdown_push(TALLOC_CTX *mem_ctx,
					  struct messaging_shutdown *msg,
					  DATA_BLOB *blob);

enum ndr_err_code messaging_shutdown_pull(TALLOC_CTX *mem_ctx,
					  const DATA_BLOB *blob,
					  struct messaging_shutdown *msg);

#endif /* __LIBRPC_NDR_NDR_MESSAGING_H__ */

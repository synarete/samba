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

enum ndr_err_code messaging_debug_v1_push(TALLOC_CTX *mem_ctx,
					  struct messaging_debug_v1 *msg,
					  DATA_BLOB *blob);

enum ndr_err_code messaging_debug_v1_pull(TALLOC_CTX *mem_ctx,
					  const DATA_BLOB *blob,
					  struct messaging_debug_v1 *msg);

enum ndr_err_code messaging_req_debuglevel_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_debuglevel_v1 *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_req_debuglevel_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_debuglevel_v1 *msg);

enum ndr_err_code messaging_debuglevel_v1_push(TALLOC_CTX *mem_ctx,
					       struct messaging_debuglevel_v1 *msg,
					       DATA_BLOB *blob);

enum ndr_err_code messaging_debuglevel_v1_pull(TALLOC_CTX *mem_ctx,
					       const DATA_BLOB *blob,
					       struct messaging_debuglevel_v1 *msg);

enum ndr_err_code messaging_profile_v1_push(TALLOC_CTX *mem_ctx,
					    struct messaging_profile_v1 *msg,
					    DATA_BLOB *blob);

enum ndr_err_code messaging_profile_v1_pull(TALLOC_CTX *mem_ctx,
					    const DATA_BLOB *blob,
					    struct messaging_profile_v1 *msg);

enum ndr_err_code messaging_req_profilelevel_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_profilelevel_v1 *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_req_profilelevel_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_profilelevel_v1 *msg);

enum ndr_err_code messaging_profilelevel_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_profilelevel_v1 *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_profilelevel_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_profilelevel_v1 *msg);

enum ndr_err_code messaging_req_pool_usage_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_pool_usage_v1 *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_req_pool_usage_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_pool_usage_v1 *msg);

enum ndr_err_code messaging_req_dmalloc_mark_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_dmalloc_mark_v1 *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_req_dmalloc_mark_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_dmalloc_mark_v1 *msg);

enum ndr_err_code messaging_req_dmalloc_log_changed_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_dmalloc_log_changed_v1 *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_req_dmalloc_log_changed_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_dmalloc_log_changed_v1 *msg);

enum ndr_err_code messaging_shutdown_v1_push(TALLOC_CTX *mem_ctx,
					     struct messaging_shutdown_v1 *msg,
					     DATA_BLOB *blob);

enum ndr_err_code messaging_shutdown_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_shutdown_v1 *msg);

enum ndr_err_code messaging_id_cache_delete_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_id_cache_delete_v1 *msg,
	const char *id,
	DATA_BLOB *blob);

enum ndr_err_code messaging_id_cache_delete_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_id_cache_delete_v1 *msg);

enum ndr_err_code messaging_id_cache_kill_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_id_cache_kill_v1 *msg,
	const char *id,
	DATA_BLOB *blob);

enum ndr_err_code messaging_id_cache_kill_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_id_cache_kill_v1 *msg);

/* MSG_RELOAD_TLS_CERTIFICATES_V1 */

enum ndr_err_code messaging_reload_tls_certificates_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_reload_tls_certificates_v1 *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_reload_tls_certificates_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_reload_tls_certificates_v1 *msg);

enum ndr_err_code messaging_smb_conf_updated_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_conf_updated_v1 *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_smb_conf_updated_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_conf_updated_v1 *msg);

#endif /* __LIBRPC_NDR_NDR_MESSAGING_H__ */

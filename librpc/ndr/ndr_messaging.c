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

#include "includes.h"
#include "librpc/gen_ndr/ndr_messaging.h"
#include "librpc/ndr/ndr_messaging.h"

enum ndr_err_code messaging_ping_v1_push(TALLOC_CTX *mem_ctx,
					 struct messaging_ping_v1 *msg,
					 const char *payload,
					 DATA_BLOB *blob)
{
	msg->version = MESSAGING_PING_VERSION_CURRENT;
	msg->payload = payload;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_ping_v1);
}

enum ndr_err_code messaging_ping_v1_pull(TALLOC_CTX *mem_ctx,
					 const DATA_BLOB *blob,
					 struct messaging_ping_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_ping_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PING_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_pong_v1_push(TALLOC_CTX *mem_ctx,
					 struct messaging_pong_v1 *msg,
					 DATA_BLOB *blob)
{
	msg->version = MESSAGING_PING_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_pong_v1);
}

enum ndr_err_code messaging_pong_v1_pull(TALLOC_CTX *mem_ctx,
					 const DATA_BLOB *blob,
					 struct messaging_pong_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_pong_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PING_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_debug_v1_push(TALLOC_CTX *mem_ctx,
					  struct messaging_debug_v1 *msg,
					  DATA_BLOB *blob)
{
	msg->version = MESSAGING_DEBUG_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_debug_v1);
}

enum ndr_err_code messaging_debug_v1_pull(TALLOC_CTX *mem_ctx,
					  const DATA_BLOB *blob,
					  struct messaging_debug_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_debug_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_DEBUG_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_debuglevel_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_debuglevel_v1 *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_DEBUGLEVEL_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_req_debuglevel_v1);
}

enum ndr_err_code messaging_req_debuglevel_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_debuglevel_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_req_debuglevel_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_DEBUGLEVEL_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_debuglevel_v1_push(TALLOC_CTX *mem_ctx,
					       struct messaging_debuglevel_v1 *msg,
					       DATA_BLOB *blob)
{
	msg->version = MESSAGING_DEBUGLEVEL_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_debuglevel_v1);
}

enum ndr_err_code messaging_debuglevel_v1_pull(TALLOC_CTX *mem_ctx,
					       const DATA_BLOB *blob,
					       struct messaging_debuglevel_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_debuglevel_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_DEBUGLEVEL_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_profile_v1_push(TALLOC_CTX *mem_ctx,
					    struct messaging_profile_v1 *msg,
					    DATA_BLOB *blob)
{
	msg->version = MESSAGING_PROFILE_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_profile_v1);
}

enum ndr_err_code messaging_profile_v1_pull(TALLOC_CTX *mem_ctx,
					    const DATA_BLOB *blob,
					    struct messaging_profile_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_profile_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PROFILE_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_profilelevel_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_profilelevel_v1 *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_PROFILELEVEL_VERSION_CURRENT;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_req_profilelevel_v1);
}

enum ndr_err_code messaging_req_profilelevel_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_profilelevel_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_req_profilelevel_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PROFILELEVEL_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_profilelevel_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_profilelevel_v1 *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_PROFILELEVEL_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_profilelevel_v1);
}

enum ndr_err_code messaging_profilelevel_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_profilelevel_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_profilelevel_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PROFILELEVEL_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_pool_usage_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_pool_usage_v1 *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_REQ_POOL_USAGE_VERSION_CURRENT;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_req_pool_usage_v1);
}

enum ndr_err_code messaging_req_pool_usage_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_pool_usage_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_req_pool_usage_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_REQ_POOL_USAGE_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_dmalloc_mark_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_dmalloc_mark_v1 *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_REQ_DMALLOC_VERSION_CURRENT;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_req_dmalloc_mark_v1);
}

enum ndr_err_code messaging_req_dmalloc_mark_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_dmalloc_mark_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_req_dmalloc_mark_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_REQ_DMALLOC_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_dmalloc_log_changed_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_dmalloc_log_changed_v1 *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_REQ_DMALLOC_VERSION_CURRENT;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)
			ndr_push_messaging_req_dmalloc_log_changed_v1);
}

enum ndr_err_code messaging_req_dmalloc_log_changed_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_dmalloc_log_changed_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)
			ndr_pull_messaging_req_dmalloc_log_changed_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_REQ_DMALLOC_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_shutdown_v1_push(TALLOC_CTX *mem_ctx,
					     struct messaging_shutdown_v1 *msg,
					     DATA_BLOB *blob)
{
	msg->version = MESSAGING_SHUTDOWN_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_shutdown_v1);
}

enum ndr_err_code messaging_shutdown_v1_pull(TALLOC_CTX *mem_ctx,
					     const DATA_BLOB *blob,
					     struct messaging_shutdown_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_shutdown_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SHUTDOWN_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_id_cache_delete_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_id_cache_delete_v1 *msg,
	const char *id,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_ID_CACHE_VERSION_CURRENT;
	msg->id = id;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_id_cache_delete_v1);
}

enum ndr_err_code messaging_id_cache_delete_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_id_cache_delete_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_id_cache_delete_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_ID_CACHE_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_id_cache_kill_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_id_cache_kill_v1 *msg,
	const char *id,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_ID_CACHE_VERSION_CURRENT;
	msg->id = id;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_id_cache_kill_v1);
}

enum ndr_err_code messaging_id_cache_kill_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_id_cache_kill_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_id_cache_kill_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_ID_CACHE_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_reload_tls_certificates_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_reload_tls_certificates_v1 *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_RELOAD_TLS_CERTIFICATES_VERSION_CURRENT;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)
			ndr_push_messaging_reload_tls_certificates_v1);
}

enum ndr_err_code messaging_reload_tls_certificates_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_reload_tls_certificates_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)
			ndr_pull_messaging_reload_tls_certificates_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_RELOAD_TLS_CERTIFICATES_VERSION_CURRENT)
	{
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_conf_updated_v1_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_conf_updated_v1 *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_SMB_CONF_UPDATED_VERSION_CURRENT;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_smb_conf_updated_v1);
}

enum ndr_err_code messaging_smb_conf_updated_v1_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_conf_updated_v1 *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_conf_updated_v1);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_CONF_UPDATED_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

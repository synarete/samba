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

enum ndr_err_code messaging_debug_push(TALLOC_CTX *mem_ctx,
				       struct messaging_debug *msg,
				       DATA_BLOB *blob)
{
	msg->version = MESSAGING_DEBUG_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_debug);
}

enum ndr_err_code messaging_debug_pull(TALLOC_CTX *mem_ctx,
				       const DATA_BLOB *blob,
				       struct messaging_debug *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_debug);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_DEBUG_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_ping_push(TALLOC_CTX *mem_ctx,
				      struct messaging_ping *msg,
				      const char *payload,
				      DATA_BLOB *blob)
{
	msg->version = MESSAGING_PING_VERSION_CURRENT;
	msg->payload = payload;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_ping);
}

enum ndr_err_code messaging_ping_pull(TALLOC_CTX *mem_ctx,
				      const DATA_BLOB *blob,
				      struct messaging_ping *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_ping);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PING_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_pong_push(TALLOC_CTX *mem_ctx,
				      struct messaging_pong *msg,
				      DATA_BLOB *blob)
{
	msg->version = MESSAGING_PING_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_pong);
}

enum ndr_err_code messaging_pong_pull(TALLOC_CTX *mem_ctx,
				      const DATA_BLOB *blob,
				      struct messaging_pong *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_pong);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PING_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_profile_push(TALLOC_CTX *mem_ctx,
					 struct messaging_profile *msg,
					 DATA_BLOB *blob)
{
	msg->version = MESSAGING_PROFILE_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_profile);
}

enum ndr_err_code messaging_profile_pull(TALLOC_CTX *mem_ctx,
					 const DATA_BLOB *blob,
					 struct messaging_profile *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_profile);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PROFILE_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_shutdown_push(TALLOC_CTX *mem_ctx,
					  struct messaging_shutdown *msg,
					  DATA_BLOB *blob)
{
	msg->version = MESSAGING_SHUTDOWN_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_shutdown);
}

enum ndr_err_code messaging_shutdown_pull(TALLOC_CTX *mem_ctx,
					  const DATA_BLOB *blob,
					  struct messaging_shutdown *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_shutdown);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SHUTDOWN_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_id_cache_delete_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_id_cache_delete *msg,
	const char *id,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_ID_CACHE_VERSION_CURRENT;
	msg->id = id;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_id_cache_delete);
}

enum ndr_err_code messaging_id_cache_delete_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_id_cache_delete *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_id_cache_delete);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_ID_CACHE_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_id_cache_kill_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_id_cache_kill *msg,
	const char *id,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_ID_CACHE_VERSION_CURRENT;
	msg->id = id;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_id_cache_kill);
}

enum ndr_err_code messaging_id_cache_kill_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_id_cache_kill *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_id_cache_kill);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_ID_CACHE_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_conf_updated_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_conf_updated *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_SMB_CONF_UPDATED_VERSION_CURRENT;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_smb_conf_updated);
}

enum ndr_err_code messaging_smb_conf_updated_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_conf_updated *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_conf_updated);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_CONF_UPDATED_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_reload_tls_certificates_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_reload_tls_certificates *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_RELOAD_TLS_CERTIFICATES_VERSION_CURRENT;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)
			ndr_push_messaging_reload_tls_certificates);
}

enum ndr_err_code messaging_reload_tls_certificates_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_reload_tls_certificates *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)
			ndr_pull_messaging_reload_tls_certificates);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_RELOAD_TLS_CERTIFICATES_VERSION_CURRENT)
	{
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_pool_usage_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_pool_usage *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_REQ_POOL_USAGE_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_req_pool_usage);
}

enum ndr_err_code messaging_req_pool_usage_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_pool_usage *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_req_pool_usage);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_REQ_POOL_USAGE_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_dmalloc_mark_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_dmalloc_mark *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_REQ_DMALLOC_VERSION_CURRENT;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_req_dmalloc_mark);
}

enum ndr_err_code messaging_req_dmalloc_mark_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_dmalloc_mark *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_req_dmalloc_mark);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_REQ_DMALLOC_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_dmalloc_log_changed_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_dmalloc_log_changed *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_REQ_DMALLOC_VERSION_CURRENT;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)
			ndr_push_messaging_req_dmalloc_log_changed);
}

enum ndr_err_code messaging_req_dmalloc_log_changed_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_dmalloc_log_changed *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)
			ndr_pull_messaging_req_dmalloc_log_changed);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_REQ_DMALLOC_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_profilelevel_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_profilelevel *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_PROFILELEVEL_VERSION_CURRENT;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_req_profilelevel);
}

enum ndr_err_code messaging_req_profilelevel_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_profilelevel *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_req_profilelevel);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PROFILELEVEL_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_profilelevel_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_profilelevel *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_PROFILELEVEL_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_profilelevel);
}

enum ndr_err_code messaging_profilelevel_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_profilelevel *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_profilelevel);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PROFILELEVEL_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_debuglevel_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_req_debuglevel *msg,
	DATA_BLOB *blob)
{
	msg->version = MESSAGING_DEBUGLEVEL_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_req_debuglevel);
}

enum ndr_err_code messaging_req_debuglevel_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_debuglevel *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_req_debuglevel);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_DEBUGLEVEL_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_debuglevel_push(TALLOC_CTX *mem_ctx,
					    struct messaging_debuglevel *msg,
					    DATA_BLOB *blob)
{
	msg->version = MESSAGING_DEBUGLEVEL_VERSION_CURRENT;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_debuglevel);
}

enum ndr_err_code messaging_debuglevel_pull(TALLOC_CTX *mem_ctx,
					    const DATA_BLOB *blob,
					    struct messaging_debuglevel *msg)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_debuglevel);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_DEBUGLEVEL_VERSION_CURRENT) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

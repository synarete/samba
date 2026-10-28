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
				       const struct messaging_debug *msg,
				       DATA_BLOB *blob)
{
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

	*msg = (struct messaging_debug){0};

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_debug);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_DEBUG_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_debuglevel_push(
	TALLOC_CTX *mem_ctx,
	const struct messaging_req_debuglevel *msg,
	DATA_BLOB *blob)
{
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

	*msg = (struct messaging_req_debuglevel){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_req_debuglevel);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_DEBUGLEVEL_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_debuglevel_push(
	TALLOC_CTX *mem_ctx,
	const struct messaging_debuglevel *msg,
	DATA_BLOB *blob)
{
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

	*msg = (struct messaging_debuglevel){0};

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_debuglevel);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_DEBUGLEVEL_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_profile_push(TALLOC_CTX *mem_ctx,
					 const struct messaging_profile *msg,
					 DATA_BLOB *blob)
{
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

	*msg = (struct messaging_profile){0};

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_profile);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PROFILE_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_profilelevel_push(
	TALLOC_CTX *mem_ctx,
	const struct messaging_req_profilelevel *msg,
	DATA_BLOB *blob)
{
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

	*msg = (struct messaging_req_profilelevel){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_req_profilelevel);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PROFILELEVEL_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_profilelevel_push(
	TALLOC_CTX *mem_ctx,
	const struct messaging_profilelevel *msg,
	DATA_BLOB *blob)
{
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

	*msg = (struct messaging_profilelevel){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_profilelevel);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PROFILELEVEL_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_ping_push(TALLOC_CTX *mem_ctx,
				      struct messaging_ping *msg,
				      const char *payload,
				      DATA_BLOB *blob)
{
	msg->info.info1.payload = payload;
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

	*msg = (struct messaging_ping){0};

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_ping);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PING_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_pong_push(TALLOC_CTX *mem_ctx,
				      const struct messaging_pong *msg,
				      DATA_BLOB *blob)
{
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

	*msg = (struct messaging_pong){0};

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_pong);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PING_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_pool_usage_push(
	TALLOC_CTX *mem_ctx,
	const struct messaging_req_pool_usage *msg,
	DATA_BLOB *blob)
{
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

	*msg = (struct messaging_req_pool_usage){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_req_pool_usage);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_POOL_USAGE_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_dmalloc_mark_push(
	TALLOC_CTX *mem_ctx,
	const struct messaging_req_dmalloc_mark *msg,
	DATA_BLOB *blob)
{
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

	*msg = (struct messaging_req_dmalloc_mark){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_req_dmalloc_mark);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_DMALLOC_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_dmalloc_log_changed_push(
	TALLOC_CTX *mem_ctx,
	const struct messaging_req_dmalloc_log_changed *msg,
	DATA_BLOB *blob)
{
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

	*msg = (struct messaging_req_dmalloc_log_changed){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)
			ndr_pull_messaging_req_dmalloc_log_changed);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_DMALLOC_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_id_cache_delete_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_id_cache_delete *msg,
	const char *id_string,
	DATA_BLOB *blob)
{
	msg->info.info1.id_string = id_string;
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

	*msg = (struct messaging_id_cache_delete){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_id_cache_delete);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_ID_CACHE_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_id_cache_kill_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_id_cache_kill *msg,
	const char *id_string,
	DATA_BLOB *blob)
{
	msg->info.info1.id_string = id_string;
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

	*msg = (struct messaging_id_cache_kill){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_id_cache_kill);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_ID_CACHE_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_conf_updated_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_conf_updated *msg,
	DATA_BLOB *blob)
{
	msg->info.info1 = (struct messaging_smb_conf_updated_v1){};
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

	*msg = (struct messaging_smb_conf_updated){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_conf_updated);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_CONF_UPDATED_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_reload_tls_certificates_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_reload_tls_certificates *msg,
	DATA_BLOB *blob)
{
	msg->info.info1 = (struct messaging_reload_tls_certificates_v1){};
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

	*msg = (struct messaging_reload_tls_certificates){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)
			ndr_pull_messaging_reload_tls_certificates);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_RELOAD_TLS_CERTIFICATES_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_shutdown_push(TALLOC_CTX *mem_ctx,
					  struct messaging_shutdown *msg,
					  DATA_BLOB *blob)
{
	msg->info.info1 = (struct messaging_shutdown_v1){};
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

	*msg = (struct messaging_shutdown){0};

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_shutdown);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SHUTDOWN_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_req_ringbuf_log_push(
	TALLOC_CTX *mem_ctx,
	const struct messaging_req_ringbuf_log *msg,
	DATA_BLOB *blob)
{
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_req_ringbuf_log);
}

enum ndr_err_code messaging_req_ringbuf_log_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_req_ringbuf_log *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_req_ringbuf_log){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_req_ringbuf_log);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_RINGBUF_LOG_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_ringbuf_log_push(TALLOC_CTX *mem_ctx,
					     struct messaging_ringbuf_log *msg,
					     const char *log_string,
					     DATA_BLOB *blob)
{
	msg->info.info1.log_string = log_string;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_ringbuf_log);
}

enum ndr_err_code messaging_ringbuf_log_pull(TALLOC_CTX *mem_ctx,
					     const DATA_BLOB *blob,
					     struct messaging_ringbuf_log *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_ringbuf_log){0};

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_ringbuf_log);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_RINGBUF_LOG_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_force_election_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_force_election *msg,
	DATA_BLOB *blob)
{
	msg->info.info1 = (struct messaging_force_election_v1){};
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_force_election);
}

enum ndr_err_code messaging_force_election_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_force_election *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_force_election){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_force_election);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_FORCE_ELECTION_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_force_tdis_push(TALLOC_CTX *mem_ctx,
					    struct messaging_force_tdis *msg,
					    const char *sharename,
					    DATA_BLOB *blob)
{
	msg->info.info1.sharename = sharename;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_force_tdis);
}

enum ndr_err_code messaging_force_tdis_pull(TALLOC_CTX *mem_ctx,
					    const DATA_BLOB *blob,
					    struct messaging_force_tdis *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_force_tdis){0};

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_force_tdis);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_FORCE_TDIS_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_force_tdis_denied_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_force_tdis_denied *msg,
	const char *sharename,
	DATA_BLOB *blob)
{
	msg->info.info1.sharename = sharename;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_force_tdis_denied);
}

enum ndr_err_code messaging_force_tdis_denied_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_force_tdis_denied *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_force_tdis_denied){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_force_tdis_denied);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_FORCE_TDIS_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_kill_client_ip_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_kill_client_ip *msg,
	const char *ip_address,
	DATA_BLOB *blob)
{
	msg->info.info1.ip_address = ip_address;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_kill_client_ip);
}

enum ndr_err_code messaging_kill_client_ip_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_kill_client_ip *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_kill_client_ip){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_kill_client_ip);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_KILL_CLIENT_IP_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_ip_dropped_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_ip_dropped *msg,
	const char *ip_address,
	DATA_BLOB *blob)
{
	msg->info.info1.ip_address = ip_address;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_smb_ip_dropped);
}

enum ndr_err_code messaging_smb_ip_dropped_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_ip_dropped *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_ip_dropped){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_ip_dropped);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_IP_DROPPED_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_sleep_push(TALLOC_CTX *mem_ctx,
					   struct messaging_smb_sleep *msg,
					   uint32_t seconds,
					   DATA_BLOB *blob)
{
	msg->info.info1.seconds = seconds;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_smb_sleep);
}

enum ndr_err_code messaging_smb_sleep_pull(TALLOC_CTX *mem_ctx,
					   const DATA_BLOB *blob,
					   struct messaging_smb_sleep *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_sleep){0};

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_smb_sleep);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_SLEEP_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_tell_num_children_push(
	TALLOC_CTX *mem_ctx,
	const struct messaging_smb_tell_num_children *msg,
	DATA_BLOB *blob)
{
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_smb_tell_num_children);
}

enum ndr_err_code messaging_smb_tell_num_children_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_tell_num_children *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_tell_num_children){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_tell_num_children);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_NUM_CHILDREN_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_num_children_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_num_children *msg,
	uint32_t num_children,
	DATA_BLOB *blob)
{
	msg->info.info1.num_children = num_children;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_smb_num_children);
}

enum ndr_err_code messaging_smb_num_children_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_num_children *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_num_children){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_num_children);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_NUM_CHILDREN_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_inject_fault_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_inject_fault *msg,
	int32_t signal,
	DATA_BLOB *blob)
{
	msg->info.info1.signal = signal;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_smb_inject_fault);
}

enum ndr_err_code messaging_smb_inject_fault_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_inject_fault *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_inject_fault){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_inject_fault);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_INJECT_FAULT_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_close_file_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_close_file *msg,
	struct file_id id,
	uint64_t share_file_id,
	DATA_BLOB *blob)
{
	msg->info.info1.id = id;
	msg->info.info1.share_file_id = share_file_id;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_smb_close_file);
}

enum ndr_err_code messaging_smb_close_file_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_close_file *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_close_file){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_close_file);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_CLOSE_FILE_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_file_rename_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_file_rename *msg,
	struct file_id id,
	uint64_t share_file_id,
	const char *servicepath,
	const char *base_name,
	const char *stream_name,
	DATA_BLOB *blob)
{
	msg->info.info1.id = id;
	msg->info.info1.share_file_id = share_file_id;
	msg->info.info1.servicepath = servicepath != NULL ? servicepath : "";
	msg->info.info1.base_name = base_name != NULL ? base_name : "";
	msg->info.info1.stream_name = stream_name != NULL ? stream_name : "";
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_smb_file_rename);
}

enum ndr_err_code messaging_smb_file_rename_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_file_rename *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_file_rename){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_file_rename);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_FILE_RENAME_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_scavenger_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_scavenger *msg,
	struct file_id id,
	uint64_t open_persistent_id,
	uint32_t name_hash,
	DATA_BLOB *blob)
{
	msg->info.info1.id = id;
	msg->info.info1.open_persistent_id = open_persistent_id;
	msg->info.info1.name_hash = name_hash;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_smb_scavenger);
}

enum ndr_err_code messaging_smb_scavenger_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_scavenger *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_scavenger){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_scavenger);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_SCAVENGER_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_notify_push(TALLOC_CTX *mem_ctx,
					    struct messaging_smb_notify *msg,
					    DATA_BLOB *blob)
{
	msg->info.info1 = (struct messaging_smb_notify_v1){};
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_smb_notify);
}

enum ndr_err_code messaging_smb_notify_pull(TALLOC_CTX *mem_ctx,
					    const DATA_BLOB *blob,
					    struct messaging_smb_notify *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_notify){0};

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_smb_notify);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_NOTIFY_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_notify_cleanup_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_notify_cleanup *msg,
	DATA_BLOB *blob)
{
	msg->info.info1 = (struct messaging_smb_notify_cleanup_v1){};
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_smb_notify_cleanup);
}

enum ndr_err_code messaging_smb_notify_cleanup_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_notify_cleanup *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_notify_cleanup){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_notify_cleanup);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_NOTIFY_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_notify_cancel_deleted_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_notify_cancel_deleted *msg,
	struct file_id fid,
	DATA_BLOB *blob)
{
	msg->info.info1.fid = fid;
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)
			ndr_push_messaging_smb_notify_cancel_deleted);
}

enum ndr_err_code messaging_smb_notify_cancel_deleted_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_notify_cancel_deleted *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_notify_cancel_deleted){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)
			ndr_pull_messaging_smb_notify_cancel_deleted);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_NOTIFY_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_notify_rec_change_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_notify_rec_change *msg,
	struct timespec creation_time,
	uint32_t filter,
	uint32_t subdir_filter,
	void *private_data,
	const char *path,
	DATA_BLOB *blob)
{
	msg->info.info1.tv_sec = creation_time.tv_sec;
	msg->info.info1.tv_nsec = creation_time.tv_nsec;
	msg->info.info1.filter = filter;
	msg->info.info1.subdir_filter = subdir_filter;
	msg->info.info1.private_data = private_data;
	msg->info.info1.path = path != NULL ? path : "";
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_smb_notify_rec_change);
}

enum ndr_err_code messaging_smb_notify_rec_change_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_notify_rec_change *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_notify_rec_change){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_notify_rec_change);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_NOTIFY_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_notify_trigger_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_notify_trigger *msg,
	struct timespec when,
	uint32_t action,
	uint32_t filter,
	const char *path,
	DATA_BLOB *blob)
{
	msg->info.info1.tv_sec = when.tv_sec;
	msg->info.info1.tv_nsec = when.tv_nsec;
	msg->info.info1.action = action;
	msg->info.info1.filter = filter;
	msg->info.info1.path = path != NULL ? path : "";
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_smb_notify_trigger);
}

enum ndr_err_code messaging_smb_notify_trigger_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_notify_trigger *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_notify_trigger){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_notify_trigger);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_NOTIFY_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_notify_get_db_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_notify_get_db *msg,
	DATA_BLOB *blob)
{
	msg->info.info1 = (struct messaging_smb_notify_get_db_v1){};
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_smb_notify_get_db);
}

enum ndr_err_code messaging_smb_notify_get_db_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_notify_get_db *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_notify_get_db){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_notify_get_db);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_NOTIFY_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_notify_db_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_notify_db *msg,
	uint64_t rec_index,
	DATA_BLOB db,
	DATA_BLOB *blob)
{
	msg->info.info1.rec_index = rec_index;
	msg->info.info1.db = db;
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_smb_notify_db);
}

enum ndr_err_code messaging_smb_notify_db_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_notify_db *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_notify_db){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_notify_db);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_NOTIFY_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_notify_rec_changes_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_notify_rec_changes *msg,
	struct messaging_reclog *reclog,
	DATA_BLOB *blob)
{
	if (reclog != NULL) {
		msg->info.info1.reclog = *reclog;
	} else {
		msg->info.info1.reclog = (struct messaging_reclog){0};
	}
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)
			ndr_push_messaging_smb_notify_rec_changes);
}

enum ndr_err_code messaging_smb_notify_rec_changes_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_notify_rec_changes *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_notify_rec_changes){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)
			ndr_pull_messaging_smb_notify_rec_changes);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_NOTIFY_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_smb_notify_started_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_notify_started *msg,
	DATA_BLOB *blob)
{
	msg->info.info1 = (struct messaging_smb_notify_started_v1){};
	return ndr_push_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_push_flags_fn_t)ndr_push_messaging_smb_notify_started);
}

enum ndr_err_code messaging_smb_notify_started_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_notify_started *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_smb_notify_started){0};

	ndr_err = ndr_pull_struct_blob(
		blob,
		mem_ctx,
		msg,
		(ndr_pull_flags_fn_t)ndr_pull_messaging_smb_notify_started);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_SMB_NOTIFY_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code messaging_pvfs_notify_push(TALLOC_CTX *mem_ctx,
					     struct messaging_pvfs_notify *msg,
					     struct timespec when,
					     void *private_data,
					     uint32_t action,
					     const char *path,
					     DATA_BLOB *blob)
{
	msg->info.info1.tv_sec = when.tv_sec;
	msg->info.info1.tv_nsec = when.tv_nsec;
	msg->info.info1.private_data = private_data;
	msg->info.info1.action = action;
	msg->info.info1.path = path != NULL ? path : "";
	return ndr_push_struct_blob(blob,
				    mem_ctx,
				    msg,
				    (ndr_push_flags_fn_t)
					    ndr_push_messaging_pvfs_notify);
}

enum ndr_err_code messaging_pvfs_notify_pull(TALLOC_CTX *mem_ctx,
					     const DATA_BLOB *blob,
					     struct messaging_pvfs_notify *msg)
{
	enum ndr_err_code ndr_err;

	*msg = (struct messaging_pvfs_notify){0};

	ndr_err = ndr_pull_struct_blob(blob,
				       mem_ctx,
				       msg,
				       (ndr_pull_flags_fn_t)
					       ndr_pull_messaging_pvfs_notify);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_err;
	}

	if (msg->version != MESSAGING_PVFS_NOTIFY_VERSION_1) {
		return NDR_ERR_VALIDATE;
	}

	return NDR_ERR_SUCCESS;
}

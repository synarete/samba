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

enum ndr_err_code messaging_debug_push(TALLOC_CTX *mem_ctx,
				       struct messaging_debug *msg,
				       DATA_BLOB *blob);

enum ndr_err_code messaging_debug_pull(TALLOC_CTX *mem_ctx,
				       const DATA_BLOB *blob,
				       struct messaging_debug *msg);

enum ndr_err_code messaging_ping_push(TALLOC_CTX *mem_ctx,
				      struct messaging_ping *msg,
				      const char *payload,
				      DATA_BLOB *blob);

enum ndr_err_code messaging_ping_pull(TALLOC_CTX *mem_ctx,
				      const DATA_BLOB *blob,
				      struct messaging_ping *msg);

enum ndr_err_code messaging_pong_push(TALLOC_CTX *mem_ctx,
				      struct messaging_pong *msg,
				      DATA_BLOB *blob);

enum ndr_err_code messaging_pong_pull(TALLOC_CTX *mem_ctx,
				      const DATA_BLOB *blob,
				      struct messaging_pong *msg);

enum ndr_err_code messaging_profile_push(TALLOC_CTX *mem_ctx,
					 struct messaging_profile *msg,
					 DATA_BLOB *blob);

enum ndr_err_code messaging_profile_pull(TALLOC_CTX *mem_ctx,
					 const DATA_BLOB *blob,
					 struct messaging_profile *msg);

enum ndr_err_code messaging_shutdown_push(TALLOC_CTX *mem_ctx,
					  struct messaging_shutdown *msg,
					  DATA_BLOB *blob);

enum ndr_err_code messaging_shutdown_pull(TALLOC_CTX *mem_ctx,
					  const DATA_BLOB *blob,
					  struct messaging_shutdown *msg);

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

enum ndr_err_code messaging_smb_conf_updated_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_conf_updated *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_smb_conf_updated_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_conf_updated *msg);

enum ndr_err_code messaging_reload_tls_certificates_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_reload_tls_certificates *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_reload_tls_certificates_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_reload_tls_certificates *msg);

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

enum ndr_err_code messaging_daemon_ready_fd_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_daemon_ready_fd *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_daemon_ready_fd_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_daemon_ready_fd *msg);

enum ndr_err_code messaging_force_election_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_force_election *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_force_election_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_force_election *msg);

enum ndr_err_code messaging_winbind_online_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_winbind_online *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_winbind_online_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_winbind_online *msg);

enum ndr_err_code messaging_winbind_offline_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_winbind_offline *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_winbind_offline_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_winbind_offline *msg);

enum ndr_err_code messaging_winbind_domain_online_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_winbind_domain_online *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_winbind_domain_online_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_winbind_domain_online *msg);

enum ndr_err_code messaging_winbind_domain_offline_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_winbind_domain_offline *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_winbind_domain_offline_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_winbind_domain_offline *msg);

enum ndr_err_code messaging_winbind_reload_trusted_domains_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_winbind_reload_trusted_domains *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_winbind_reload_trusted_domains_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_winbind_reload_trusted_domains *msg);

enum ndr_err_code messaging_winbind_disconnect_dc_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_winbind_disconnect_dc *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_winbind_disconnect_dc_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_winbind_disconnect_dc *msg);

enum ndr_err_code messaging_winbind_validate_cache_req_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_winbind_validate_cache_req *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_winbind_validate_cache_req_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_winbind_validate_cache_req *msg);

enum ndr_err_code messaging_winbind_validate_cache_reply_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_winbind_validate_cache_reply *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_winbind_validate_cache_reply_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_winbind_validate_cache_reply *msg);

enum ndr_err_code messaging_winbind_onlinestatus_req_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_winbind_onlinestatus_req *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_winbind_onlinestatus_req_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_winbind_onlinestatus_req *msg);

enum ndr_err_code messaging_winbind_onlinestatus_reply_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_winbind_onlinestatus_reply *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_winbind_onlinestatus_reply_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_winbind_onlinestatus_reply *msg);

enum ndr_err_code messaging_winbind_dump_domain_list_req_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_winbind_dump_domain_list_req *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_winbind_dump_domain_list_req_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_winbind_dump_domain_list_req *msg);

enum ndr_err_code messaging_winbind_dump_domain_list_reply_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_winbind_dump_domain_list_reply *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_winbind_dump_domain_list_reply_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_winbind_dump_domain_list_reply *msg);

enum ndr_err_code messaging_smb_tell_num_children_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_tell_num_children *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_smb_tell_num_children_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_tell_num_children *msg);

enum ndr_err_code messaging_smb_num_children_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_num_children *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_smb_num_children_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_num_children *msg);

enum ndr_err_code messaging_smb_notify_cleanup_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_notify_cleanup *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_smb_notify_cleanup_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_notify_cleanup *msg);

enum ndr_err_code messaging_smb_notify_started_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_notify_started *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_smb_notify_started_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_notify_started *msg);

enum ndr_err_code messaging_smb_notify_get_db_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_notify_get_db *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_smb_notify_get_db_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_notify_get_db *msg);

enum ndr_err_code messaging_smb_sleep_push(TALLOC_CTX *mem_ctx,
					   struct messaging_smb_sleep *msg,
					   DATA_BLOB *blob);

enum ndr_err_code messaging_smb_sleep_pull(TALLOC_CTX *mem_ctx,
					   const DATA_BLOB *blob,
					   struct messaging_smb_sleep *msg);

enum ndr_err_code messaging_smb_ip_dropped_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_smb_ip_dropped *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_smb_ip_dropped_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_smb_ip_dropped *msg);

enum ndr_err_code messaging_winbind_ip_dropped_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_winbind_ip_dropped *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_winbind_ip_dropped_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_winbind_ip_dropped *msg);

enum ndr_err_code messaging_kill_client_ip_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_kill_client_ip *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_kill_client_ip_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_kill_client_ip *msg);

enum ndr_err_code messaging_force_tdis_push(TALLOC_CTX *mem_ctx,
					    struct messaging_force_tdis *msg,
					    DATA_BLOB *blob);

enum ndr_err_code messaging_force_tdis_pull(TALLOC_CTX *mem_ctx,
					    const DATA_BLOB *blob,
					    struct messaging_force_tdis *msg);

enum ndr_err_code messaging_force_tdis_denied_push(
	TALLOC_CTX *mem_ctx,
	struct messaging_force_tdis_denied *msg,
	DATA_BLOB *blob);

enum ndr_err_code messaging_force_tdis_denied_pull(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB *blob,
	struct messaging_force_tdis_denied *msg);

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

#endif /* __LIBRPC_NDR_NDR_MESSAGING_H__ */

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

#ifndef __SOURCE3_MESSAGES_SEND_H__
#define __SOURCE3_MESSAGES_SEND_H__

#include "includes.h"
#include "librpc/gen_ndr/messaging.h"
#include "librpc/ndr/ndr_messaging.h"
#include "messages.h"
#include "cluster_support.h"

/*
 * Note: when the destination has a zero pid, the message is sent to
 * all processes (see messaging_send_all()).
 */

NTSTATUS messaging_send_debug(struct messaging_context *msg_ctx,
			      struct server_id dst,
			      const char *debug_string);

NTSTATUS messaging_send_req_debuglevel(struct messaging_context *msg_ctx,
				       struct server_id dst);

NTSTATUS messaging_send_profile(struct messaging_context *msg_ctx,
				struct server_id dst,
				int level);

NTSTATUS messaging_send_req_profilelevel(struct messaging_context *msg_ctx,
					 struct server_id dst);

NTSTATUS messaging_send_ping(struct messaging_context *msg_ctx,
			     struct server_id dst);

NTSTATUS messaging_send_shutdown(struct messaging_context *msg_ctx,
				 struct server_id dst);

NTSTATUS messaging_send_req_pool_usage(struct messaging_context *msg_ctx,
				       struct server_id dst,
				       int fd);

NTSTATUS messaging_send_req_dmalloc_mark(struct messaging_context *msg_ctx,
					 struct server_id dst);

NTSTATUS messaging_send_req_dmalloc_log_changed(
	struct messaging_context *msg_ctx,
	struct server_id dst);

NTSTATUS messaging_send_id_cache_delete(struct messaging_context *msg_ctx,
					struct server_id dst,
					const char *id_string);

NTSTATUS messaging_send_id_cache_kill(struct messaging_context *msg_ctx,
				      struct server_id dst,
				      const char *id_string);

NTSTATUS messaging_send_smb_conf_updated(struct messaging_context *msg_ctx,
					 struct server_id dst);

NTSTATUS messaging_send_all_smb_conf_updated(
	struct messaging_context *msg_ctx);

NTSTATUS messaging_send_reload_tls_certificates(
	struct messaging_context *msg_ctx,
	struct server_id dst);

NTSTATUS messaging_send_req_ringbuf_log(struct messaging_context *msg_ctx,
					struct server_id dst);

NTSTATUS messaging_send_force_election(struct messaging_context *msg_ctx,
				       struct server_id dst);

NTSTATUS messaging_send_kill_client_ip(struct messaging_context *msg_ctx,
				       struct server_id dst,
				       const char *ip_address);

NTSTATUS messaging_send_force_tdis(struct messaging_context *msg_ctx,
				   struct server_id dst,
				   const char *sharename);

NTSTATUS messaging_send_all_force_tdis(struct messaging_context *msg_ctx,
				       const char *sharename);

NTSTATUS messaging_send_force_tdis_denied(struct messaging_context *msg_ctx,
					  struct server_id dst,
					  const char *sharename);

NTSTATUS messaging_send_ip_dropped(struct messaging_context *msg_ctx,
				   struct server_id dst,
				   const char *ip_address);

NTSTATUS messaging_send_smb_sleep(struct messaging_context *msg_ctx,
				  struct server_id dst,
				  unsigned int seconds);

NTSTATUS messaging_send_tell_num_children(struct messaging_context *msg_ctx,
					  struct server_id dst);

NTSTATUS messaging_send_inject_fault(struct messaging_context *msg_ctx,
				     struct server_id dst,
				     int32_t sig);

NTSTATUS messaging_send_close_file(struct messaging_context *msg_ctx,
				   struct server_id dst,
				   struct file_id id,
				   uint64_t share_file_id);

NTSTATUS messaging_send_file_rename(struct messaging_context *msg_ctx,
				    struct server_id dst,
				    struct file_id id,
				    uint64_t share_file_id,
				    const char *servicepath,
				    const char *base_name,
				    const char *stream_name);

#endif /* __SOURCE3_MESSAGES_SEND_H__ */

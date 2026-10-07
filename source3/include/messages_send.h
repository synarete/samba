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

bool messaging_use_ndr_v1(void);

/*
 * The caller passes the already chosen msg_type and payload, no format
 * is selected here. A dst with pid 0 means "send to all".
 */
NTSTATUS messaging_send_one_or_all(struct messaging_context *msg_ctx,
				   struct server_id dst,
				   uint32_t msg_type,
				   const uint8_t *buf,
				   size_t len);

NTSTATUS messaging_send_debug(struct messaging_context *msg_ctx,
			      struct server_id dst,
			      const char *debug_string);

NTSTATUS messaging_send_req_debuglevel(struct messaging_context *msg_ctx,
				       struct server_id dst);
NTSTATUS messaging_send_req_debuglevel_v1(struct messaging_context *msg_ctx,
					  struct server_id dst);
NTSTATUS messaging_send_req_debuglevel_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst);

NTSTATUS messaging_send_profile(struct messaging_context *msg_ctx,
				struct server_id dst,
				int level);

NTSTATUS messaging_send_req_profilelevel(struct messaging_context *msg_ctx,
					 struct server_id dst);
NTSTATUS messaging_send_req_profilelevel_v1(struct messaging_context *msg_ctx,
					    struct server_id dst);
NTSTATUS messaging_send_req_profilelevel_legacy(
	struct messaging_context *msg_ctx,
	struct server_id dst);

NTSTATUS messaging_send_profilelevel_v1(struct messaging_context *msg_ctx,
					struct server_id dst,
					int level);
NTSTATUS messaging_send_profilelevel_legacy(struct messaging_context *msg_ctx,
					    struct server_id dst,
					    int level);

NTSTATUS messaging_send_ping(struct messaging_context *msg_ctx,
			     struct server_id dst);
NTSTATUS messaging_send_ping_v1(struct messaging_context *msg_ctx,
				struct server_id dst);
NTSTATUS messaging_send_ping_legacy(struct messaging_context *msg_ctx,
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

#endif /* __SOURCE3_MESSAGES_SEND_H__ */

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

NTSTATUS messaging_send_debug(struct messaging_context *msg_ctx,
			      struct server_id dst,
			      const char *debug_string);

NTSTATUS messaging_send_req_debuglevel(struct messaging_context *msg_ctx,
				       struct server_id dst);

NTSTATUS messaging_send_profile(struct messaging_context *msg_ctx,
				struct server_id dst,
				int level);

#endif /* __SOURCE3_MESSAGES_SEND_H__ */

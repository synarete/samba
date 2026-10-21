/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Volker Lendecke 2014
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __NOTIFYD_NOTIFYD_H__
#define __NOTIFYD_NOTIFYD_H__

#include "includes.h"
#include "librpc/gen_ndr/notify.h"
#include "librpc/gen_ndr/messaging.h"
#include "librpc/gen_ndr/notifyd.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_rbt.h"
#include "messages.h"
#include "tdb.h"
#include "util_tdb.h"

/*
 * Filechangenotify based on asynchronous messages
 *
 * smbds talk to local notify daemons to inform them about paths they are
 * interested in. They also tell local notify daemons about changes they have
 * done to the file system. There's two message types from smbd to
 * notifyd. The first is used to inform notifyd about changes in notify
 * interest. These are only sent from smbd to notifyd if the SMB client issues
 * FileChangeNotify requests.
 */

/*
 * The notifyd implementation is designed to cope with multiple daemons taking
 * care of just a subset of smbds. The goal is to minimize the traffic between
 * the notify daemons. The idea behind this is a samba/ctdb cluster, but it
 * could also be used to spread the load of notifyd instances on a single
 * node, should this become a bottleneck. The following diagram illustrates
 * the setup. The numbers in the boxes are node:process ids.
 *
 *         +-----------+                  +-----------+
 *         |notifyd 0:5|------------------|notifyd 1:6|
 *         +-----------+                  +-----------+
 *            / |  \                         /    \
 *           /  |   \                       /      \
 *   +--------+ | +--------+        +--------+   +--------+
 *   |smbd 0:1| | |smbd 0:4|        |smbd 1:7|   |smbd 1:2|
 *   +--------+ | +--------+        +--------+   +--------+
 *              |
 *     	   +---------+
 *	   |smbd 0:20|
 *	   +---------+
 *
 * Suppose 0:1 and 0:4 are interested in changes for /foo and 0:20 creates the
 * file /foo/bar, if everything fully connected, 0:20 would have to send two
 * local messages, one to 0:1 and one to 0:4. With the notifyd design, 0:20
 * only has to send one message, it lets notifyd 0:5 do the hard work to
 * multicast the change to 0:1 and 0:4.
 *
 * Now lets assume 1:7 on the other node creates /foo/baz. It tells its
 * notifyd 1:6 about this change. All 1:6 will know about is that its peer
 * notifyd 0:5 is interested in the change. Thus it forwards the event to 0:5,
 * which sees it as if it came from just another local event creator. 0:5 will
 * multicast the change to 0:1 and 0:4. To prevent notify loops, the message
 * from 1:6 to 0:5 will carry a "proxied" flag, so that 0:5 will only forward
 * the event to local clients.
 */

/*
 * Data that notifyd maintains per smbd notify instance
 */
struct notify_instance {
	struct timespec creation_time;
	uint32_t filter;
	uint32_t subdir_filter;
	void *private_data;
};

/*
 * The messages consist of a fixed size NDR header
 * (see source3/librpc/idl/notifyd.idl) followed
 * by the (nul terminated) path, the following
 * structures are the parsed representations.
 *
 * The notify_*_msg_push_hdr() functions return the message
 * type to use and the length of the header, which can be
 * smaller than NOTIFY_*_HDR_SIZE on non LP64 platforms.
 * The notify_*_msg_parse() functions take the received
 * message type, the receivers need to register for both
 * message types, e.g. MSG_SMB_NOTIFY_REC_CHANGE and
 * MSG_SMB_NOTIFY_REC_CHANGE_LE.
 *
 * The notify_*_msg_push_hdr_type() functions push the
 * header for an explicit message type, they return false
 * for an unexpected message type. They are only useful
 * for tests.
 */

/* MSG_SMB_NOTIFY_REC_CHANGE[_LE] payload */
struct notify_rec_change_msg {
	struct notify_instance instance;
	const char *path; /* points into the message buffer */
	size_t pathlen;
};

uint32_t notify_rec_change_msg_push_hdr(
	const struct notify_instance *instance,
	uint8_t hdr[NOTIFY_REC_CHANGE_HDR_SIZE],
	size_t *hdr_len);
bool notify_rec_change_msg_push_hdr_type(
	uint32_t msg_type,
	const struct notify_instance *instance,
	uint8_t hdr[NOTIFY_REC_CHANGE_HDR_SIZE],
	size_t *hdr_len);
bool notify_rec_change_msg_parse(uint32_t msg_type,
				 const uint8_t *buf,
				 size_t buflen,
				 struct notify_rec_change_msg *msg);

/*
 * The second message from smbd to notifyd is sent whenever an smbd makes a
 * file system change. It tells notifyd to inform all interested parties about
 * that change. This is the message that needs to be really fast in smbd
 * because it is called a lot.
 */

/* MSG_SMB_NOTIFY_TRIGGER[_LE] payload */
struct notify_trigger_msg {
	struct timespec when;
	uint32_t action;
	uint32_t filter;
	const char *path; /* points into the message buffer */
};

uint32_t notify_trigger_msg_push_hdr(struct timespec when,
				     uint32_t action,
				     uint32_t filter,
				     uint8_t hdr[NOTIFY_TRIGGER_HDR_SIZE],
				     size_t *hdr_len);
bool notify_trigger_msg_push_hdr_type(uint32_t msg_type,
				      struct timespec when,
				      uint32_t action,
				      uint32_t filter,
				      uint8_t hdr[NOTIFY_TRIGGER_HDR_SIZE],
				      size_t *hdr_len);
bool notify_trigger_msg_parse(uint32_t msg_type,
			      const uint8_t *buf,
			      size_t buflen,
			      struct notify_trigger_msg *msg);

/*
 * In response to a MSG_SMB_NOTIFY_TRIGGER message notifyd walks its database
 * and sends out the following message to all interested clients
 */

/* MSG_PVFS_NOTIFY[_LE] payload */
struct notify_event_msg {
	struct timespec when;
	void *private_data;
	uint32_t action;
	const char *path; /* points into the message buffer */
};

uint32_t notify_event_msg_push_hdr(struct timespec when,
				   void *private_data,
				   uint32_t action,
				   uint8_t hdr[NOTIFY_EVENT_HDR_SIZE],
				   size_t *hdr_len);
bool notify_event_msg_push_hdr_type(uint32_t msg_type,
				    struct timespec when,
				    void *private_data,
				    uint32_t action,
				    uint8_t hdr[NOTIFY_EVENT_HDR_SIZE],
				    size_t *hdr_len);
bool notify_event_msg_parse(uint32_t msg_type,
			    const uint8_t *buf,
			    size_t buflen,
			    struct notify_event_msg *msg);

struct sys_notify_context;
struct ctdbd_connection;

typedef int (*sys_notify_watch_fn)(TALLOC_CTX *mem_ctx,
				   struct sys_notify_context *ctx,
				   const char *path,
				   uint32_t *filter,
				   uint32_t *subdir_filter,
				   void (*callback)(struct sys_notify_context *ctx,
						    void *private_data,
						    struct notify_event *ev,
						    uint32_t filter),
				   void *private_data,
				   void *handle_p);

struct tevent_req *notifyd_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct messaging_context *msg_ctx,
				struct ctdbd_connection *ctdbd_conn,
				sys_notify_watch_fn sys_notify_watch,
				struct sys_notify_context *sys_notify_ctx);
int notifyd_recv(struct tevent_req *req);

#endif

/*
 * Unix SMB/CIFS implementation.
 *
 * Marshalling of the notifyd messages
 *
 * Copyright (C) Stefan Metzmacher 2026
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

#include "replace.h"
#include "system/time.h"
#include "lib/util/debug.h"
#include "librpc/gen_ndr/ndr_notifyd.h"
#include "notifyd.h"

/*
 * The messages consist of a fixed size NDR header
 * (see source3/librpc/idl/notifyd.idl) followed
 * by the nul terminated path.
 *
 * The headers used to be raw C structures, the NDR
 * representations in host byte order have exactly
 * the same layout on LP64 platforms. On other platforms
 * we have to keep using the raw C structures in order
 * to stay compatible.
 */

struct notify_trigger_legacy {
	struct timespec when;
	uint32_t action;
	uint32_t filter;
	char path[];
};

struct notify_event_legacy {
	struct timespec when;
	void *private_data;
	uint32_t action;
	char path[];
};

static bool notifyd_msg_is_ndr(void)
{
	return sizeof(struct notify_instance) == NOTIFY_REC_CHANGE_HDR_SIZE &&
	       sizeof(struct timespec) == 16 &&
	       offsetof(struct notify_instance, filter) == 16 &&
	       offsetof(struct notify_instance, subdir_filter) == 20 &&
	       offsetof(struct notify_instance, private_data) == 24 &&
	       offsetof(struct notify_trigger_legacy, action) == 16 &&
	       offsetof(struct notify_trigger_legacy, filter) == 20 &&
	       offsetof(struct notify_trigger_legacy, path) ==
			NOTIFY_TRIGGER_HDR_SIZE &&
	       offsetof(struct notify_event_legacy, private_data) == 16 &&
	       offsetof(struct notify_event_legacy, action) == 24 &&
	       offsetof(struct notify_event_legacy, path) ==
			NOTIFY_EVENT_HDR_SIZE;
}

size_t notify_rec_change_msg_hdr_len(void)
{
	if (!notifyd_msg_is_ndr()) {
		return sizeof(struct notify_instance);
	}
	return NOTIFY_REC_CHANGE_HDR_SIZE;
}

size_t notify_trigger_msg_hdr_len(void)
{
	if (!notifyd_msg_is_ndr()) {
		return offsetof(struct notify_trigger_legacy, path);
	}
	return NOTIFY_TRIGGER_HDR_SIZE;
}

size_t notify_event_msg_hdr_len(void)
{
	if (!notifyd_msg_is_ndr()) {
		return offsetof(struct notify_event_legacy, path);
	}
	return NOTIFY_EVENT_HDR_SIZE;
}

static struct notifyd_timespec notifyd_timespec_from(struct timespec ts)
{
	return (struct notifyd_timespec) {
		.tv_sec = ts.tv_sec,
		.tv_nsec = ts.tv_nsec,
	};
}

static struct timespec notifyd_timespec_to(struct notifyd_timespec nts)
{
	return (struct timespec) {
		.tv_sec = nts.tv_sec,
		.tv_nsec = nts.tv_nsec,
	};
}

void notify_rec_change_msg_push_hdr(
	const struct notify_instance *instance,
	uint8_t hdr[NOTIFY_REC_CHANGE_HDR_SIZE])
{
	struct notify_rec_change_hdr h = {
		.creation_time = notifyd_timespec_from(
			instance->creation_time),
		.filter = instance->filter,
		.subdir_filter = instance->subdir_filter,
		.private_data = (uint64_t)(uintptr_t)instance->private_data,
	};
	DATA_BLOB blob = data_blob_const(hdr, NOTIFY_REC_CHANGE_HDR_SIZE);
	enum ndr_err_code ndr_err;

	if (!notifyd_msg_is_ndr()) {
		memcpy(hdr, instance, sizeof(struct notify_instance));
		return;
	}

	ndr_err = ndr_push_struct_into_fixed_blob_flags(
		&blob, &h, LIBNDR_FLAG_HOST_BYTE_ORDER,
		(ndr_push_flags_fn_t)ndr_push_notify_rec_change_hdr);
	SMB_ASSERT(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
}

bool notify_rec_change_msg_parse(const uint8_t *buf,
				 size_t buflen,
				 struct notify_rec_change_msg *msg)
{
	struct notify_rec_change_hdr h = { .filter = 0, };
	size_t hdr_len = notify_rec_change_msg_hdr_len();
	DATA_BLOB blob = data_blob_const(buf, hdr_len);
	struct notify_instance instance;
	enum ndr_err_code ndr_err;

	if (buflen < hdr_len + 1) {
		DBG_WARNING("message too short: %zu\n", buflen);
		return false;
	}

	if (!notifyd_msg_is_ndr()) {
		memcpy(&instance, buf, sizeof(instance));
		goto done;
	}

	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(
		&blob, &h, LIBNDR_FLAG_HOST_BYTE_ORDER,
		(ndr_pull_flags_fn_t)ndr_pull_notify_rec_change_hdr);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("ndr_pull_notify_rec_change_hdr failed: %s\n",
			    ndr_errstr(ndr_err));
		return false;
	}

	instance = (struct notify_instance) {
		.creation_time = notifyd_timespec_to(h.creation_time),
		.filter = h.filter,
		.subdir_filter = h.subdir_filter,
		.private_data = (void *)(uintptr_t)h.private_data,
	};

done:
	*msg = (struct notify_rec_change_msg) {
		.instance = instance,
		.path = (const char *)buf + hdr_len,
		.pathlen = buflen - hdr_len,
	};

	return true;
}

void notify_trigger_msg_push_hdr(struct timespec when,
				 uint32_t action,
				 uint32_t filter,
				 uint8_t hdr[NOTIFY_TRIGGER_HDR_SIZE])
{
	struct notify_trigger_hdr h = {
		.when = notifyd_timespec_from(when),
		.action = action,
		.filter = filter,
	};
	DATA_BLOB blob = data_blob_const(hdr, NOTIFY_TRIGGER_HDR_SIZE);
	enum ndr_err_code ndr_err;

	if (!notifyd_msg_is_ndr()) {
		struct notify_trigger_legacy l = {
			.when = when,
			.action = action,
			.filter = filter,
		};
		memcpy(hdr, &l, offsetof(struct notify_trigger_legacy, path));
		return;
	}

	ndr_err = ndr_push_struct_into_fixed_blob_flags(
		&blob, &h, LIBNDR_FLAG_HOST_BYTE_ORDER,
		(ndr_push_flags_fn_t)ndr_push_notify_trigger_hdr);
	SMB_ASSERT(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
}

bool notify_trigger_msg_parse(const uint8_t *buf,
			      size_t buflen,
			      struct notify_trigger_msg *msg)
{
	struct notify_trigger_hdr h = { .action = 0, };
	size_t hdr_len = notify_trigger_msg_hdr_len();
	DATA_BLOB blob = data_blob_const(buf, hdr_len);
	enum ndr_err_code ndr_err;

	if (buflen < hdr_len + 1) {
		DBG_WARNING("message too short: %zu\n", buflen);
		return false;
	}
	if (buf[buflen-1] != '\0') {
		DBG_WARNING("path not 0-terminated\n");
		return false;
	}

	if (!notifyd_msg_is_ndr()) {
		struct notify_trigger_legacy l;

		memcpy(&l, buf, offsetof(struct notify_trigger_legacy, path));
		*msg = (struct notify_trigger_msg) {
			.when = l.when,
			.action = l.action,
			.filter = l.filter,
			.path = (const char *)buf + hdr_len,
		};
		return true;
	}

	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(
		&blob, &h, LIBNDR_FLAG_HOST_BYTE_ORDER,
		(ndr_pull_flags_fn_t)ndr_pull_notify_trigger_hdr);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("ndr_pull_notify_trigger_hdr failed: %s\n",
			    ndr_errstr(ndr_err));
		return false;
	}

	*msg = (struct notify_trigger_msg) {
		.when = notifyd_timespec_to(h.when),
		.action = h.action,
		.filter = h.filter,
		.path = (const char *)buf + hdr_len,
	};

	return true;
}

void notify_event_msg_push_hdr(struct timespec when,
			       void *private_data,
			       uint32_t action,
			       uint8_t hdr[NOTIFY_EVENT_HDR_SIZE])
{
	struct notify_event_hdr h = {
		.when = notifyd_timespec_from(when),
		.private_data = (uint64_t)(uintptr_t)private_data,
		.action = action,
	};
	DATA_BLOB blob = data_blob_const(hdr, NOTIFY_EVENT_HDR_SIZE);
	enum ndr_err_code ndr_err;

	if (!notifyd_msg_is_ndr()) {
		struct notify_event_legacy l = {
			.when = when,
			.private_data = private_data,
			.action = action,
		};
		memcpy(hdr, &l, offsetof(struct notify_event_legacy, path));
		return;
	}

	ndr_err = ndr_push_struct_into_fixed_blob_flags(
		&blob, &h, LIBNDR_FLAG_HOST_BYTE_ORDER,
		(ndr_push_flags_fn_t)ndr_push_notify_event_hdr);
	SMB_ASSERT(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
}

bool notify_event_msg_parse(const uint8_t *buf,
			    size_t buflen,
			    struct notify_event_msg *msg)
{
	struct notify_event_hdr h = { .action = 0, };
	size_t hdr_len = notify_event_msg_hdr_len();
	DATA_BLOB blob = data_blob_const(buf, hdr_len);
	enum ndr_err_code ndr_err;

	if (buflen < hdr_len + 1) {
		DBG_WARNING("message too short: %zu\n", buflen);
		return false;
	}
	if (buf[buflen-1] != '\0') {
		DBG_WARNING("path not 0-terminated\n");
		return false;
	}

	if (!notifyd_msg_is_ndr()) {
		struct notify_event_legacy l;

		memcpy(&l, buf, offsetof(struct notify_event_legacy, path));
		*msg = (struct notify_event_msg) {
			.when = l.when,
			.private_data = l.private_data,
			.action = l.action,
			.path = (const char *)buf + hdr_len,
		};
		return true;
	}

	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(
		&blob, &h, LIBNDR_FLAG_HOST_BYTE_ORDER,
		(ndr_pull_flags_fn_t)ndr_pull_notify_event_hdr);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("ndr_pull_notify_event_hdr failed: %s\n",
			    ndr_errstr(ndr_err));
		return false;
	}

	*msg = (struct notify_event_msg) {
		.when = notifyd_timespec_to(h.when),
		.private_data = (void *)(uintptr_t)h.private_data,
		.action = h.action,
		.path = (const char *)buf + hdr_len,
	};

	return true;
}

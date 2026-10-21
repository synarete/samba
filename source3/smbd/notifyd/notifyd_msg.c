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
#include "notifyd_private.h"

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

/*
 * The raw C structures of the in memory notifyd database
 * have exactly the same layout as notifyd_watcher_rec
 * and notifyd_instance_rec in host byte order on LP64
 * platforms, other platforms keep using the raw C
 * structures in MSG_SMB_NOTIFY_DB.
 */
static bool notifyd_entry_is_ndr(void)
{
	return notifyd_msg_is_ndr() &&
	       sizeof(struct notifyd_watcher) == NOTIFYD_WATCHER_REC_SIZE &&
	       offsetof(struct notifyd_watcher, sys_watch) == 16 &&
	       sizeof(struct notifyd_instance) == NOTIFYD_INSTANCE_REC_SIZE &&
	       offsetof(struct notifyd_instance, instance) == 24;
}

/*
 * Calculate the length of the representation of a value of
 * the in memory notifyd database (struct notifyd_watcher
 * followed by struct notifyd_instance elements)
 * used in MSG_SMB_NOTIFY_DB.
 */
bool notifyd_entry_wire_len(size_t buflen, size_t *wire_len)
{
	size_t num_instances;

	if (buflen < sizeof(struct notifyd_watcher)) {
		return false;
	}
	if ((buflen - sizeof(struct notifyd_watcher)) %
	    sizeof(struct notifyd_instance) != 0) {
		return false;
	}
	num_instances = (buflen - sizeof(struct notifyd_watcher)) /
			sizeof(struct notifyd_instance);

	if (!notifyd_entry_is_ndr()) {
		*wire_len = buflen;
		return true;
	}

	*wire_len = NOTIFYD_WATCHER_REC_SIZE +
		    num_instances * NOTIFYD_INSTANCE_REC_SIZE;
	return true;
}

/*
 * Convert a value of the in memory notifyd database into
 * the representation used in MSG_SMB_NOTIFY_DB, wire_len
 * needs to be the result of notifyd_entry_wire_len().
 */
bool notifyd_entry_to_wire_buf(const uint8_t *buf,
			       size_t buflen,
			       uint8_t *wire,
			       size_t wire_len)
{
	struct notifyd_watcher watcher;
	size_t expected_len;
	size_t num_instances;
	size_t i;
	DATA_BLOB blob;
	struct notifyd_watcher_rec w;
	enum ndr_err_code ndr_err;

	if (!notifyd_entry_wire_len(buflen, &expected_len)) {
		return false;
	}
	if (wire_len != expected_len) {
		return false;
	}

	if (!notifyd_entry_is_ndr()) {
		memcpy(wire, buf, buflen);
		return true;
	}

	num_instances = (buflen - sizeof(struct notifyd_watcher)) /
			sizeof(struct notifyd_instance);

	memcpy(&watcher, buf, sizeof(watcher));

	w = (struct notifyd_watcher_rec) {
		.filter = watcher.filter,
		.subdir_filter = watcher.subdir_filter,
		.sys_filter = watcher.sys_filter,
		.sys_subdir_filter = watcher.sys_subdir_filter,
		.sys_watch = (uint64_t)(uintptr_t)watcher.sys_watch,
	};

	blob = data_blob_const(wire, NOTIFYD_WATCHER_REC_SIZE);
	ndr_err = ndr_push_struct_into_fixed_blob_flags(
		&blob, &w, LIBNDR_FLAG_HOST_BYTE_ORDER,
		(ndr_push_flags_fn_t)ndr_push_notifyd_watcher_rec);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	for (i = 0; i < num_instances; i++) {
		struct notifyd_instance instance;
		struct notifyd_instance_rec ir;

		memcpy(&instance,
		       buf + sizeof(struct notifyd_watcher) +
			       i * sizeof(struct notifyd_instance),
		       sizeof(instance));

		ir = (struct notifyd_instance_rec) {
			.client = instance.client,
			.instance = {
				.creation_time = notifyd_timespec_from(
					instance.instance.creation_time),
				.filter = instance.instance.filter,
				.subdir_filter =
					instance.instance.subdir_filter,
				.private_data = (uint64_t)(uintptr_t)
					instance.instance.private_data,
			},
		};

		blob = data_blob_const(wire + NOTIFYD_WATCHER_REC_SIZE +
					       i * NOTIFYD_INSTANCE_REC_SIZE,
				       NOTIFYD_INSTANCE_REC_SIZE);
		ndr_err = ndr_push_struct_into_fixed_blob_flags(
			&blob, &ir, LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_push_flags_fn_t)ndr_push_notifyd_instance_rec);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return false;
		}
	}

	return true;
}

/*
 * Convert a value of the in memory notifyd database
 * (struct notifyd_watcher followed by struct notifyd_instance
 * elements) into the representation used in MSG_SMB_NOTIFY_DB.
 */
bool notifyd_entry_to_wire(TALLOC_CTX *mem_ctx,
			   const uint8_t *buf,
			   size_t buflen,
			   DATA_BLOB *wire)
{
	size_t wire_len;
	bool ok;

	if (!notifyd_entry_wire_len(buflen, &wire_len)) {
		return false;
	}

	*wire = data_blob_talloc(mem_ctx, NULL, wire_len);
	if (wire->data == NULL) {
		return false;
	}

	ok = notifyd_entry_to_wire_buf(buf, buflen, wire->data, wire->length);
	if (!ok) {
		data_blob_free(wire);
		return false;
	}

	return true;
}

/*
 * Calculate the length of the in memory representation
 * of a value received in MSG_SMB_NOTIFY_DB.
 */
bool notifyd_entry_native_len(size_t buflen, size_t *native_len)
{
	size_t num_instances;

	if (!notifyd_entry_is_ndr()) {
		if (buflen < sizeof(struct notifyd_watcher)) {
			return false;
		}
		if ((buflen - sizeof(struct notifyd_watcher)) %
		    sizeof(struct notifyd_instance) != 0) {
			return false;
		}
		*native_len = buflen;
		return true;
	}

	if (buflen < NOTIFYD_WATCHER_REC_SIZE) {
		return false;
	}
	if ((buflen - NOTIFYD_WATCHER_REC_SIZE) %
	    NOTIFYD_INSTANCE_REC_SIZE != 0) {
		return false;
	}
	num_instances = (buflen - NOTIFYD_WATCHER_REC_SIZE) /
			NOTIFYD_INSTANCE_REC_SIZE;

	*native_len = sizeof(struct notifyd_watcher) +
		      num_instances * sizeof(struct notifyd_instance);
	return true;
}

/*
 * The reverse of notifyd_entry_to_wire_buf(), native_len
 * needs to be the result of notifyd_entry_native_len().
 */
bool notifyd_entry_from_wire_buf(const uint8_t *buf,
				 size_t buflen,
				 uint8_t *native,
				 size_t native_len)
{
	size_t expected_len;
	size_t num_instances;
	size_t i;
	DATA_BLOB blob;
	struct notifyd_watcher_rec w = { .filter = 0, };
	struct notifyd_watcher watcher;
	enum ndr_err_code ndr_err;

	if (!notifyd_entry_native_len(buflen, &expected_len)) {
		return false;
	}
	if (native_len != expected_len) {
		return false;
	}

	if (!notifyd_entry_is_ndr()) {
		memcpy(native, buf, buflen);
		return true;
	}

	num_instances = (buflen - NOTIFYD_WATCHER_REC_SIZE) /
			NOTIFYD_INSTANCE_REC_SIZE;

	blob = data_blob_const(buf, NOTIFYD_WATCHER_REC_SIZE);
	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(
		&blob, &w, LIBNDR_FLAG_HOST_BYTE_ORDER,
		(ndr_pull_flags_fn_t)ndr_pull_notifyd_watcher_rec);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	watcher = (struct notifyd_watcher) {
		.filter = w.filter,
		.subdir_filter = w.subdir_filter,
		.sys_filter = w.sys_filter,
		.sys_subdir_filter = w.sys_subdir_filter,
		.sys_watch = (void *)(uintptr_t)w.sys_watch,
	};
	memcpy(native, &watcher, sizeof(watcher));

	for (i = 0; i < num_instances; i++) {
		struct notifyd_instance_rec ir = { .client = { .pid = 0, }, };
		struct notifyd_instance instance;

		blob = data_blob_const(buf + NOTIFYD_WATCHER_REC_SIZE +
					       i * NOTIFYD_INSTANCE_REC_SIZE,
				       NOTIFYD_INSTANCE_REC_SIZE);
		ndr_err = ndr_pull_struct_blob_all_noalloc_flags(
			&blob, &ir, LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_pull_flags_fn_t)ndr_pull_notifyd_instance_rec);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return false;
		}

		instance = (struct notifyd_instance) {
			.client = ir.client,
			.instance = {
				.creation_time = notifyd_timespec_to(
					ir.instance.creation_time),
				.filter = ir.instance.filter,
				.subdir_filter = ir.instance.subdir_filter,
				.private_data = (void *)(uintptr_t)
					ir.instance.private_data,
			},
		};

		memcpy(native + sizeof(struct notifyd_watcher) +
			       i * sizeof(struct notifyd_instance),
		       &instance,
		       sizeof(instance));
	}

	return true;
}

/*
 * The reverse of notifyd_entry_to_wire()
 */
bool notifyd_entry_from_wire(TALLOC_CTX *mem_ctx,
			     const uint8_t *buf,
			     size_t buflen,
			     DATA_BLOB *native)
{
	size_t native_len;
	bool ok;

	if (!notifyd_entry_native_len(buflen, &native_len)) {
		return false;
	}

	*native = data_blob_talloc(mem_ctx, NULL, native_len);
	if (native->data == NULL) {
		return false;
	}

	ok = notifyd_entry_from_wire_buf(buf,
					 buflen,
					 native->data,
					 native->length);
	if (!ok) {
		data_blob_free(native);
		return false;
	}

	return true;
}

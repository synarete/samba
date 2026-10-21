/*
 * Unix SMB/CIFS implementation.
 *
 * Verify that NDR structures replacing raw C structures
 * in databases and messages have exactly the same layout
 * on 64-bit little endian platforms.
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

#include "includes.h"
#include "lib/file_id.h"
#include "lib/file_id_key.h"
#include "librpc/gen_ndr/ndr_file_id.h"
#include "locking/proto.h"
#include "librpc/gen_ndr/ndr_secrets.h"
#include "librpc/gen_ndr/ndr_open_files.h"
#include "librpc/gen_ndr/ndr_ratelimit.h"
#include "smbd/notifyd/notifyd.h"
#include "lib/util/server_id.h"
#include "lib/messages_util.h"
#include "librpc/gen_ndr/ndr_messaging.h"
#include <cmocka.h>

/*
 * The legacy raw formats have the same layout as the
 * NDR versions marshalled with LIBNDR_FLAG_HOST_BYTE_ORDER.
 *
 * For the not packed C structures containing pointers
 * or long values that's only true on LP64 platforms,
 * the code keeps using the raw structures elsewhere.
 */
#if (SIZEOF_VOID_P == 8) && (SIZEOF_LONG == 8)
#define LEGACY_LP64_PLATFORM 1
#else
#define LEGACY_LP64_PLATFORM 0
#endif

#define SKIP_IF_NOT_LEGACY_PLATFORM() do { \
	if (!LEGACY_LP64_PLATFORM) { \
		skip(); \
	} \
} while (0)

static void fill_pattern(void *ptr, size_t len, uint8_t start)
{
	uint8_t *p = ptr;
	size_t i;

	for (i = 0; i < len; i++) {
		p[i] = (uint8_t)(start + i);
	}
}

/*
 * SECRETS/SID/<DOMAIN> used a raw struct dom_sid
 */
static void test_secrets_domain_sid(void **state)
{
	struct dom_sid sid;
	struct secrets_domain_sid ssid = { .sid = { .num_auths = 0, }, };
	struct secrets_domain_sid ssid2 = { .sid = { .num_auths = 0, }, };
	uint8_t raw[sizeof(struct dom_sid)];
	uint8_t buf[SECRETS_DOMAIN_SID_SIZE] = { 0, };
	DATA_BLOB blob = data_blob_const(buf, sizeof(buf));
	enum ndr_err_code ndr_err;
	int8_t i;

	assert_int_equal(sizeof(raw), SECRETS_DOMAIN_SID_SIZE);

	ZERO_STRUCT(sid);
	sid.sid_rev_num = 1;
	sid.num_auths = 4;
	fill_pattern(sid.id_auth, sizeof(sid.id_auth), 0x10);
	for (i = 0; i < sid.num_auths; i++) {
		sid.sub_auths[i] = 0x01020304 * (i + 1);
	}
	memcpy(raw, &sid, sizeof(raw));

	ssid.sid = sid;

	ndr_err = ndr_push_struct_into_fixed_blob_flags(&blob, &ssid,
			LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_push_flags_fn_t)ndr_push_secrets_domain_sid);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(buf, raw, sizeof(raw));

	blob = data_blob_const(raw, sizeof(raw));
	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(&blob, &ssid2,
			LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_pull_flags_fn_t)ndr_pull_secrets_domain_sid);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(&ssid, &ssid2, sizeof(ssid));

	/*
	 * Old versions didn't clear the unused sub_auths,
	 * they are ignored by dom_sid68.
	 */
	sid.sub_auths[sid.num_auths] = 0xffffffff;
	sid.sub_auths[ARRAY_SIZE(sid.sub_auths) - 1] = 0xffffffff;
	memcpy(raw, &sid, sizeof(raw));
	ZERO_STRUCT(ssid2);
	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(&blob, &ssid2,
			LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_pull_flags_fn_t)ndr_pull_secrets_domain_sid);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(&ssid, &ssid2, sizeof(ssid));
}

/*
 * SECRETS/DOMGUID/<DOMAIN> used a raw struct GUID
 */
static void test_secrets_domain_guid(void **state)
{
	struct secrets_domain_guid sguid = { .guid = { .time_low = 0, }, };
	struct secrets_domain_guid sguid2 = { .guid = { .time_low = 0, }, };
	uint8_t raw[sizeof(struct GUID)];
	uint8_t buf[SECRETS_DOMAIN_GUID_SIZE] = { 0, };
	DATA_BLOB blob = data_blob_const(buf, sizeof(buf));
	enum ndr_err_code ndr_err;

	assert_int_equal(sizeof(raw), SECRETS_DOMAIN_GUID_SIZE);

	fill_pattern(&sguid.guid, sizeof(sguid.guid), 0x20);
	memcpy(raw, &sguid.guid, sizeof(raw));

	ndr_err = ndr_push_struct_into_fixed_blob_flags(&blob, &sguid,
			LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_push_flags_fn_t)ndr_push_secrets_domain_guid);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(buf, raw, sizeof(raw));

	blob = data_blob_const(raw, sizeof(raw));
	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(&blob, &sguid2,
			LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_pull_flags_fn_t)ndr_pull_secrets_domain_guid);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_true(GUID_equal(&sguid.guid, &sguid2.guid));
}

/*
 * ndr_push_struct_into_fixed_blob_flags() and
 * ndr_pull_struct_blob_all_noalloc_flags() need to pass
 * the flags down, test that with LIBNDR_FLAG_BIGENDIAN,
 * so that it is also covered on little endian platforms.
 */
static void test_ndr_flags_bigendian(void **state)
{
	struct secrets_domain_sid ssid = {
		.sid = {
			.sid_rev_num = 1,
			.num_auths = 1,
			.id_auth = { 0, 0, 0, 0, 0, 5 },
			.sub_auths = { 0x01020304, },
		},
	};
	struct secrets_domain_sid ssid2 = { .sid = { .num_auths = 0, }, };
	uint8_t buf[SECRETS_DOMAIN_SID_SIZE] = { 0, };
	uint8_t expected[SECRETS_DOMAIN_SID_SIZE] = {
		1, 1, 0, 0, 0, 0, 0, 5,
		0x01, 0x02, 0x03, 0x04,
	};
	DATA_BLOB blob = data_blob_const(buf, sizeof(buf));
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_into_fixed_blob_flags(&blob, &ssid,
			LIBNDR_FLAG_BIGENDIAN,
			(ndr_push_flags_fn_t)ndr_push_secrets_domain_sid);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(buf, expected, sizeof(expected));

	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(&blob, &ssid2,
			LIBNDR_FLAG_BIGENDIAN,
			(ndr_pull_flags_fn_t)ndr_pull_secrets_domain_sid);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(&ssid, &ssid2, sizeof(ssid));

	/* wrong sizes are rejected */
	blob.length -= 1;
	ndr_err = ndr_push_struct_into_fixed_blob_flags(&blob, &ssid,
			LIBNDR_FLAG_BIGENDIAN,
			(ndr_push_flags_fn_t)ndr_push_secrets_domain_sid);
	assert_false(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(&blob, &ssid2,
			LIBNDR_FLAG_BIGENDIAN,
			(ndr_pull_flags_fn_t)ndr_pull_secrets_domain_sid);
	assert_false(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
}

/*
 * The keys of locking.tdb and brlock.tdb used a raw struct file_id
 */
static void test_file_id_key(void **state)
{
	struct file_id id = {
		.devid = 0x0102030405060708,
		.inode = 0x1112131415161718,
		.extid = 0x2122232425262728,
	};
	struct file_id id2 = { .devid = 0, };
	struct file_id_key key = { .id = id };
	struct file_id_key key2 = { .id = { .devid = 0, }, };
	struct file_id_key_buf buf = { .buf = { 0, }, };
	uint8_t be[FILE_ID_KEY_LENGTH];
	DATA_BLOB blob = data_blob_const(buf.buf, sizeof(buf.buf));
	enum ndr_err_code ndr_err;
	bool ok;

	assert_int_equal(sizeof(id), FILE_ID_KEY_LENGTH);

	push_file_id_24(&buf, &id);
	assert_memory_equal(buf.buf, &id, sizeof(id));

	ok = pull_file_id_24(buf.buf, sizeof(buf.buf), &id2);
	assert_true(ok);
	assert_true(file_id_equal(&id, &id2));

	ok = pull_file_id_24(buf.buf, sizeof(buf.buf) - 1, &id2);
	assert_false(ok);

	/*
	 * On big endian platforms each member needs to be
	 * a big endian uint64, not two big endian uint32
	 * with the low half first (like udlong).
	 */
	PUSH_BE_U64(be, 0, id.devid);
	PUSH_BE_U64(be, 8, id.inode);
	PUSH_BE_U64(be, 16, id.extid);

	ndr_err = ndr_push_struct_into_fixed_blob_flags(&blob, &key,
			LIBNDR_FLAG_BIGENDIAN,
			(ndr_push_flags_fn_t)ndr_push_file_id_key);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(buf.buf, be, sizeof(be));

	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(&blob, &key2,
			LIBNDR_FLAG_BIGENDIAN,
			(ndr_pull_flags_fn_t)ndr_pull_file_id_key);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_true(file_id_equal(&key.id, &key2.id));
}

/*
 * push_file_id_16() used SIVAL() for the 32 bit halves
 * of devid and inode and ignored the extid
 */
static void test_file_id_key_16(void **state)
{
	struct file_id id = {
		.devid = 0x0102030405060708,
		.inode = 0x1112131415161718,
		.extid = 0x2122232425262728,
	};
	struct file_id id2 = { .devid = 0, };
	uint8_t legacy[FILE_ID_KEY_16_LENGTH];
	uint8_t buf[FILE_ID_KEY_16_LENGTH] = { 0, };
	bool ok;

	SIVAL(legacy,  0, id.devid&0xFFFFFFFF);
	SIVAL(legacy,  4, id.devid>>32);
	SIVAL(legacy,  8, id.inode&0xFFFFFFFF);
	SIVAL(legacy, 12, id.inode>>32);

	push_file_id_16(buf, &id);
	assert_memory_equal(buf, legacy, sizeof(legacy));

	ok = pull_file_id_16(buf, sizeof(buf), &id2);
	assert_true(ok);
	assert_int_equal(id2.devid, id.devid);
	assert_int_equal(id2.inode, id.inode);
	assert_int_equal(id2.extid, 0);

	ok = pull_file_id_16(buf, sizeof(buf) - 1, &id2);
	assert_false(ok);
}

/*
 * brlock.tdb used a raw array of struct lock_struct
 */
static void test_brlock_lock_entry(void **state)
{
	struct lock_struct lock;
	struct brlock_lock_entry e = { .smblctx = 0, };
	struct brlock_lock_entry e2 = { .smblctx = 0, };
	uint8_t raw[sizeof(struct lock_struct)];
	uint8_t buf[BRLOCK_LOCK_ENTRY_SIZE] = { 0, };
	DATA_BLOB blob = data_blob_const(buf, sizeof(buf));
	enum ndr_err_code ndr_err;

	/*
	 * Only platforms with 8 byte aligned uint64_t
	 * use brlock_lock_entry, see brlock.c
	 */
	if (sizeof(struct lock_struct) != BRLOCK_LOCK_ENTRY_SIZE) {
		skip();
	}

	assert_int_equal(sizeof(raw), BRLOCK_LOCK_ENTRY_SIZE);

	/* make sure the padding is 0 */
	memset(&lock, 0, sizeof(lock));
	lock.context.smblctx = 0x0102030405060708;
	lock.context.tid = 0x11121314;
	lock.context.pid = (struct server_id) {
		.pid = 0x2122232425262728,
		.task_id = 0x31323334,
		.vnn = 0x41424344,
		.unique_id = 0x5152535455565758,
	};
	lock.start = 0x6162636465666768;
	lock.size = 0x7172737475767778;
	lock.fnum = 0x8182838485868788;
	lock.lock_type = WRITE_LOCK;
	lock.lock_flav = POSIX_LOCK;
	lock.persistent = true;
	memcpy(raw, &lock, sizeof(raw));

	e = (struct brlock_lock_entry) {
		.smblctx = lock.context.smblctx,
		.tid = lock.context.tid,
		.pid = lock.context.pid,
		.start = lock.start,
		.size = lock.size,
		.fnum = lock.fnum,
		.lock_type = lock.lock_type,
		.lock_flav = lock.lock_flav,
		.persistent = lock.persistent,
	};

	ndr_err = ndr_push_struct_into_fixed_blob_flags(&blob, &e,
			LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_push_flags_fn_t)ndr_push_brlock_lock_entry);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(buf, raw, sizeof(raw));

	blob = data_blob_const(raw, sizeof(raw));
	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(&blob, &e2,
			LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_pull_flags_fn_t)ndr_pull_brlock_lock_entry);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(&e, &e2, sizeof(e));
}

/*
 * The packed structures formerly used by vfs_aio_ratelimit
 * and smbd_ratelimitd.
 */
struct legacy_ratelimit_activity_report {
	uint64_t timestamp_usec;
	int64_t recent_iops;
	uint32_t protocol_version;
	uint32_t operation;
	int32_t pid;
	uint32_t inflight_ios;
	char share_name[256];
} PACKED_STRUCT;

struct legacy_ratelimit_node_summary {
	uint32_t vnn;
	int32_t process_count;
	uint64_t timestamp_usec;
	char share_name[256];
} PACKED_STRUCT;

struct legacy_ratelimit_tdb_record {
	uint64_t last_usec;
	float iops_tokens;
	float bytes_tokens;
	uint8_t reserved[64 - (8 + 4 + 4)];
} PACKED_STRUCT;

static void test_ratelimit_activity_report(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct legacy_ratelimit_activity_report legacy = { .pid = 0, };
	struct ratelimit_activity_report r = { .pid = 0, };
	struct ratelimit_activity_report r2 = { .pid = 0, };
	uint8_t buf[RATELIMIT_ACTIVITY_REPORT_SIZE] = { 0, };
	DATA_BLOB blob = data_blob_const(buf, sizeof(buf));
	enum ndr_err_code ndr_err;

	assert_int_equal(sizeof(legacy), RATELIMIT_ACTIVITY_REPORT_SIZE);

	legacy.timestamp_usec = r.timestamp_usec = 0x0102030405060708;
	legacy.recent_iops = r.recent_iops = -0x1112131415161718;
	legacy.protocol_version = r.protocol_version = 2;
	legacy.operation = r.operation = 1;
	legacy.pid = r.pid = -12345;
	legacy.inflight_ios = r.inflight_ios = 0x21222324;
	strlcpy(legacy.share_name, "share", sizeof(legacy.share_name));
	r.share_name = "share";

	ndr_err = ndr_push_struct_into_fixed_blob_flags(&blob, &r,
			LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_push_flags_fn_t)ndr_push_ratelimit_activity_report);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(buf, &legacy, sizeof(legacy));

	blob = data_blob_const(&legacy, sizeof(legacy));
	ndr_err = ndr_pull_struct_blob_all_flags(&blob, frame, &r2,
			LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_pull_flags_fn_t)ndr_pull_ratelimit_activity_report);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_int_equal(r2.timestamp_usec, r.timestamp_usec);
	assert_int_equal(r2.recent_iops, r.recent_iops);
	assert_int_equal(r2.protocol_version, r.protocol_version);
	assert_int_equal(r2.operation, r.operation);
	assert_int_equal(r2.pid, r.pid);
	assert_int_equal(r2.inflight_ios, r.inflight_ios);
	assert_string_equal(r2.share_name, r.share_name);

	TALLOC_FREE(frame);
}

static void test_ratelimit_node_summary(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct legacy_ratelimit_node_summary legacy = { .vnn = 0, };
	struct ratelimit_node_summary r = { .vnn = 0, };
	struct ratelimit_node_summary r2 = { .vnn = 0, };
	uint8_t buf[RATELIMIT_NODE_SUMMARY_SIZE] = { 0, };
	DATA_BLOB blob = data_blob_const(buf, sizeof(buf));
	enum ndr_err_code ndr_err;

	assert_int_equal(sizeof(legacy), RATELIMIT_NODE_SUMMARY_SIZE);

	legacy.vnn = r.vnn = 0x01020304;
	legacy.process_count = r.process_count = -7;
	legacy.timestamp_usec = r.timestamp_usec = 0x1112131415161718;
	strlcpy(legacy.share_name, "share", sizeof(legacy.share_name));
	r.share_name = "share";

	ndr_err = ndr_push_struct_into_fixed_blob_flags(&blob, &r,
			LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_push_flags_fn_t)ndr_push_ratelimit_node_summary);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(buf, &legacy, sizeof(legacy));

	blob = data_blob_const(&legacy, sizeof(legacy));
	ndr_err = ndr_pull_struct_blob_all_flags(&blob, frame, &r2,
			LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_pull_flags_fn_t)ndr_pull_ratelimit_node_summary);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_int_equal(r2.vnn, r.vnn);
	assert_int_equal(r2.process_count, r.process_count);
	assert_int_equal(r2.timestamp_usec, r.timestamp_usec);
	assert_string_equal(r2.share_name, r.share_name);

	TALLOC_FREE(frame);
}

static void test_ratelimit_tdb_record(void **state)
{
	struct legacy_ratelimit_tdb_record legacy = { .last_usec = 0, };
	struct ratelimit_tdb_record r = { .last_usec = 0, };
	struct ratelimit_tdb_record r2 = { .last_usec = 0, };
	uint8_t buf[RATELIMIT_TDB_RECORD_SIZE] = { 0, };
	DATA_BLOB blob = data_blob_const(buf, sizeof(buf));
	enum ndr_err_code ndr_err;

	assert_int_equal(sizeof(legacy), RATELIMIT_TDB_RECORD_SIZE);

	legacy.last_usec = r.last_usec = 0x0102030405060708;
	legacy.iops_tokens = r.iops_tokens = 1.5f;
	legacy.bytes_tokens = r.bytes_tokens = -2.25f;

	ndr_err = ndr_push_struct_into_fixed_blob_flags(&blob, &r,
			LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_push_flags_fn_t)ndr_push_ratelimit_tdb_record);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(buf, &legacy, sizeof(legacy));

	blob = data_blob_const(&legacy, sizeof(legacy));
	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(&blob, &r2,
			LIBNDR_FLAG_HOST_BYTE_ORDER,
			(ndr_pull_flags_fn_t)ndr_pull_ratelimit_tdb_record);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(&r, &r2, sizeof(r));

	/*
	 * The floats need to be IEEE 754 single precision
	 * values in the selected byte order (1.5 is 0x3fc00000,
	 * -2.25 is 0xc0100000).
	 */
	blob = data_blob_const(buf, sizeof(buf));
	ndr_err = ndr_push_struct_into_fixed_blob_flags(&blob, &r, 0,
			(ndr_push_flags_fn_t)ndr_push_ratelimit_tdb_record);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_int_equal(PULL_LE_U32(buf, 8), 0x3fc00000);
	assert_int_equal(PULL_LE_U32(buf, 12), 0xc0100000);

	ndr_err = ndr_push_struct_into_fixed_blob_flags(&blob, &r,
			LIBNDR_FLAG_BIGENDIAN,
			(ndr_push_flags_fn_t)ndr_push_ratelimit_tdb_record);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_int_equal(PULL_BE_U32(buf, 8), 0x3fc00000);
	assert_int_equal(PULL_BE_U32(buf, 12), 0xc0100000);

	r2 = (struct ratelimit_tdb_record) { .last_usec = 0, };
	ndr_err = ndr_pull_struct_blob_all_noalloc_flags(&blob, &r2,
			LIBNDR_FLAG_BIGENDIAN,
			(ndr_pull_flags_fn_t)ndr_pull_ratelimit_tdb_record);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(&r, &r2, sizeof(r));
}

/*
 * The raw C structures formerly used for the notifyd messages
 */
struct legacy_notify_instance {
	struct timespec creation_time;
	uint32_t filter;
	uint32_t subdir_filter;
	void *private_data;
};

struct legacy_notify_rec_change_msg {
	struct legacy_notify_instance instance;
	char path[];
};

struct legacy_notify_trigger_msg {
	struct timespec when;
	uint32_t action;
	uint32_t filter;
	char path[];
};

struct legacy_notify_event_msg {
	struct timespec when;
	void *private_data;
	uint32_t action;
	char path[];
};

static void test_notify_rec_change_msg(void **state)
{
	struct legacy_notify_rec_change_msg legacy;
	struct notify_instance instance = {
		.creation_time = {
			.tv_sec = 0x0102030405060708,
			.tv_nsec = 999999999,
		},
		.filter = 0x11121314,
		.subdir_filter = 0x21222324,
		.private_data = (void *)(uintptr_t)0x3132333435363738,
	};
	uint8_t hdr[NOTIFY_REC_CHANGE_HDR_SIZE] = { 0, };
	uint8_t buf[NOTIFY_REC_CHANGE_HDR_SIZE + 5] = { 0, };
	struct notify_rec_change_msg msg;
	bool ok;

	SKIP_IF_NOT_LEGACY_PLATFORM();

	assert_int_equal(offsetof(struct legacy_notify_rec_change_msg, path),
			 NOTIFY_REC_CHANGE_HDR_SIZE);

	memset(&legacy, 0, sizeof(legacy));
	legacy.instance.creation_time = instance.creation_time;
	legacy.instance.filter = instance.filter;
	legacy.instance.subdir_filter = instance.subdir_filter;
	legacy.instance.private_data = instance.private_data;

	notify_rec_change_msg_push_hdr(&instance, hdr);
	assert_memory_equal(hdr, &legacy, sizeof(hdr));

	memcpy(buf, &legacy, NOTIFY_REC_CHANGE_HDR_SIZE);
	memcpy(buf + NOTIFY_REC_CHANGE_HDR_SIZE, "/foo", 5);

	ok = notify_rec_change_msg_parse(buf, sizeof(buf), &msg);
	assert_true(ok);
	assert_int_equal(msg.instance.creation_time.tv_sec,
			 instance.creation_time.tv_sec);
	assert_int_equal(msg.instance.creation_time.tv_nsec,
			 instance.creation_time.tv_nsec);
	assert_int_equal(msg.instance.filter, instance.filter);
	assert_int_equal(msg.instance.subdir_filter, instance.subdir_filter);
	assert_ptr_equal(msg.instance.private_data, instance.private_data);
	assert_int_equal(msg.pathlen, 5);
	assert_string_equal(msg.path, "/foo");
}

static void test_notify_trigger_msg(void **state)
{
	struct legacy_notify_trigger_msg legacy;
	struct timespec when = {
		.tv_sec = 0x0102030405060708,
		.tv_nsec = 999999999,
	};
	uint8_t hdr[NOTIFY_TRIGGER_HDR_SIZE] = { 0, };
	uint8_t buf[NOTIFY_TRIGGER_HDR_SIZE + 5] = { 0, };
	struct notify_trigger_msg msg;
	bool ok;

	SKIP_IF_NOT_LEGACY_PLATFORM();

	assert_int_equal(offsetof(struct legacy_notify_trigger_msg, path),
			 NOTIFY_TRIGGER_HDR_SIZE);

	memset(&legacy, 0, sizeof(legacy));
	legacy.when = when;
	legacy.action = 0x11121314;
	legacy.filter = 0x21222324;

	notify_trigger_msg_push_hdr(when, legacy.action, legacy.filter, hdr);
	assert_memory_equal(hdr, &legacy, sizeof(hdr));

	memcpy(buf, &legacy, NOTIFY_TRIGGER_HDR_SIZE);
	memcpy(buf + NOTIFY_TRIGGER_HDR_SIZE, "/foo", 5);

	ok = notify_trigger_msg_parse(buf, sizeof(buf), &msg);
	assert_true(ok);
	assert_int_equal(msg.when.tv_sec, when.tv_sec);
	assert_int_equal(msg.when.tv_nsec, when.tv_nsec);
	assert_int_equal(msg.action, legacy.action);
	assert_int_equal(msg.filter, legacy.filter);
	assert_string_equal(msg.path, "/foo");
}

static void test_notify_event_msg(void **state)
{
	struct legacy_notify_event_msg legacy;
	struct timespec when = {
		.tv_sec = 0x0102030405060708,
		.tv_nsec = 999999999,
	};
	void *private_data = (void *)(uintptr_t)0x3132333435363738;
	uint8_t hdr[NOTIFY_EVENT_HDR_SIZE] = { 0, };
	uint8_t buf[NOTIFY_EVENT_HDR_SIZE + 5] = { 0, };
	struct notify_event_msg msg;
	bool ok;

	SKIP_IF_NOT_LEGACY_PLATFORM();

	assert_int_equal(offsetof(struct legacy_notify_event_msg, path),
			 NOTIFY_EVENT_HDR_SIZE);

	memset(&legacy, 0, sizeof(legacy));
	legacy.when = when;
	legacy.private_data = private_data;
	legacy.action = 0x11121314;

	notify_event_msg_push_hdr(when, private_data, legacy.action, hdr);
	assert_memory_equal(hdr, &legacy, sizeof(hdr));

	memcpy(buf, &legacy, NOTIFY_EVENT_HDR_SIZE);
	memcpy(buf + NOTIFY_EVENT_HDR_SIZE, "/foo", 5);

	ok = notify_event_msg_parse(buf, sizeof(buf), &msg);
	assert_true(ok);
	assert_int_equal(msg.when.tv_sec, when.tv_sec);
	assert_int_equal(msg.when.tv_nsec, when.tv_nsec);
	assert_ptr_equal(msg.private_data, private_data);
	assert_int_equal(msg.action, legacy.action);
	assert_string_equal(msg.path, "/foo");

	/* the path needs to be nul terminated */
	buf[sizeof(buf)-1] = 'x';
	ok = notify_event_msg_parse(buf, sizeof(buf), &msg);
	assert_false(ok);
}

/*
 * message_hdr_put() and message_hdr_get() are hand-marshalled
 * (little endian), verify they match messaging_hdr.
 */
static void test_messaging_hdr(void **state)
{
	struct messaging_hdr hdr = {
		.dest = {
			.pid = 0x0102030405060708,
			.task_id = 0x11121314,
			.vnn = 0x21222324,
			.unique_id = 0x3132333435363738,
		},
		.src = {
			.pid = 0x4142434445464748,
			.task_id = 0x51525354,
			.vnn = 0x61626364,
			.unique_id = 0x7172737475767778,
		},
		.msg_type = 0x81828384,
	};
	struct messaging_hdr hdr2 = { .msg_type = 0, };
	uint8_t raw[MESSAGE_HDR_LENGTH] = { 0, };
	uint8_t buf[MESSAGING_HDR_LENGTH] = { 0, };
	DATA_BLOB blob = data_blob_const(buf, sizeof(buf));
	struct server_id src, dst;
	uint32_t msg_type;
	enum ndr_err_code ndr_err;

	assert_int_equal(MESSAGE_HDR_LENGTH, MESSAGING_HDR_LENGTH);

	message_hdr_put(raw, hdr.msg_type, hdr.src, hdr.dest);

	ndr_err = ndr_push_struct_into_fixed_blob(&blob, &hdr,
			(ndr_push_flags_fn_t)ndr_push_messaging_hdr);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(buf, raw, sizeof(raw));

	message_hdr_get(&msg_type, &src, &dst, buf);
	assert_int_equal(msg_type, hdr.msg_type);
	assert_true(server_id_equal(&src, &hdr.src));
	assert_true(server_id_equal(&dst, &hdr.dest));

	blob = data_blob_const(raw, sizeof(raw));
	ndr_err = ndr_pull_struct_blob_all_noalloc(&blob, &hdr2,
			(ndr_pull_flags_fn_t)ndr_pull_messaging_hdr);
	assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));
	assert_memory_equal(&hdr, &hdr2, sizeof(hdr));
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_secrets_domain_sid),
		cmocka_unit_test(test_secrets_domain_guid),
		cmocka_unit_test(test_ndr_flags_bigendian),
		cmocka_unit_test(test_file_id_key),
		cmocka_unit_test(test_file_id_key_16),
		cmocka_unit_test(test_brlock_lock_entry),
		cmocka_unit_test(test_ratelimit_activity_report),
		cmocka_unit_test(test_ratelimit_node_summary),
		cmocka_unit_test(test_ratelimit_tdb_record),
		cmocka_unit_test(test_notify_rec_change_msg),
		cmocka_unit_test(test_notify_trigger_msg),
		cmocka_unit_test(test_notify_event_msg),
		cmocka_unit_test(test_messaging_hdr),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}

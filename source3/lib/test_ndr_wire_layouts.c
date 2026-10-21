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
#include "librpc/gen_ndr/ndr_secrets.h"
#include "lib/util/server_id.h"
#include "lib/messages_util.h"
#include "librpc/gen_ndr/ndr_messaging.h"
#include <cmocka.h>

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
		cmocka_unit_test(test_messaging_hdr),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}

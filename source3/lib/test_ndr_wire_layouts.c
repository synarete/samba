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
#include "lib/util/server_id.h"
#include "lib/messages_util.h"
#include "librpc/gen_ndr/ndr_messaging.h"
#include <cmocka.h>

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
		cmocka_unit_test(test_messaging_hdr),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}

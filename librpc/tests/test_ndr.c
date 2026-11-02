/*
 * Tests for librpc ndr functions
 *
 * Copyright (C) Catalyst.NET Ltd 2020
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
 *
 */

/*
 * from cmocka.c:
 * These headers or their equivalents should be included prior to
 * including
 * this header file.
 *
 * #include <stdarg.h>
 * #include <stddef.h>
 * #include <setjmp.h>
 *
 * This allows test applications to use custom definitions of C standard
 * library functions and types.
 *
 */
#include "replace.h"
#include <setjmp.h>
#include <cmocka.h>

#include "librpc/ndr/libndr.h"

/*
 * Test NDR_PULL_NEED_BYTES integer overflow handling.
 */
static enum ndr_err_code wrap_NDR_PULL_NEED_BYTES(
	struct ndr_pull *ndr,
	uint32_t bytes) {

	NDR_PULL_NEED_BYTES(ndr, bytes);
	return NDR_ERR_SUCCESS;
}

static void test_NDR_PULL_NEED_BYTES(void **state)
{
	struct ndr_pull ndr = {0};
	enum ndr_err_code err;

	ndr.data_size = UINT32_MAX;
	ndr.offset = UINT32_MAX -1;

	/*
	 * This will not cause an overflow
	 */
	err = wrap_NDR_PULL_NEED_BYTES(&ndr, 1);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/*
	 * This will cause an overflow
	 * and (offset + n) will be less than data_size
	 */
	err = wrap_NDR_PULL_NEED_BYTES(&ndr, 2);
	assert_int_equal(NDR_ERR_BUFSIZE, err);
}

/*
 * Test NDR_PULL_ALIGN integer overflow handling.
 */
static enum ndr_err_code wrap_NDR_PULL_ALIGN(
	struct ndr_pull *ndr,
	uint32_t bytes) {

	NDR_PULL_ALIGN(ndr, bytes);
	return NDR_ERR_SUCCESS;
}

static void test_NDR_PULL_ALIGN(void **state)
{
	struct ndr_pull ndr = {0};
	enum ndr_err_code err;

	ndr.data_size = UINT32_MAX;
	ndr.offset = UINT32_MAX -1;

	/*
	 * This will not cause an overflow
	 */
	err = wrap_NDR_PULL_ALIGN(&ndr, 2);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/*
	 * This will cause an overflow
	 * and (offset + n) will be less than data_size
	 */
	err = wrap_NDR_PULL_ALIGN(&ndr, 4);
	assert_int_equal(NDR_ERR_BUFSIZE, err);
}

/*
 * Test ndr_pull_advance integer overflow handling.
 */
static void test_ndr_pull_advance(void **state)
{
	struct ndr_pull ndr = {0};
	enum ndr_err_code err;

	ndr.data_size = UINT32_MAX;
	ndr.offset = UINT32_MAX -1;

	/*
	 * This will not cause an overflow
	 */
	err = ndr_pull_advance(&ndr, 1);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/*
	 * This will cause an overflow
	 * and (offset + n) will be less than data_size
	 */
	err = ndr_pull_advance(&ndr, 2);
	assert_int_equal(NDR_ERR_BUFSIZE, err);
}

/*
 * Floats and doubles are IEEE 754 values in the
 * selected byte order, like uint32 and hyper.
 */
static void test_ndr_float_double_flags(libndr_flags flags,
					const uint8_t *expected,
					size_t expected_len)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct ndr_push *push = NULL;
	struct ndr_pull *pull = NULL;
	DATA_BLOB blob;
	float f = 0;
	double d = 0;
	enum ndr_err_code err;

	assert_non_null(mem_ctx);

	push = ndr_push_init_ctx(mem_ctx);
	assert_non_null(push);
	push->flags |= flags;

	err = ndr_push_float(push, NDR_SCALARS, 1.5f);
	assert_int_equal(NDR_ERR_SUCCESS, err);
	err = ndr_push_double(push, NDR_SCALARS, -2.25);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	blob = ndr_push_blob(push);
	assert_int_equal(blob.length, expected_len);
	assert_memory_equal(blob.data, expected, expected_len);

	pull = ndr_pull_init_blob(&blob, mem_ctx);
	assert_non_null(pull);
	pull->flags |= flags;

	err = ndr_pull_float(pull, NDR_SCALARS, &f);
	assert_int_equal(NDR_ERR_SUCCESS, err);
	err = ndr_pull_double(pull, NDR_SCALARS, &d);
	assert_int_equal(NDR_ERR_SUCCESS, err);
	assert_int_equal(pull->offset, expected_len);

	assert_true(f == 1.5f);
	assert_true(d == -2.25);

	TALLOC_FREE(mem_ctx);
}

static void test_ndr_float_double(void **state)
{
	/* 1.5f is 0x3fc00000, -2.25 is 0xc002000000000000 */
	const uint8_t le[] = {
		0x00, 0x00, 0xc0, 0x3f,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xc0,
	};
	const uint8_t be[] = {
		0x3f, 0xc0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xc0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	test_ndr_float_double_flags(0, le, sizeof(le));
	test_ndr_float_double_flags(LIBNDR_FLAG_BIGENDIAN, be, sizeof(be));
}

int main(int argc, const char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_NDR_PULL_NEED_BYTES),
		cmocka_unit_test(test_NDR_PULL_ALIGN),
		cmocka_unit_test(test_ndr_pull_advance),
		cmocka_unit_test(test_ndr_float_double),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}

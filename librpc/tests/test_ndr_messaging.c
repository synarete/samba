/*
 * Unit tests for messaging NDR encode/decode.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include "cmocka.h"

#include "replace.h"
#include "talloc.h"
#include "librpc/gen_ndr/ndr_messaging.h"
#include "librpc/ndr/ndr_messaging.h"

/* MSG_DEBUG_V1 */
/*
 * Wire encoding of messaging_debug with debug_string = "5/all":
 *
 *   01 00 00 00  - version (MESSAGING_DEBUG_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE) 35 2f 61 6c  - "5/al" (UTF-8) 6c 00        - "l\0" (no trailing padding;
 * utf8string is not aligned)
 */
static const uint8_t debug_blob_5_all[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
	0x01,
	0x00,
	0x00,
	0x00, /* union discriminant */
	0x35,
	0x2f,
	0x61,
	0x6c, /* "5/al" */
	0x6c,
	0x00, /* "l\0" */
};

/*
 * Wire encoding of messaging_debug with debug_string = "3":
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   33 00        - "3\0" (no trailing padding; utf8string is not aligned)
 */
static const uint8_t debug_blob_3[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
	0x01,
	0x00,
	0x00,
	0x00, /* union discriminant */
	0x33,
	0x00, /* "3\0" */
};

static void test_ndr_messaging_debug_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_debug msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, debug_blob_5_all),
		.length = sizeof(debug_blob_5_all),
	};
	enum ndr_err_code err;

	err = messaging_debug_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_DEBUG_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_string_equal("5/all", msg.info.info1.debug_string);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_debug_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_debug msg = {
		.info.info1.debug_string = "5/all",
	};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, debug_blob_5_all),
		.length = sizeof(debug_blob_5_all),
	};
	enum ndr_err_code err;

	err = messaging_debug_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_debug_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_debug orig = {
		.info.info1.debug_string = "3",
	};
	struct messaging_debug decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_debug_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded "3" blob must match the reference vector. */
	assert_int_equal(sizeof(debug_blob_3), blob.length);
	assert_memory_equal(debug_blob_3, blob.data, sizeof(debug_blob_3));

	err = messaging_debug_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_DEBUG_VERSION_1, decoded.version);
	assert_string_equal("3", decoded.info.info1.debug_string);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_debug_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_debug msg = {};
	/*
	 * Same layout as debug_blob_3 but with version = 0x00000002
	 * (an unknown version value).
	 */
	uint8_t bad_blob[] = {
		0x02,
		0x00,
		0x00,
		0x00, /* version = 2 (unknown) */
		0x00,
		0x00,
		0x00,
		0x00, /* reserved */
		0x02,
		0x00,
		0x00,
		0x00, /* union discriminant */
		0x33,
		0x00, /* "3\0" */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_debug_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_REQ_DEBUGLEVEL */
/*
 * Wire encoding of messaging_req_debuglevel:
 *
 *   01 00 00 00  - version (MESSAGING_DEBUGLEVEL_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *
 * No payload: this message is a request with no string body.
 */
static const uint8_t req_debuglevel_blob[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
};

static void test_ndr_messaging_req_debuglevel_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_debuglevel msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, req_debuglevel_blob),
		.length = sizeof(req_debuglevel_blob),
	};
	enum ndr_err_code err;

	err = messaging_req_debuglevel_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_DEBUGLEVEL_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_debuglevel_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_debuglevel msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, req_debuglevel_blob),
		.length = sizeof(req_debuglevel_blob),
	};
	enum ndr_err_code err;

	err = messaging_req_debuglevel_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_debuglevel_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_debuglevel msg = {};
	uint8_t bad_blob[] = {
		0x02,
		0x00,
		0x00,
		0x00, /* version = 2 (unknown) */
		0x00,
		0x00,
		0x00,
		0x00, /* reserved */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_req_debuglevel_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_DEBUGLEVEL */
/*
 * Wire encoding of messaging_debuglevel with debuglevel_string = "5/all":
 *
 *   01 00 00 00  - version (MESSAGING_DEBUGLEVEL_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE) 35 2f 61 6c  - "5/al" (UTF-8) 6c 00        - "l\0" (no trailing padding;
 * utf8string is not aligned)
 */
static const uint8_t debuglevel_blob_5_all[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
	0x01,
	0x00,
	0x00,
	0x00, /* union discriminant */
	0x35,
	0x2f,
	0x61,
	0x6c, /* "5/al" */
	0x6c,
	0x00, /* "l\0" */
};

/*
 * Wire encoding of messaging_debuglevel with debuglevel_string = "3":
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   33 00        - "3\0" (no trailing padding; utf8string is not aligned)
 */
static const uint8_t debuglevel_blob_3[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
	0x01,
	0x00,
	0x00,
	0x00, /* union discriminant */
	0x33,
	0x00, /* "3\0" */
};

static void test_ndr_messaging_debuglevel_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_debuglevel msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, debuglevel_blob_5_all),
		.length = sizeof(debuglevel_blob_5_all),
	};
	enum ndr_err_code err;

	err = messaging_debuglevel_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_DEBUGLEVEL_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_string_equal("5/all", msg.info.info1.debuglevel_string);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_debuglevel_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_debuglevel msg = {
		.info.info1.debuglevel_string = "5/all",
	};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, debuglevel_blob_5_all),
		.length = sizeof(debuglevel_blob_5_all),
	};
	enum ndr_err_code err;

	err = messaging_debuglevel_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_debuglevel_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_debuglevel orig = {
		.info.info1.debuglevel_string = "3",
	};
	struct messaging_debuglevel decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_debuglevel_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded "3" blob must match the reference vector. */
	assert_int_equal(sizeof(debuglevel_blob_3), blob.length);
	assert_memory_equal(debuglevel_blob_3,
			    blob.data,
			    sizeof(debuglevel_blob_3));

	err = messaging_debuglevel_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_DEBUGLEVEL_VERSION_1, decoded.version);
	assert_string_equal("3", decoded.info.info1.debuglevel_string);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_debuglevel_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_debuglevel msg = {};
	/*
	 * Same layout as debuglevel_blob_3 but with version = 0x00000002
	 * (an unknown version value).
	 */
	uint8_t bad_blob[] = {
		0x02,
		0x00,
		0x00,
		0x00, /* version = 2 (unknown) */
		0x00,
		0x00,
		0x00,
		0x00, /* reserved */
		0x02,
		0x00,
		0x00,
		0x00, /* union discriminant */
		0x33,
		0x00, /* "3\0" */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_debuglevel_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_PROFILE */
/*
 * Wire encoding of messaging_profile with level = 2:
 *
 *   01 00 00 00  - version (MESSAGING_PROFILE_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE) 02 00 00 00  - level = 2 (uint32 LE)
 */
static const uint8_t profile_blob_2[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
	0x01,
	0x00,
	0x00,
	0x00, /* union discriminant */
	0x02,
	0x00,
	0x00,
	0x00, /* level = 2 */
};

/*
 * Wire encoding of messaging_profile with level = 0:
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   00 00 00 00  - level = 0
 */
static const uint8_t profile_blob_0[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
	0x01,
	0x00,
	0x00,
	0x00, /* union discriminant */
	0x00,
	0x00,
	0x00,
	0x00, /* level = 0 */
};

static void test_ndr_messaging_profile_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_profile msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, profile_blob_2),
		.length = sizeof(profile_blob_2),
	};
	enum ndr_err_code err;

	err = messaging_profile_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_PROFILE_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_int_equal(2, msg.info.info1.level);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_profile_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_profile msg = {
		.info.info1.level = 2,
	};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, profile_blob_2),
		.length = sizeof(profile_blob_2),
	};
	enum ndr_err_code err;

	err = messaging_profile_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_profile_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_profile orig = {
		.info.info1.level = 0,
	};
	struct messaging_profile decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_profile_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded "0" blob must match the reference vector. */
	assert_int_equal(sizeof(profile_blob_0), blob.length);
	assert_memory_equal(profile_blob_0, blob.data, sizeof(profile_blob_0));

	err = messaging_profile_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_PROFILE_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.info.info1.level);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_profile_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_profile msg = {};
	/*
	 * Same layout as profile_blob_0 but with version = 0x00000002
	 * (an unknown version value).
	 */
	uint8_t bad_blob[] = {
		0x02,
		0x00,
		0x00,
		0x00, /* version = 2 (unknown) */
		0x00,
		0x00,
		0x00,
		0x00, /* reserved */
		0x02,
		0x00,
		0x00,
		0x00, /* union discriminant */
		0x00,
		0x00,
		0x00,
		0x00, /* level = 0 */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_profile_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ndr_messaging_debug_pull),
		cmocka_unit_test(test_ndr_messaging_debug_push),
		cmocka_unit_test(test_ndr_messaging_debug_roundtrip),
		cmocka_unit_test(test_ndr_messaging_debug_bad_version),
		cmocka_unit_test(test_ndr_messaging_req_debuglevel_pull),
		cmocka_unit_test(test_ndr_messaging_req_debuglevel_push),
		cmocka_unit_test(
			test_ndr_messaging_req_debuglevel_bad_version),
		cmocka_unit_test(test_ndr_messaging_debuglevel_pull),
		cmocka_unit_test(test_ndr_messaging_debuglevel_push),
		cmocka_unit_test(test_ndr_messaging_debuglevel_roundtrip),
		cmocka_unit_test(test_ndr_messaging_debuglevel_bad_version),
		cmocka_unit_test(test_ndr_messaging_profile_pull),
		cmocka_unit_test(test_ndr_messaging_profile_push),
		cmocka_unit_test(test_ndr_messaging_profile_roundtrip),
		cmocka_unit_test(test_ndr_messaging_profile_bad_version),
	};
	if (!isatty(1)) {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}
	return cmocka_run_group_tests(tests, NULL, NULL);
}

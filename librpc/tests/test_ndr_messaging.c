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

/* MSG_REQ_PROFILELEVEL */
/*
 * Wire encoding of messaging_req_profilelevel:
 *
 *   01 00 00 00  - version (MESSAGING_PROFILELEVEL_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *
 * No payload: this message is a request with no integer body.
 */
static const uint8_t req_profilelevel_blob[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
};

static void test_ndr_messaging_req_profilelevel_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_profilelevel msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, req_profilelevel_blob),
		.length = sizeof(req_profilelevel_blob),
	};
	enum ndr_err_code err;

	err = messaging_req_profilelevel_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_PROFILELEVEL_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_profilelevel_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_profilelevel msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, req_profilelevel_blob),
		.length = sizeof(req_profilelevel_blob),
	};
	enum ndr_err_code err;

	err = messaging_req_profilelevel_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_profilelevel_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_profilelevel msg = {};
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

	err = messaging_req_profilelevel_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_PROFILELEVEL */
/*
 * Wire encoding of messaging_profilelevel with level = 2:
 *
 *   01 00 00 00  - version (MESSAGING_PROFILELEVEL_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE) 02 00 00 00  - level = 2 (uint32 LE)
 */
static const uint8_t profilelevel_blob_2[] = {
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
 * Wire encoding of messaging_profilelevel with level = 0:
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   00 00 00 00  - level = 0
 */
static const uint8_t profilelevel_blob_0[] = {
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

static void test_ndr_messaging_profilelevel_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_profilelevel msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, profilelevel_blob_2),
		.length = sizeof(profilelevel_blob_2),
	};
	enum ndr_err_code err;

	err = messaging_profilelevel_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_PROFILELEVEL_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_int_equal(2, msg.info.info1.level);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_profilelevel_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_profilelevel msg = {
		.info.info1.level = 2,
	};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, profilelevel_blob_2),
		.length = sizeof(profilelevel_blob_2),
	};
	enum ndr_err_code err;

	err = messaging_profilelevel_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_profilelevel_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_profilelevel orig = {
		.info.info1.level = 0,
	};
	struct messaging_profilelevel decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_profilelevel_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded "0" blob must match the reference vector. */
	assert_int_equal(sizeof(profilelevel_blob_0), blob.length);
	assert_memory_equal(profilelevel_blob_0,
			    blob.data,
			    sizeof(profilelevel_blob_0));

	err = messaging_profilelevel_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_PROFILELEVEL_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.info.info1.level);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_profilelevel_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_profilelevel msg = {};
	/*
	 * Same layout as profilelevel_blob_0 but with version = 0x00000002
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

	err = messaging_profilelevel_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_PING / MSG_PONG */
/*
 * Wire encoding of messaging_ping with payload = "ping-payload":
 *
 *   01 00 00 00  - version (MESSAGING_PING_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE) 70 69 6e 67  - "ping" (UTF-8) 2d 70 61 79  - "-pay" 6c 6f 61 64  -
 * "load" 00           - "\0" (no trailing padding; utf8string is not aligned)
 */
static const uint8_t ping_blob_payload[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x70, 0x69, 0x6e, 0x67, /* "ping" */
	0x2d, 0x70, 0x61, 0x79, /* "-pay" */
	0x6c, 0x6f, 0x61, 0x64, /* "load" */
	0x00,			/* "\0" */
};

/*
 * Wire encoding of messaging_ping with payload = "":
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   00           - "\0"
 */
static const uint8_t ping_blob_empty[] = {
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
	0x00, /* "\0" */
};

/*
 * Wire encoding of messaging_pong:
 *
 *   01 00 00 00  - version (MESSAGING_PING_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 */
static const uint8_t pong_blob[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
};

static void test_ndr_messaging_ping_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_ping msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, ping_blob_payload),
		.length = sizeof(ping_blob_payload),
	};
	enum ndr_err_code err;

	err = messaging_ping_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_PING_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_string_equal("ping-payload", msg.info.info1.payload);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_ping_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_ping msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, ping_blob_payload),
		.length = sizeof(ping_blob_payload),
	};
	enum ndr_err_code err;

	err = messaging_ping_push(mem_ctx, &msg, "ping-payload", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_ping_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_ping orig = {};
	struct messaging_ping decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_ping_push(mem_ctx, &orig, "", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded empty ping blob must match the reference vector. */
	assert_int_equal(sizeof(ping_blob_empty), blob.length);
	assert_memory_equal(ping_blob_empty,
			    blob.data,
			    sizeof(ping_blob_empty));

	err = messaging_ping_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_PING_VERSION_1, decoded.version);
	assert_string_equal("", decoded.info.info1.payload);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_ping_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_ping msg = {};
	/*
	 * Same layout as ping_blob_empty but with version = 0x00000002
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
		0x00, /* payload = "" */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_ping_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_pong_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_pong msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, pong_blob),
		.length = sizeof(pong_blob),
	};
	enum ndr_err_code err;

	err = messaging_pong_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_PING_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_pong_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_pong msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, pong_blob),
		.length = sizeof(pong_blob),
	};
	enum ndr_err_code err;

	err = messaging_pong_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_pong_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_pong msg = {};
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

	err = messaging_pong_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SHUTDOWN */
/*
 * Wire encoding of messaging_shutdown:
 *
 *   01 00 00 00  - version (MESSAGING_SHUTDOWN_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE)
 *
 * info1 (messaging_shutdown_v1) is an empty struct, so there is no body.
 */
static const uint8_t shutdown_blob[] = {
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
};

static void test_ndr_messaging_shutdown_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_shutdown msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, shutdown_blob),
		.length = sizeof(shutdown_blob),
	};
	enum ndr_err_code err;

	err = messaging_shutdown_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SHUTDOWN_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_shutdown_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_shutdown msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, shutdown_blob),
		.length = sizeof(shutdown_blob),
	};
	enum ndr_err_code err;

	err = messaging_shutdown_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_shutdown_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_shutdown orig = {};
	struct messaging_shutdown decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_shutdown_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(shutdown_blob), blob.length);
	assert_memory_equal(shutdown_blob, blob.data, sizeof(shutdown_blob));

	err = messaging_shutdown_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SHUTDOWN_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_shutdown_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_shutdown msg = {};
	/*
	 * Same layout as shutdown_blob but with version = 0x00000002
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
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_shutdown_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_REQ_POOL_USAGE */
/*
 * Wire encoding of messaging_req_pool_usage:
 *
 *   01 00 00 00  - version (MESSAGING_POOL_USAGE_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *
 * No payload: this message is a request with no body.
 */
static const uint8_t req_pool_usage_blob[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
};

static void test_ndr_messaging_req_pool_usage_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_pool_usage msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, req_pool_usage_blob),
		.length = sizeof(req_pool_usage_blob),
	};
	enum ndr_err_code err;

	err = messaging_req_pool_usage_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_POOL_USAGE_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_pool_usage_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_pool_usage msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, req_pool_usage_blob),
		.length = sizeof(req_pool_usage_blob),
	};
	enum ndr_err_code err;

	err = messaging_req_pool_usage_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_pool_usage_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_pool_usage orig = {};
	struct messaging_req_pool_usage decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_req_pool_usage_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(req_pool_usage_blob), blob.length);
	assert_memory_equal(req_pool_usage_blob,
			    blob.data,
			    sizeof(req_pool_usage_blob));

	err = messaging_req_pool_usage_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_POOL_USAGE_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_pool_usage_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_pool_usage msg = {};
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

	err = messaging_req_pool_usage_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}
/* MSG_REQ_DMALLOC_MARK */
/*
 * Wire encoding of messaging_req_dmalloc_mark:
 *
 *   01 00 00 00  - version (MESSAGING_DMALLOC_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *
 * No payload: this message is a request with no body.
 */
static const uint8_t req_dmalloc_mark_blob[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
};

static void test_ndr_messaging_req_dmalloc_mark_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_dmalloc_mark msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, req_dmalloc_mark_blob),
		.length = sizeof(req_dmalloc_mark_blob),
	};
	enum ndr_err_code err;

	err = messaging_req_dmalloc_mark_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_DMALLOC_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_dmalloc_mark_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_dmalloc_mark msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, req_dmalloc_mark_blob),
		.length = sizeof(req_dmalloc_mark_blob),
	};
	enum ndr_err_code err;

	err = messaging_req_dmalloc_mark_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_dmalloc_mark_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_dmalloc_mark orig = {};
	struct messaging_req_dmalloc_mark decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_req_dmalloc_mark_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(req_dmalloc_mark_blob), blob.length);
	assert_memory_equal(req_dmalloc_mark_blob,
			    blob.data,
			    sizeof(req_dmalloc_mark_blob));

	err = messaging_req_dmalloc_mark_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_DMALLOC_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_dmalloc_mark_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_dmalloc_mark msg = {};
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

	err = messaging_req_dmalloc_mark_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_REQ_DMALLOC_LOG_CHANGED */
/*
 * Wire encoding of messaging_req_dmalloc_log_changed:
 *
 *   01 00 00 00  - version (MESSAGING_DMALLOC_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *
 * No payload: this message is a request with no body.
 */
static const uint8_t req_dmalloc_log_changed_blob[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
};

static void test_ndr_messaging_req_dmalloc_log_changed_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_dmalloc_log_changed msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, req_dmalloc_log_changed_blob),
		.length = sizeof(req_dmalloc_log_changed_blob),
	};
	enum ndr_err_code err;

	err = messaging_req_dmalloc_log_changed_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_DMALLOC_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_dmalloc_log_changed_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_dmalloc_log_changed msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, req_dmalloc_log_changed_blob),
		.length = sizeof(req_dmalloc_log_changed_blob),
	};
	enum ndr_err_code err;

	err = messaging_req_dmalloc_log_changed_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_dmalloc_log_changed_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_dmalloc_log_changed orig = {};
	struct messaging_req_dmalloc_log_changed decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_req_dmalloc_log_changed_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(req_dmalloc_log_changed_blob), blob.length);
	assert_memory_equal(req_dmalloc_log_changed_blob,
			    blob.data,
			    sizeof(req_dmalloc_log_changed_blob));

	err = messaging_req_dmalloc_log_changed_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_DMALLOC_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_dmalloc_log_changed_bad_version(
	void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_dmalloc_log_changed msg = {};
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

	err = messaging_req_dmalloc_log_changed_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* ID_CACHE_DELETE */
/*
 * Wire encoding of messaging_id_cache_delete with id_string = "UID 1234":
 *
 *   01 00 00 00  - version (MESSAGING_ID_CACHE_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE) 55 49 44 20  - "UID " (UTF-8) 31 32 33 34  - "1234" 00           - "\0"
 * (no trailing padding; utf8string is not aligned)
 */
static const uint8_t id_cache_delete_blob_uid_1234[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x55, 0x49, 0x44, 0x20, /* "UID " */
	0x31, 0x32, 0x33, 0x34, /* "1234" */
	0x00,			/* "\0" */
};

/*
 * Wire encoding of messaging_id_cache_delete with id_string = "GID 5":
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   47 49 44 20  - "GID "
 *   35 00        - "5\0"
 */
static const uint8_t id_cache_delete_blob_gid_5[] = {
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
	0x47,
	0x49,
	0x44,
	0x20, /* "GID " */
	0x35,
	0x00, /* "5\0" */
};

static void test_ndr_messaging_id_cache_delete_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_id_cache_delete msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t,
					id_cache_delete_blob_uid_1234),
		.length = sizeof(id_cache_delete_blob_uid_1234),
	};
	enum ndr_err_code err;

	err = messaging_id_cache_delete_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_ID_CACHE_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_string_equal("UID 1234", msg.info.info1.id_string);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_id_cache_delete_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_id_cache_delete msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t,
					id_cache_delete_blob_uid_1234),
		.length = sizeof(id_cache_delete_blob_uid_1234),
	};
	enum ndr_err_code err;

	err = messaging_id_cache_delete_push(mem_ctx, &msg, "UID 1234", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_id_cache_delete_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_id_cache_delete orig = {};
	struct messaging_id_cache_delete decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_id_cache_delete_push(mem_ctx, &orig, "GID 5", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(id_cache_delete_blob_gid_5), blob.length);
	assert_memory_equal(id_cache_delete_blob_gid_5,
			    blob.data,
			    sizeof(id_cache_delete_blob_gid_5));

	err = messaging_id_cache_delete_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_ID_CACHE_VERSION_1, decoded.version);
	assert_string_equal("GID 5", decoded.info.info1.id_string);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_id_cache_delete_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_id_cache_delete msg = {};
	/*
	 * Same layout as id_cache_delete_blob_gid_5 but with version =
	 * 0x00000002 (an unknown version value).
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
		0x47,
		0x49,
		0x44,
		0x20, /* "GID " */
		0x35,
		0x00, /* "5\0" */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_id_cache_delete_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* ID_CACHE_KILL */
/*
 * Wire encoding of messaging_id_cache_kill with id_string = "UID 1234":
 *
 *   01 00 00 00  - version (MESSAGING_ID_CACHE_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE) 55 49 44 20  - "UID " (UTF-8) 31 32 33 34  - "1234" 00           - "\0"
 * (no trailing padding; utf8string is not aligned)
 */
static const uint8_t id_cache_kill_blob_uid_1234[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x55, 0x49, 0x44, 0x20, /* "UID " */
	0x31, 0x32, 0x33, 0x34, /* "1234" */
	0x00,			/* "\0" */
};

/*
 * Wire encoding of messaging_id_cache_kill with id_string = "GID 5":
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   47 49 44 20  - "GID "
 *   35 00        - "5\0"
 */
static const uint8_t id_cache_kill_blob_gid_5[] = {
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
	0x47,
	0x49,
	0x44,
	0x20, /* "GID " */
	0x35,
	0x00, /* "5\0" */
};

static void test_ndr_messaging_id_cache_kill_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_id_cache_kill msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, id_cache_kill_blob_uid_1234),
		.length = sizeof(id_cache_kill_blob_uid_1234),
	};
	enum ndr_err_code err;

	err = messaging_id_cache_kill_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_ID_CACHE_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_string_equal("UID 1234", msg.info.info1.id_string);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_id_cache_kill_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_id_cache_kill msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, id_cache_kill_blob_uid_1234),
		.length = sizeof(id_cache_kill_blob_uid_1234),
	};
	enum ndr_err_code err;

	err = messaging_id_cache_kill_push(mem_ctx, &msg, "UID 1234", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_id_cache_kill_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_id_cache_kill orig = {};
	struct messaging_id_cache_kill decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_id_cache_kill_push(mem_ctx, &orig, "GID 5", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(id_cache_kill_blob_gid_5), blob.length);
	assert_memory_equal(id_cache_kill_blob_gid_5,
			    blob.data,
			    sizeof(id_cache_kill_blob_gid_5));

	err = messaging_id_cache_kill_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_ID_CACHE_VERSION_1, decoded.version);
	assert_string_equal("GID 5", decoded.info.info1.id_string);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_id_cache_kill_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_id_cache_kill msg = {};
	/*
	 * Same layout as id_cache_kill_blob_gid_5 but with version =
	 * 0x00000002 (an unknown version value).
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
		0x47,
		0x49,
		0x44,
		0x20, /* "GID " */
		0x35,
		0x00, /* "5\0" */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_id_cache_kill_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_CONF_UPDATED */
/*
 * Wire encoding of messaging_smb_conf_updated:
 *
 *   01 00 00 00  - version (MESSAGING_SMB_CONF_UPDATED_VERSION_1 = 1, uint32
 * LE) 00 00 00 00  - reserved (uint32 LE) 01 00 00 00  - union discriminant
 * (version repeated inside union, uint32 LE)
 *
 * info1 (messaging_smb_conf_updated_v1) is an empty struct, so there is no
 * body.
 */
static const uint8_t smb_conf_updated_blob[] = {
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
};

static void test_ndr_messaging_smb_conf_updated_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_conf_updated msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_conf_updated_blob),
		.length = sizeof(smb_conf_updated_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_conf_updated_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_CONF_UPDATED_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_conf_updated_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_conf_updated msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_conf_updated_blob),
		.length = sizeof(smb_conf_updated_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_conf_updated_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_conf_updated_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_conf_updated orig = {};
	struct messaging_smb_conf_updated decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_conf_updated_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(smb_conf_updated_blob), blob.length);
	assert_memory_equal(smb_conf_updated_blob,
			    blob.data,
			    sizeof(smb_conf_updated_blob));

	err = messaging_smb_conf_updated_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_CONF_UPDATED_VERSION_1,
			 decoded.version);
	assert_int_equal(0, decoded.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_conf_updated_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_conf_updated msg = {};
	/*
	 * Same layout as smb_conf_updated_blob but with version = 0x00000002
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
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_conf_updated_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_RELOAD_TLS_CERTIFICATES */
/*
 * Wire encoding of messaging_reload_tls_certificates:
 *
 *   01 00 00 00  - version (MESSAGING_RELOAD_TLS_CERTIFICATES_VERSION_1 = 1,
 *                           uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union,
 *                                     uint32 LE)
 *
 * info1 (messaging_reload_tls_certificates_v1) is an empty struct, so there
 * is no body.
 */
static const uint8_t reload_tls_certificates_blob[] = {
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
};

static void test_ndr_messaging_reload_tls_certificates_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_reload_tls_certificates msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, reload_tls_certificates_blob),
		.length = sizeof(reload_tls_certificates_blob),
	};
	enum ndr_err_code err;

	err = messaging_reload_tls_certificates_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_RELOAD_TLS_CERTIFICATES_VERSION_1,
			 msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_reload_tls_certificates_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_reload_tls_certificates msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, reload_tls_certificates_blob),
		.length = sizeof(reload_tls_certificates_blob),
	};
	enum ndr_err_code err;

	err = messaging_reload_tls_certificates_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_reload_tls_certificates_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_reload_tls_certificates orig = {};
	struct messaging_reload_tls_certificates decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_reload_tls_certificates_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(reload_tls_certificates_blob), blob.length);
	assert_memory_equal(reload_tls_certificates_blob,
			    blob.data,
			    sizeof(reload_tls_certificates_blob));

	err = messaging_reload_tls_certificates_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_RELOAD_TLS_CERTIFICATES_VERSION_1,
			 decoded.version);
	assert_int_equal(0, decoded.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_reload_tls_certificates_bad_version(
	void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_reload_tls_certificates msg = {};
	/*
	 * Same layout as reload_tls_certificates_blob but with version =
	 * 0x00000002 (an unknown version value).
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
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_reload_tls_certificates_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_REQ_RINGBUF_LOG */
/*
 * Wire encoding of messaging_req_ringbuf_log:
 *
 *   01 00 00 00  - version (MESSAGING_RINGBUF_LOG_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *
 * No payload: this message is a request with no string body.
 */
static const uint8_t req_ringbuf_log_blob[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
};

static void test_ndr_messaging_req_ringbuf_log_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_ringbuf_log msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, req_ringbuf_log_blob),
		.length = sizeof(req_ringbuf_log_blob),
	};
	enum ndr_err_code err;

	err = messaging_req_ringbuf_log_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_RINGBUF_LOG_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_ringbuf_log_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_ringbuf_log msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, req_ringbuf_log_blob),
		.length = sizeof(req_ringbuf_log_blob),
	};
	enum ndr_err_code err;

	err = messaging_req_ringbuf_log_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_req_ringbuf_log_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_req_ringbuf_log msg = {};
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

	err = messaging_req_ringbuf_log_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_RINGBUF_LOG */
/*
 * Wire encoding of messaging_ringbuf_log with log_string = "hello\n":
 *
 *   01 00 00 00  - version (MESSAGING_RINGBUF_LOG_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE) 68 65 6c 6c  - "hell" (UTF-8) 6f 0a 00     - "o\n\0" (no trailing
 * padding; utf8string is not aligned)
 */
static const uint8_t ringbuf_log_blob_hello[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x68, 0x65, 0x6c, 0x6c, /* "hell" */
	0x6f, 0x0a, 0x00,	/* "o\n\0" */
};

/*
 * Wire encoding of messaging_ringbuf_log with log_string = "x":
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   78 00        - "x\0"
 */
static const uint8_t ringbuf_log_blob_x[] = {
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
	0x78,
	0x00, /* "x\0" */
};

static void test_ndr_messaging_ringbuf_log_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_ringbuf_log msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, ringbuf_log_blob_hello),
		.length = sizeof(ringbuf_log_blob_hello),
	};
	enum ndr_err_code err;

	err = messaging_ringbuf_log_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_RINGBUF_LOG_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_string_equal("hello\n", msg.info.info1.log_string);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_ringbuf_log_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_ringbuf_log msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, ringbuf_log_blob_hello),
		.length = sizeof(ringbuf_log_blob_hello),
	};
	enum ndr_err_code err;

	err = messaging_ringbuf_log_push(mem_ctx, &msg, "hello\n", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_ringbuf_log_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_ringbuf_log decoded = {};
	struct messaging_ringbuf_log msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_ringbuf_log_push(mem_ctx, &msg, "x", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded "x" blob must match the reference vector. */
	assert_int_equal(sizeof(ringbuf_log_blob_x), blob.length);
	assert_memory_equal(ringbuf_log_blob_x,
			    blob.data,
			    sizeof(ringbuf_log_blob_x));

	err = messaging_ringbuf_log_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_RINGBUF_LOG_VERSION_1, decoded.version);
	assert_string_equal("x", decoded.info.info1.log_string);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_ringbuf_log_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_ringbuf_log msg = {};
	/*
	 * Same layout as ringbuf_log_blob_x but with version = 0x00000002
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
		0x78,
		0x00, /* "x\0" */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_ringbuf_log_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_FORCE_ELECTION */
/*
 * Wire encoding of messaging_force_election:
 *
 *   01 00 00 00  - version (MESSAGING_FORCE_ELECTION_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE)
 *
 * info1 (messaging_force_election_v1) is an empty struct, so there is no body.
 */
static const uint8_t force_election_blob[] = {
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
};

static void test_ndr_messaging_force_election_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_force_election msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, force_election_blob),
		.length = sizeof(force_election_blob),
	};
	enum ndr_err_code err;

	err = messaging_force_election_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_FORCE_ELECTION_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_force_election_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_force_election msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, force_election_blob),
		.length = sizeof(force_election_blob),
	};
	enum ndr_err_code err;

	err = messaging_force_election_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_force_election_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_force_election orig = {};
	struct messaging_force_election decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_force_election_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(force_election_blob), blob.length);
	assert_memory_equal(force_election_blob,
			    blob.data,
			    sizeof(force_election_blob));

	err = messaging_force_election_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_FORCE_ELECTION_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_force_election_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_force_election msg = {};
	/*
	 * Same layout as force_election_blob but with version = 0x00000002
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
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_force_election_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_FORCE_TDIS */
/*
 * Wire encoding of messaging_force_tdis with sharename = "homes":
 *
 *   01 00 00 00  - version (MESSAGING_FORCE_TDIS_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE) 68 6f 6d 65  - "home" (UTF-8) 73 00        - "s\0" (no trailing padding;
 * utf8string is not aligned)
 */
static const uint8_t force_tdis_blob_homes[] = {
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
	0x68,
	0x6f,
	0x6d,
	0x65, /* "home" */
	0x73,
	0x00, /* "s\0" */
};

/*
 * Wire encoding of messaging_force_tdis with sharename = "*":
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   2a 00        - "*\0"
 */
static const uint8_t force_tdis_blob_all[] = {
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
	0x2a,
	0x00, /* "*\0" */
};

static void test_ndr_messaging_force_tdis_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_force_tdis msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, force_tdis_blob_homes),
		.length = sizeof(force_tdis_blob_homes),
	};
	enum ndr_err_code err;

	err = messaging_force_tdis_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_FORCE_TDIS_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_string_equal("homes", msg.info.info1.sharename);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_force_tdis_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_force_tdis msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, force_tdis_blob_homes),
		.length = sizeof(force_tdis_blob_homes),
	};
	enum ndr_err_code err;

	err = messaging_force_tdis_push(mem_ctx, &msg, "homes", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_force_tdis_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_force_tdis orig = {};
	struct messaging_force_tdis decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_force_tdis_push(mem_ctx, &orig, "*", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(force_tdis_blob_all), blob.length);
	assert_memory_equal(force_tdis_blob_all,
			    blob.data,
			    sizeof(force_tdis_blob_all));

	err = messaging_force_tdis_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_FORCE_TDIS_VERSION_1, decoded.version);
	assert_string_equal("*", decoded.info.info1.sharename);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_force_tdis_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_force_tdis msg = {};
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
		0x2a,
		0x00, /* "*\0" */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_force_tdis_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_FORCE_TDIS_DENIED */
/*
 * Wire encoding of messaging_force_tdis_denied with sharename = "homes":
 *
 *   01 00 00 00  - version (MESSAGING_FORCE_TDIS_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE) 68 6f 6d 65  - "home" (UTF-8) 73 00        - "s\0" (no trailing padding;
 * utf8string is not aligned)
 */
static const uint8_t force_tdis_denied_blob_homes[] = {
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
	0x68,
	0x6f,
	0x6d,
	0x65, /* "home" */
	0x73,
	0x00, /* "s\0" */
};

/*
 * Wire encoding of messaging_force_tdis_denied with sharename = "*":
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   2a 00        - "*\0"
 */
static const uint8_t force_tdis_denied_blob_all[] = {
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
	0x2a,
	0x00, /* "*\0" */
};

static void test_ndr_messaging_force_tdis_denied_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_force_tdis_denied msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, force_tdis_denied_blob_homes),
		.length = sizeof(force_tdis_denied_blob_homes),
	};
	enum ndr_err_code err;

	err = messaging_force_tdis_denied_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_FORCE_TDIS_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_string_equal("homes", msg.info.info1.sharename);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_force_tdis_denied_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_force_tdis_denied msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, force_tdis_denied_blob_homes),
		.length = sizeof(force_tdis_denied_blob_homes),
	};
	enum ndr_err_code err;

	err = messaging_force_tdis_denied_push(mem_ctx, &msg, "homes", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_force_tdis_denied_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_force_tdis_denied orig = {};
	struct messaging_force_tdis_denied decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_force_tdis_denied_push(mem_ctx, &orig, "*", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(force_tdis_denied_blob_all), blob.length);
	assert_memory_equal(force_tdis_denied_blob_all,
			    blob.data,
			    sizeof(force_tdis_denied_blob_all));

	err = messaging_force_tdis_denied_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_FORCE_TDIS_VERSION_1, decoded.version);
	assert_string_equal("*", decoded.info.info1.sharename);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_force_tdis_denied_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_force_tdis_denied msg = {};
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
		0x2a,
		0x00, /* "*\0" */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_force_tdis_denied_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_KILL_CLIENT_IP */
/*
 * Wire encoding of messaging_kill_client_ip with ip_address = "192.168.1.1":
 *
 *   01 00 00 00  - version (MESSAGING_KILL_CLIENT_IP_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE) 31 39 32 2e  - "192." (UTF-8) 31 36 38 2e  - "168." 31 2e 31 00  -
 * "1.1\0" (no trailing padding; utf8string is not aligned)
 */
static const uint8_t kill_client_ip_blob_ipv4[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x31, 0x39, 0x32, 0x2e, /* "192." */
	0x31, 0x36, 0x38, 0x2e, /* "168." */
	0x31, 0x2e, 0x31, 0x00, /* "1.1\0" */
};

/*
 * Wire encoding of messaging_kill_client_ip with ip_address = "::1":
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   3a 3a 31 00  - "::1\0"
 */
static const uint8_t kill_client_ip_blob_ipv6[] = {
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
	0x3a,
	0x3a,
	0x31,
	0x00, /* "::1\0" */
};

static void test_ndr_messaging_kill_client_ip_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_kill_client_ip msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, kill_client_ip_blob_ipv4),
		.length = sizeof(kill_client_ip_blob_ipv4),
	};
	enum ndr_err_code err;

	err = messaging_kill_client_ip_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_KILL_CLIENT_IP_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_string_equal("192.168.1.1", msg.info.info1.ip_address);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_kill_client_ip_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_kill_client_ip msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, kill_client_ip_blob_ipv4),
		.length = sizeof(kill_client_ip_blob_ipv4),
	};
	enum ndr_err_code err;

	err = messaging_kill_client_ip_push(mem_ctx,
					    &msg,
					    "192.168.1.1",
					    &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_kill_client_ip_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_kill_client_ip orig = {};
	struct messaging_kill_client_ip decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_kill_client_ip_push(mem_ctx, &orig, "::1", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(kill_client_ip_blob_ipv6), blob.length);
	assert_memory_equal(kill_client_ip_blob_ipv6,
			    blob.data,
			    sizeof(kill_client_ip_blob_ipv6));

	err = messaging_kill_client_ip_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_KILL_CLIENT_IP_VERSION_1, decoded.version);
	assert_string_equal("::1", decoded.info.info1.ip_address);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_kill_client_ip_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_kill_client_ip msg = {};
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
		0x3a,
		0x3a,
		0x31,
		0x00, /* "::1\0" */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_kill_client_ip_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_IP_DROPPED */
/*
 * Wire encoding of messaging_smb_ip_dropped with ip_address = "192.168.1.1":
 *
 *   01 00 00 00  - version (MESSAGING_SMB_IP_DROPPED_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE) 31 39 32 2e  - "192." (UTF-8) 31 36 38 2e  - "168." 31 2e 31 00  -
 * "1.1\0" (no trailing padding; utf8string is not aligned)
 */
static const uint8_t smb_ip_dropped_blob_ipv4[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x31, 0x39, 0x32, 0x2e, /* "192." */
	0x31, 0x36, 0x38, 0x2e, /* "168." */
	0x31, 0x2e, 0x31, 0x00, /* "1.1\0" */
};

/*
 * Wire encoding of messaging_smb_ip_dropped with ip_address = "::1":
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   3a 3a 31 00  - "::1\0"
 */
static const uint8_t smb_ip_dropped_blob_ipv6[] = {
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
	0x3a,
	0x3a,
	0x31,
	0x00, /* "::1\0" */
};

static void test_ndr_messaging_smb_ip_dropped_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_ip_dropped msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_ip_dropped_blob_ipv4),
		.length = sizeof(smb_ip_dropped_blob_ipv4),
	};
	enum ndr_err_code err;

	err = messaging_smb_ip_dropped_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_IP_DROPPED_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_string_equal("192.168.1.1", msg.info.info1.ip_address);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_ip_dropped_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_ip_dropped msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_ip_dropped_blob_ipv4),
		.length = sizeof(smb_ip_dropped_blob_ipv4),
	};
	enum ndr_err_code err;

	err = messaging_smb_ip_dropped_push(mem_ctx,
					    &msg,
					    "192.168.1.1",
					    &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_ip_dropped_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_ip_dropped orig = {};
	struct messaging_smb_ip_dropped decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_ip_dropped_push(mem_ctx, &orig, "::1", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(smb_ip_dropped_blob_ipv6), blob.length);
	assert_memory_equal(smb_ip_dropped_blob_ipv6,
			    blob.data,
			    sizeof(smb_ip_dropped_blob_ipv6));

	err = messaging_smb_ip_dropped_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_IP_DROPPED_VERSION_1, decoded.version);
	assert_string_equal("::1", decoded.info.info1.ip_address);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_ip_dropped_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_ip_dropped msg = {};
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
		0x3a,
		0x3a,
		0x31,
		0x00, /* "::1\0" */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_ip_dropped_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_SLEEP */
/*
 * Wire encoding of messaging_smb_sleep with seconds = 10:
 *
 *   01 00 00 00  - version (MESSAGING_SMB_SLEEP_VERSION_1 = 1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union, uint32
 * LE) 0a 00 00 00  - seconds = 10 (uint32 LE)
 */
static const uint8_t smb_sleep_blob_10[] = {
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
	0x0a,
	0x00,
	0x00,
	0x00, /* seconds = 10 */
};

/*
 * Wire encoding of messaging_smb_sleep with seconds = 1:
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   01 00 00 00  - seconds = 1
 */
static const uint8_t smb_sleep_blob_1[] = {
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
	0x01,
	0x00,
	0x00,
	0x00, /* seconds = 1 */
};

static void test_ndr_messaging_smb_sleep_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_sleep msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_sleep_blob_10),
		.length = sizeof(smb_sleep_blob_10),
	};
	enum ndr_err_code err;

	err = messaging_smb_sleep_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_SLEEP_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_int_equal(10, msg.info.info1.seconds);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_sleep_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_sleep msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_sleep_blob_10),
		.length = sizeof(smb_sleep_blob_10),
	};
	enum ndr_err_code err;

	err = messaging_smb_sleep_push(mem_ctx, &msg, 10, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_sleep_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_sleep orig = {};
	struct messaging_smb_sleep decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_sleep_push(mem_ctx, &orig, 1, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(smb_sleep_blob_1), blob.length);
	assert_memory_equal(smb_sleep_blob_1,
			    blob.data,
			    sizeof(smb_sleep_blob_1));

	err = messaging_smb_sleep_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_SLEEP_VERSION_1, decoded.version);
	assert_int_equal(1, decoded.info.info1.seconds);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_sleep_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_sleep msg = {};
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
		0x0a,
		0x00,
		0x00,
		0x00, /* seconds = 10 */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_sleep_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_TELL_NUM_CHILDREN */
/*
 * Wire encoding of messaging_smb_tell_num_children:
 *
 *   01 00 00 00  - version (MESSAGING_SMB_NUM_CHILDREN_VERSION_1 = 1)
 *   00 00 00 00  - reserved
 *
 * No payload: this message is a request with no body.
 */
static const uint8_t smb_tell_num_children_blob[] = {
	0x01,
	0x00,
	0x00,
	0x00, /* version */
	0x00,
	0x00,
	0x00,
	0x00, /* reserved */
};

static void test_ndr_messaging_smb_tell_num_children_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_tell_num_children msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_tell_num_children_blob),
		.length = sizeof(smb_tell_num_children_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_tell_num_children_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NUM_CHILDREN_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_tell_num_children_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_tell_num_children msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_tell_num_children_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(sizeof(smb_tell_num_children_blob), blob.length);
	assert_memory_equal(smb_tell_num_children_blob,
			    blob.data,
			    sizeof(smb_tell_num_children_blob));

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_tell_num_children_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_tell_num_children msg = {};
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

	err = messaging_smb_tell_num_children_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_NUM_CHILDREN */
/*
 * Wire encoding of messaging_smb_num_children with num_children = 4:
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   04 00 00 00  - num_children = 4
 */
static const uint8_t smb_num_children_blob_4[] = {
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
	0x04,
	0x00,
	0x00,
	0x00, /* num_children = 4 */
};

/* Same as above, with num_children = 0 */
static const uint8_t smb_num_children_blob_0[] = {
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
	0x00, /* num_children = 0 */
};

static void test_ndr_messaging_smb_num_children_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_num_children msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_num_children_blob_4),
		.length = sizeof(smb_num_children_blob_4),
	};
	enum ndr_err_code err;

	err = messaging_smb_num_children_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NUM_CHILDREN_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_int_equal(4, msg.info.info1.num_children);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_num_children_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_num_children msg = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_num_children_push(mem_ctx, &msg, 4, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(sizeof(smb_num_children_blob_4), blob.length);
	assert_memory_equal(smb_num_children_blob_4,
			    blob.data,
			    sizeof(smb_num_children_blob_4));

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_num_children_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_num_children orig = {};
	struct messaging_smb_num_children decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_num_children_push(mem_ctx, &orig, 0, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(smb_num_children_blob_0), blob.length);
	assert_memory_equal(smb_num_children_blob_0,
			    blob.data,
			    sizeof(smb_num_children_blob_0));

	err = messaging_smb_num_children_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NUM_CHILDREN_VERSION_1,
			 decoded.version);
	assert_int_equal(0, decoded.info.info1.num_children);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_num_children_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_num_children msg = {};
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
		0x04,
		0x00,
		0x00,
		0x00, /* num_children = 4 */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_num_children_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_INJECT_FAULT */
/*
 * Wire encoding of messaging_smb_inject_fault with signal = SIGSEGV (11):
 *
 *   01 00 00 00  - version (MESSAGING_SMB_INJECT_FAULT_VERSION_1 = 1, uint32
 * LE) 00 00 00 00  - reserved (uint32 LE) 01 00 00 00  - union discriminant
 * (uint32 LE) 0b 00 00 00  - signal = 11 (SIGSEGV, int32 LE)
 */
static const uint8_t smb_inject_fault_blob_segv[] = {
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
	0x0b,
	0x00,
	0x00,
	0x00, /* signal = 11 (SIGSEGV) */
};

/*
 * Wire encoding of messaging_smb_inject_fault with signal = -1 (internal):
 *
 *   01 00 00 00  - version
 *   00 00 00 00  - reserved
 *   01 00 00 00  - union discriminant
 *   ff ff ff ff  - signal = -1
 */
static const uint8_t smb_inject_fault_blob_internal[] = {
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
	0xff,
	0xff,
	0xff,
	0xff, /* signal = -1 */
};

static void test_ndr_messaging_smb_inject_fault_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_inject_fault msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_inject_fault_blob_segv),
		.length = sizeof(smb_inject_fault_blob_segv),
	};
	enum ndr_err_code err;

	err = messaging_smb_inject_fault_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_INJECT_FAULT_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_int_equal(11, msg.info.info1.signal);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_inject_fault_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_inject_fault msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_inject_fault_blob_segv),
		.length = sizeof(smb_inject_fault_blob_segv),
	};
	enum ndr_err_code err;

	err = messaging_smb_inject_fault_push(mem_ctx, &msg, 11, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_inject_fault_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_inject_fault orig = {};
	struct messaging_smb_inject_fault decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_inject_fault_push(mem_ctx, &orig, -1, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(smb_inject_fault_blob_internal), blob.length);
	assert_memory_equal(smb_inject_fault_blob_internal,
			    blob.data,
			    sizeof(smb_inject_fault_blob_internal));

	err = messaging_smb_inject_fault_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_INJECT_FAULT_VERSION_1,
			 decoded.version);
	assert_int_equal(-1, decoded.info.info1.signal);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_inject_fault_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_inject_fault msg = {};
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
		0x0b,
		0x00,
		0x00,
		0x00, /* signal = 11 */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_inject_fault_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_CLOSE_FILE */
/*
 * Wire encoding of messaging_smb_close_file with
 * id = {devid=0x0000000100000002, inode=0x0000000300000004, extid=0},
 * share_file_id = 7:
 *
 *   01 00 00 00  - version (MESSAGING_SMB_CLOSE_FILE_VERSION_1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (uint32 LE)
 *   02 00 00 00  - devid lo32 = 0x00000002
 *   01 00 00 00  - devid hi32 = 0x00000001
 *   04 00 00 00  - inode lo32 = 0x00000004
 *   03 00 00 00  - inode hi32 = 0x00000003
 *   00 00 00 00  - extid lo32 = 0
 *   00 00 00 00  - extid hi32 = 0
 *   07 00 00 00  - share_file_id lo32 = 7
 *   00 00 00 00  - share_file_id hi32 = 0
 */
static const uint8_t smb_close_file_blob[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x02, 0x00, 0x00, 0x00, /* devid lo32 */
	0x01, 0x00, 0x00, 0x00, /* devid hi32 */
	0x04, 0x00, 0x00, 0x00, /* inode lo32 */
	0x03, 0x00, 0x00, 0x00, /* inode hi32 */
	0x00, 0x00, 0x00, 0x00, /* extid lo32 */
	0x00, 0x00, 0x00, 0x00, /* extid hi32 */
	0x07, 0x00, 0x00, 0x00, /* share_file_id lo32 */
	0x00, 0x00, 0x00, 0x00, /* share_file_id hi32 */
};

/*
 * Wire encoding of messaging_smb_close_file with all-zero file_id and
 * share_file_id = 0 (used for roundtrip test):
 */
static const uint8_t smb_close_file_blob_zero[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x00, 0x00, 0x00, 0x00, /* devid lo32 */
	0x00, 0x00, 0x00, 0x00, /* devid hi32 */
	0x00, 0x00, 0x00, 0x00, /* inode lo32 */
	0x00, 0x00, 0x00, 0x00, /* inode hi32 */
	0x00, 0x00, 0x00, 0x00, /* extid lo32 */
	0x00, 0x00, 0x00, 0x00, /* extid hi32 */
	0x00, 0x00, 0x00, 0x00, /* share_file_id lo32 */
	0x00, 0x00, 0x00, 0x00, /* share_file_id hi32 */
};

static void test_ndr_messaging_smb_close_file_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_close_file msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_close_file_blob),
		.length = sizeof(smb_close_file_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_close_file_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_CLOSE_FILE_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_int_equal(0x0000000100000002ULL, msg.info.info1.id.devid);
	assert_int_equal(0x0000000300000004ULL, msg.info.info1.id.inode);
	assert_int_equal(0, msg.info.info1.id.extid);
	assert_int_equal(7, msg.info.info1.share_file_id);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_close_file_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_close_file msg = {};
	DATA_BLOB blob = data_blob_null;
	const struct file_id id = {
		.devid = 0x0000000100000002ULL,
		.inode = 0x0000000300000004ULL,
		.extid = 0,
	};
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_close_file_blob),
		.length = sizeof(smb_close_file_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_close_file_push(mem_ctx, &msg, id, 7, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_close_file_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_close_file orig = {};
	struct messaging_smb_close_file decoded = {};
	const struct file_id id = {
		.devid = 0,
		.inode = 0,
		.extid = 0,
	};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_close_file_push(mem_ctx, &orig, id, 0, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(smb_close_file_blob_zero), blob.length);
	assert_memory_equal(smb_close_file_blob_zero,
			    blob.data,
			    sizeof(smb_close_file_blob_zero));

	err = messaging_smb_close_file_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_CLOSE_FILE_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.info.info1.id.devid);
	assert_int_equal(0, decoded.info.info1.id.inode);
	assert_int_equal(0, decoded.info.info1.id.extid);
	assert_int_equal(0, decoded.info.info1.share_file_id);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_close_file_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_close_file msg = {};
	uint8_t bad_blob[] = {
		0x02, 0x00, 0x00, 0x00, /* version = 2 (unknown) */
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x02, 0x00, 0x00, 0x00, /* union discriminant = 2 */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_close_file_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_FILE_RENAME */
/*
 * Wire encoding of messaging_smb_file_rename with
 * id = {devid=0x0000000100000002, inode=0x0000000300000004, extid=0},
 * share_file_id = 7, servicepath = "/data", base_name = "test.txt",
 * stream_name = ":stream":
 *
 *   01 00 00 00  - version (MESSAGING_SMB_FILE_RENAME_VERSION_1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (uint32 LE)
 *   02 00 00 00  - devid lo32 = 0x00000002
 *   01 00 00 00  - devid hi32 = 0x00000001
 *   04 00 00 00  - inode lo32 = 0x00000004
 *   03 00 00 00  - inode hi32 = 0x00000003
 *   00 00 00 00  - extid lo32 = 0
 *   00 00 00 00  - extid hi32 = 0
 *   07 00 00 00  - share_file_id lo32 = 7
 *   00 00 00 00  - share_file_id hi32 = 0
 *   2f 64 61 74  - servicepath: "/dat"
 *   61 00        - servicepath: "a\0"
 *   74 65 73 74  - base_name: "test"
 *   2e 74 78 74  - base_name: ".txt"
 *   00           - base_name: "\0"
 *   3a 73 74 72  - stream_name: ":str"
 *   65 61 6d 00  - stream_name: "eam\0"
 */
static const uint8_t smb_file_rename_blob[] = {
	0x01, 0x00, 0x00, 0x00,		    /* version */
	0x00, 0x00, 0x00, 0x00,		    /* reserved */
	0x01, 0x00, 0x00, 0x00,		    /* union discriminant */
	0x02, 0x00, 0x00, 0x00,		    /* devid lo32 */
	0x01, 0x00, 0x00, 0x00,		    /* devid hi32 */
	0x04, 0x00, 0x00, 0x00,		    /* inode lo32 */
	0x03, 0x00, 0x00, 0x00,		    /* inode hi32 */
	0x00, 0x00, 0x00, 0x00,		    /* extid lo32 */
	0x00, 0x00, 0x00, 0x00,		    /* extid hi32 */
	0x07, 0x00, 0x00, 0x00,		    /* share_file_id lo32 */
	0x00, 0x00, 0x00, 0x00,		    /* share_file_id hi32 */
	0x2f, 0x64, 0x61, 0x74, 0x61, 0x00, /* servicepath: "/data\0" */
	0x74, 0x65, 0x73, 0x74, 0x2e, 0x74,
	0x78, 0x74, 0x00, /* base_name: "test.txt\0" */
	0x3a, 0x73, 0x74, 0x72, 0x65, 0x61,
	0x6d, 0x00, /* stream_name: ":stream\0" */
};

/*
 * Wire encoding of messaging_smb_file_rename with all-zero file_id,
 * share_file_id = 0, servicepath = "/data", base_name = "test.txt",
 * stream_name = "" (used for roundtrip test):
 */
static const uint8_t smb_file_rename_blob_nostream[] = {
	0x01, 0x00, 0x00, 0x00,		    /* version */
	0x00, 0x00, 0x00, 0x00,		    /* reserved */
	0x01, 0x00, 0x00, 0x00,		    /* union discriminant */
	0x00, 0x00, 0x00, 0x00,		    /* devid lo32 */
	0x00, 0x00, 0x00, 0x00,		    /* devid hi32 */
	0x00, 0x00, 0x00, 0x00,		    /* inode lo32 */
	0x00, 0x00, 0x00, 0x00,		    /* inode hi32 */
	0x00, 0x00, 0x00, 0x00,		    /* extid lo32 */
	0x00, 0x00, 0x00, 0x00,		    /* extid hi32 */
	0x00, 0x00, 0x00, 0x00,		    /* share_file_id lo32 */
	0x00, 0x00, 0x00, 0x00,		    /* share_file_id hi32 */
	0x2f, 0x64, 0x61, 0x74, 0x61, 0x00, /* servicepath: "/data\0" */
	0x74, 0x65, 0x73, 0x74, 0x2e, 0x74,
	0x78, 0x74, 0x00, /* base_name: "test.txt\0" */
	0x00,		  /* stream_name: "\0" */
};

static void test_ndr_messaging_smb_file_rename_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_file_rename msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_file_rename_blob),
		.length = sizeof(smb_file_rename_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_file_rename_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_FILE_RENAME_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_int_equal(0x0000000100000002ULL, msg.info.info1.id.devid);
	assert_int_equal(0x0000000300000004ULL, msg.info.info1.id.inode);
	assert_int_equal(0, msg.info.info1.id.extid);
	assert_int_equal(7, msg.info.info1.share_file_id);
	assert_string_equal("/data", msg.info.info1.servicepath);
	assert_string_equal("test.txt", msg.info.info1.base_name);
	assert_string_equal(":stream", msg.info.info1.stream_name);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_file_rename_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_file_rename msg = {};
	DATA_BLOB blob = data_blob_null;
	const struct file_id id = {
		.devid = 0x0000000100000002ULL,
		.inode = 0x0000000300000004ULL,
		.extid = 0,
	};
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_file_rename_blob),
		.length = sizeof(smb_file_rename_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_file_rename_push(
		mem_ctx, &msg, id, 7, "/data", "test.txt", ":stream", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_file_rename_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_file_rename orig = {};
	struct messaging_smb_file_rename decoded = {};
	const struct file_id id = {
		.devid = 0,
		.inode = 0,
		.extid = 0,
	};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_file_rename_push(
		mem_ctx, &orig, id, 0, "/data", "test.txt", NULL, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(smb_file_rename_blob_nostream), blob.length);
	assert_memory_equal(smb_file_rename_blob_nostream,
			    blob.data,
			    sizeof(smb_file_rename_blob_nostream));

	err = messaging_smb_file_rename_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_FILE_RENAME_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.info.info1.id.devid);
	assert_int_equal(0, decoded.info.info1.id.inode);
	assert_int_equal(0, decoded.info.info1.id.extid);
	assert_int_equal(0, decoded.info.info1.share_file_id);
	assert_string_equal("/data", decoded.info.info1.servicepath);
	assert_string_equal("test.txt", decoded.info.info1.base_name);
	assert_string_equal("", decoded.info.info1.stream_name);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_file_rename_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_file_rename msg = {};
	uint8_t bad_blob[] = {
		0x02, 0x00, 0x00, 0x00, /* version = 2 (unknown) */
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x02, 0x00, 0x00, 0x00, /* union discriminant = 2 */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_file_rename_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_NOTIFY_CLEANUP */
/*
 * Wire encoding of messaging_smb_notify_cleanup:
 *
 *   01 00 00 00  - version (MESSAGING_SMB_NOTIFY_VERSION_1 = 1,
 *                           uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (version repeated inside union,
 *                                     uint32 LE)
 *
 * info1 (messaging_smb_notify_cleanup_v1) is an empty struct, so there
 * is no body.
 */
static const uint8_t smb_notify_cleanup_blob[] = {
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
};

static void test_ndr_messaging_smb_notify_cleanup_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_cleanup msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_notify_cleanup_blob),
		.length = sizeof(smb_notify_cleanup_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_cleanup_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_cleanup_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_cleanup msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_notify_cleanup_blob),
		.length = sizeof(smb_notify_cleanup_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_cleanup_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_cleanup_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_cleanup orig = {};
	struct messaging_smb_notify_cleanup decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_notify_cleanup_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(smb_notify_cleanup_blob), blob.length);
	assert_memory_equal(smb_notify_cleanup_blob,
			    blob.data,
			    sizeof(smb_notify_cleanup_blob));

	err = messaging_smb_notify_cleanup_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1,
			 decoded.version);
	assert_int_equal(0, decoded.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_cleanup_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_cleanup msg = {};
	/*
	 * Same layout as smb_notify_cleanup_blob but with version =
	 * 0x00000002 (an unknown version value).
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
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_cleanup_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_SCAVENGER */
/*
 * Wire encoding of messaging_smb_scavenger with
 * id = {devid=0x0000000100000002, inode=0x0000000300000004, extid=0},
 * open_persistent_id = 7, name_hash = 0xaabbccdd:
 *
 *   01 00 00 00  - version (MESSAGING_SMB_SCAVENGER_VERSION_1, uint32 LE)
 *   00 00 00 00  - reserved (uint32 LE)
 *   01 00 00 00  - union discriminant (uint32 LE)
 *   02 00 00 00  - devid lo32 = 0x00000002
 *   01 00 00 00  - devid hi32 = 0x00000001
 *   04 00 00 00  - inode lo32 = 0x00000004
 *   03 00 00 00  - inode hi32 = 0x00000003
 *   00 00 00 00  - extid lo32 = 0
 *   00 00 00 00  - extid hi32 = 0
 *   07 00 00 00  - open_persistent_id lo32 = 7
 *   00 00 00 00  - open_persistent_id hi32 = 0
 *   dd cc bb aa  - name_hash = 0xaabbccdd (uint32 LE)
 */
static const uint8_t smb_scavenger_blob[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x02, 0x00, 0x00, 0x00, /* devid lo32 */
	0x01, 0x00, 0x00, 0x00, /* devid hi32 */
	0x04, 0x00, 0x00, 0x00, /* inode lo32 */
	0x03, 0x00, 0x00, 0x00, /* inode hi32 */
	0x00, 0x00, 0x00, 0x00, /* extid lo32 */
	0x00, 0x00, 0x00, 0x00, /* extid hi32 */
	0x07, 0x00, 0x00, 0x00, /* open_persistent_id lo32 */
	0x00, 0x00, 0x00, 0x00, /* open_persistent_id hi32 */
	0xdd, 0xcc, 0xbb, 0xaa, /* name_hash */
};

/*
 * Wire encoding of messaging_smb_scavenger with all-zero file_id,
 * open_persistent_id = 0 and name_hash = 0 (used for roundtrip test):
 */
static const uint8_t smb_scavenger_blob_zero[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x00, 0x00, 0x00, 0x00, /* devid lo32 */
	0x00, 0x00, 0x00, 0x00, /* devid hi32 */
	0x00, 0x00, 0x00, 0x00, /* inode lo32 */
	0x00, 0x00, 0x00, 0x00, /* inode hi32 */
	0x00, 0x00, 0x00, 0x00, /* extid lo32 */
	0x00, 0x00, 0x00, 0x00, /* extid hi32 */
	0x00, 0x00, 0x00, 0x00, /* open_persistent_id lo32 */
	0x00, 0x00, 0x00, 0x00, /* open_persistent_id hi32 */
	0x00, 0x00, 0x00, 0x00, /* name_hash */
};

static void test_ndr_messaging_smb_scavenger_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_scavenger msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_scavenger_blob),
		.length = sizeof(smb_scavenger_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_scavenger_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_SCAVENGER_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_int_equal(0x0000000100000002ULL, msg.info.info1.id.devid);
	assert_int_equal(0x0000000300000004ULL, msg.info.info1.id.inode);
	assert_int_equal(0, msg.info.info1.id.extid);
	assert_int_equal(7, msg.info.info1.open_persistent_id);
	assert_int_equal(0xaabbccdd, msg.info.info1.name_hash);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_scavenger_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_scavenger msg = {};
	DATA_BLOB blob = data_blob_null;
	const struct file_id id = {
		.devid = 0x0000000100000002ULL,
		.inode = 0x0000000300000004ULL,
		.extid = 0,
	};
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_scavenger_blob),
		.length = sizeof(smb_scavenger_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_scavenger_push(
		mem_ctx, &msg, id, 7, 0xaabbccdd, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_scavenger_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_scavenger orig = {};
	struct messaging_smb_scavenger decoded = {};
	const struct file_id id = {
		.devid = 0,
		.inode = 0,
		.extid = 0,
	};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_scavenger_push(mem_ctx, &orig, id, 0, 0, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(smb_scavenger_blob_zero), blob.length);
	assert_memory_equal(smb_scavenger_blob_zero,
			    blob.data,
			    sizeof(smb_scavenger_blob_zero));

	err = messaging_smb_scavenger_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_SCAVENGER_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.info.info1.id.devid);
	assert_int_equal(0, decoded.info.info1.id.inode);
	assert_int_equal(0, decoded.info.info1.id.extid);
	assert_int_equal(0, decoded.info.info1.open_persistent_id);
	assert_int_equal(0, decoded.info.info1.name_hash);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_scavenger_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_scavenger msg = {};
	uint8_t bad_blob[] = {
		0x02, 0x00, 0x00, 0x00, /* version = 2 (unknown) */
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x02, 0x00, 0x00, 0x00, /* union discriminant = 2 */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_scavenger_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_NOTIFY */
static const uint8_t smb_notify_blob[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
};

static void test_ndr_messaging_smb_notify_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_notify_blob),
		.length = sizeof(smb_notify_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_notify_blob),
		.length = sizeof(smb_notify_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify orig = {};
	struct messaging_smb_notify decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_notify_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(sizeof(smb_notify_blob), blob.length);
	assert_memory_equal(smb_notify_blob,
			    blob.data,
			    sizeof(smb_notify_blob));

	err = messaging_smb_notify_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify msg = {};
	uint8_t bad_blob[] = {
		0x02, 0x00, 0x00, 0x00, /* version = 2 (unknown) */
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x02, 0x00, 0x00, 0x00, /* union discriminant */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_NOTIFY_CANCEL_DELETED */
static const uint8_t smb_notify_cancel_deleted_blob[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x02, 0x00, 0x00, 0x00, /* devid lo32 */
	0x01, 0x00, 0x00, 0x00, /* devid hi32 */
	0x04, 0x00, 0x00, 0x00, /* inode lo32 */
	0x03, 0x00, 0x00, 0x00, /* inode hi32 */
	0x00, 0x00, 0x00, 0x00, /* extid lo32 */
	0x00, 0x00, 0x00, 0x00, /* extid hi32 */
};

static const uint8_t smb_notify_cancel_deleted_blob_zero[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x00, 0x00, 0x00, 0x00, /* devid lo32 */
	0x00, 0x00, 0x00, 0x00, /* devid hi32 */
	0x00, 0x00, 0x00, 0x00, /* inode lo32 */
	0x00, 0x00, 0x00, 0x00, /* inode hi32 */
	0x00, 0x00, 0x00, 0x00, /* extid lo32 */
	0x00, 0x00, 0x00, 0x00, /* extid hi32 */
};

static void test_ndr_messaging_smb_notify_cancel_deleted_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_cancel_deleted msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_notify_cancel_deleted_blob),
		.length = sizeof(smb_notify_cancel_deleted_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_cancel_deleted_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_int_equal(0x0000000100000002ULL, msg.info.info1.fid.devid);
	assert_int_equal(0x0000000300000004ULL, msg.info.info1.fid.inode);
	assert_int_equal(0, msg.info.info1.fid.extid);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_cancel_deleted_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_cancel_deleted msg = {};
	DATA_BLOB blob = data_blob_null;
	const struct file_id fid = {
		.devid = 0x0000000100000002ULL,
		.inode = 0x0000000300000004ULL,
		.extid = 0,
	};
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_notify_cancel_deleted_blob),
		.length = sizeof(smb_notify_cancel_deleted_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_cancel_deleted_push(mem_ctx, &msg, fid, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_cancel_deleted_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_cancel_deleted orig = {};
	struct messaging_smb_notify_cancel_deleted decoded = {};
	const struct file_id fid = {0};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_notify_cancel_deleted_push(mem_ctx, &orig, fid, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(sizeof(smb_notify_cancel_deleted_blob_zero), blob.length);
	assert_memory_equal(smb_notify_cancel_deleted_blob_zero,
			    blob.data,
			    sizeof(smb_notify_cancel_deleted_blob_zero));

	err = messaging_smb_notify_cancel_deleted_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.reserved);
	assert_int_equal(0, decoded.info.info1.fid.devid);
	assert_int_equal(0, decoded.info.info1.fid.inode);
	assert_int_equal(0, decoded.info.info1.fid.extid);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_cancel_deleted_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_cancel_deleted msg = {};
	uint8_t bad_blob[] = {
		0x02, 0x00, 0x00, 0x00, /* version = 2 */
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x02, 0x00, 0x00, 0x00, /* union discriminant */
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_cancel_deleted_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_NOTIFY_REC_CHANGE */
/*
 * Wire encoding of messaging_smb_notify_rec_change with
 * creation_time = { tv_sec = 0x0000000100000002, tv_nsec = 3 },
 * filter = 0x11223344, subdir_filter = 0x55667788,
 * private_data = (void *)(uintptr_t)0x12345678,
 * path = "test":
 *
 *   01 00 00 00  - version (MESSAGING_SMB_NOTIFY_REC_CHANGE_VERSION_1, uint32
 * LE) 00 00 00 00  - reserved (uint32 LE) 01 00 00 00  - union discriminant
 * (uint32 LE) 00 00 00 00  - padding to 8-byte align 02 00 00 00  - tv_sec
 * lo32 01 00 00 00  - tv_sec hi32 03 00 00 00  - tv_nsec (uint32 LE) 44 33 22
 * 11  - filter (uint32 LE) 88 77 66 55  - subdir_filter (uint32 LE) [00 00 00
 * 00]- padding to pointer align (if 64-bit) 78 56 34 12  - private_data (lo32)
 *   [00 00 00 00]- private_data (hi32, if 64-bit)
 *   74 65 73 74  - "test"
 *   00           - "\0"
 */
#if __SIZEOF_POINTER__ == 4
static const uint8_t smb_notify_rec_change_blob[] = {
	0x01, 0x00, 0x00, 0x00,	      /* version */
	0x00, 0x00, 0x00, 0x00,	      /* reserved */
	0x01, 0x00, 0x00, 0x00,	      /* union discriminant */
	0x00, 0x00, 0x00, 0x00,	      /* padding */
	0x02, 0x00, 0x00, 0x00,	      /* tv_sec lo32 */
	0x01, 0x00, 0x00, 0x00,	      /* tv_sec hi32 */
	0x03, 0x00, 0x00, 0x00,	      /* tv_nsec */
	0x44, 0x33, 0x22, 0x11,	      /* filter */
	0x88, 0x77, 0x66, 0x55,	      /* subdir_filter */
	0x78, 0x56, 0x34, 0x12,	      /* private_data */
	0x74, 0x65, 0x73, 0x74, 0x00, /* "test\0" */
};

static const uint8_t smb_notify_rec_change_blob_zero[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x00, 0x00, 0x00, 0x00, /* padding */
	0x00, 0x00, 0x00, 0x00, /* tv_sec lo32 */
	0x00, 0x00, 0x00, 0x00, /* tv_sec hi32 */
	0x00, 0x00, 0x00, 0x00, /* tv_nsec */
	0x00, 0x00, 0x00, 0x00, /* filter */
	0x00, 0x00, 0x00, 0x00, /* subdir_filter */
	0x00, 0x00, 0x00, 0x00, /* private_data */
	0x00,			/* "\0" */
};
#else
static const uint8_t smb_notify_rec_change_blob[] = {
	0x01, 0x00, 0x00, 0x00,	      /* version */
	0x00, 0x00, 0x00, 0x00,	      /* reserved */
	0x01, 0x00, 0x00, 0x00,	      /* union discriminant */
	0x00, 0x00, 0x00, 0x00,	      /* padding */
	0x02, 0x00, 0x00, 0x00,	      /* tv_sec lo32 */
	0x01, 0x00, 0x00, 0x00,	      /* tv_sec hi32 */
	0x03, 0x00, 0x00, 0x00,	      /* tv_nsec */
	0x44, 0x33, 0x22, 0x11,	      /* filter */
	0x88, 0x77, 0x66, 0x55,	      /* subdir_filter */
	0x00, 0x00, 0x00, 0x00,	      /* padding */
	0x78, 0x56, 0x34, 0x12,	      /* private_data lo32 */
	0x00, 0x00, 0x00, 0x00,	      /* private_data hi32 */
	0x74, 0x65, 0x73, 0x74, 0x00, /* "test\0" */
};

static const uint8_t smb_notify_rec_change_blob_zero[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x00, 0x00, 0x00, 0x00, /* padding */
	0x00, 0x00, 0x00, 0x00, /* tv_sec lo32 */
	0x00, 0x00, 0x00, 0x00, /* tv_sec hi32 */
	0x00, 0x00, 0x00, 0x00, /* tv_nsec */
	0x00, 0x00, 0x00, 0x00, /* filter */
	0x00, 0x00, 0x00, 0x00, /* subdir_filter */
	0x00, 0x00, 0x00, 0x00, /* padding */
	0x00, 0x00, 0x00, 0x00, /* private_data lo32 */
	0x00, 0x00, 0x00, 0x00, /* private_data hi32 */
	0x00,			/* "\0" */
};
#endif

static void test_ndr_messaging_smb_notify_rec_change_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_rec_change msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_notify_rec_change_blob),
		.length = sizeof(smb_notify_rec_change_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_rec_change_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1,
			 msg.version);
	assert_int_equal(0, msg.reserved);
	assert_int_equal(0x0000000100000002ULL, msg.info.info1.tv_sec);
	assert_int_equal(3, msg.info.info1.tv_nsec);
	assert_int_equal(0x11223344, msg.info.info1.filter);
	assert_int_equal(0x55667788, msg.info.info1.subdir_filter);
	assert_ptr_equal((void *)(uintptr_t)0x12345678,
			 msg.info.info1.private_data);
	assert_string_equal("test", msg.info.info1.path);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_rec_change_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_rec_change msg = {};
	DATA_BLOB blob = data_blob_null;
	struct timespec creation_time = {
		.tv_sec = 0x0000000100000002ULL,
		.tv_nsec = 3,
	};
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_notify_rec_change_blob),
		.length = sizeof(smb_notify_rec_change_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_rec_change_push(
		mem_ctx,
		&msg,
		creation_time,
		0x11223344,
		0x55667788,
		(void *)(uintptr_t)0x12345678,
		"test",
		&blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_rec_change_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_rec_change orig = {};
	struct messaging_smb_notify_rec_change decoded = {};
	struct timespec creation_time = {
		.tv_sec = 0,
		.tv_nsec = 0,
	};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_notify_rec_change_push(
		mem_ctx, &orig, creation_time, 0, 0, NULL, "", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	/* The encoded blob must match the reference vector. */
	assert_int_equal(sizeof(smb_notify_rec_change_blob_zero), blob.length);
	assert_memory_equal(smb_notify_rec_change_blob_zero,
			    blob.data,
			    sizeof(smb_notify_rec_change_blob_zero));

	err = messaging_smb_notify_rec_change_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1,
			 decoded.version);
	assert_int_equal(0, decoded.info.info1.tv_sec);
	assert_int_equal(0, decoded.info.info1.tv_nsec);
	assert_int_equal(0, decoded.info.info1.filter);
	assert_int_equal(0, decoded.info.info1.subdir_filter);
	assert_null(decoded.info.info1.private_data);
	assert_string_equal("", decoded.info.info1.path);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_rec_change_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_rec_change msg = {};
	uint8_t bad_blob[] = {
		0x02, 0x00, 0x00, 0x00, /* version = 2 (unknown) */
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x02, 0x00, 0x00, 0x00, /* union discriminant = 2 */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_rec_change_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_NOTIFY_TRIGGER */
/*
	* Wire encoding of messaging_smb_notify_trigger with
	* when = { tv_sec = 0x0000000100000002, tv_nsec = 3 },
	* action = 4, filter = 0x11223344, path = "test":
	*/
static const uint8_t smb_notify_trigger_blob[] = {
	0x01, 0x00, 0x00, 0x00,	      /* version */
	0x00, 0x00, 0x00, 0x00,	      /* reserved */
	0x01, 0x00, 0x00, 0x00,	      /* union discriminant */
	0x00, 0x00, 0x00, 0x00,	      /* padding */
	0x02, 0x00, 0x00, 0x00,	      /* tv_sec lo32 */
	0x01, 0x00, 0x00, 0x00,	      /* tv_sec hi32 */
	0x03, 0x00, 0x00, 0x00,	      /* tv_nsec */
	0x04, 0x00, 0x00, 0x00,	      /* action */
	0x44, 0x33, 0x22, 0x11,	      /* filter */
	0x74, 0x65, 0x73, 0x74, 0x00, /* "test\0" */
};

static const uint8_t smb_notify_trigger_blob_zero[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x00, 0x00, 0x00, 0x00, /* padding */
	0x00, 0x00, 0x00, 0x00, /* tv_sec lo32 */
	0x00, 0x00, 0x00, 0x00, /* tv_sec hi32 */
	0x00, 0x00, 0x00, 0x00, /* tv_nsec */
	0x00, 0x00, 0x00, 0x00, /* action */
	0x00, 0x00, 0x00, 0x00, /* filter */
	0x00,			/* "\0" */
};

static void test_ndr_messaging_smb_notify_trigger_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_trigger msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_notify_trigger_blob),
		.length = sizeof(smb_notify_trigger_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_trigger_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_int_equal(0x0000000100000002ULL, msg.info.info1.tv_sec);
	assert_int_equal(3, msg.info.info1.tv_nsec);
	assert_int_equal(4, msg.info.info1.action);
	assert_int_equal(0x11223344, msg.info.info1.filter);
	assert_string_equal("test", msg.info.info1.path);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_trigger_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_trigger msg = {};
	DATA_BLOB blob = data_blob_null;
	const struct timespec when = {
		.tv_sec = 0x0000000100000002ULL,
		.tv_nsec = 3,
	};
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_notify_trigger_blob),
		.length = sizeof(smb_notify_trigger_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_trigger_push(
		mem_ctx, &msg, when, 4, 0x11223344, "test", &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_trigger_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_trigger orig = {};
	struct messaging_smb_notify_trigger decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_notify_trigger_push(
		mem_ctx, &orig, (struct timespec){0}, 0, 0, NULL, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(sizeof(smb_notify_trigger_blob_zero), blob.length);
	assert_memory_equal(smb_notify_trigger_blob_zero,
			    blob.data,
			    sizeof(smb_notify_trigger_blob_zero));

	err = messaging_smb_notify_trigger_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.info.info1.tv_sec);
	assert_int_equal(0, decoded.info.info1.tv_nsec);
	assert_int_equal(0, decoded.info.info1.action);
	assert_int_equal(0, decoded.info.info1.filter);
	assert_string_equal("", decoded.info.info1.path);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_trigger_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_trigger msg = {};
	uint8_t bad_blob[] = {
		0x02, 0x00, 0x00, 0x00, /* version = 2 */
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x02, 0x00, 0x00, 0x00, /* union discriminant */
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00,
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_trigger_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_NOTIFY_GET_DB */
static const uint8_t smb_notify_get_db_blob[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
};

static void test_ndr_messaging_smb_notify_get_db_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_get_db msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_notify_get_db_blob),
		.length = sizeof(smb_notify_get_db_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_get_db_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_get_db_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_get_db msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_notify_get_db_blob),
		.length = sizeof(smb_notify_get_db_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_get_db_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_get_db_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_get_db orig = {};
	struct messaging_smb_notify_get_db decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_notify_get_db_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(sizeof(smb_notify_get_db_blob), blob.length);
	assert_memory_equal(smb_notify_get_db_blob,
			    blob.data,
			    sizeof(smb_notify_get_db_blob));

	err = messaging_smb_notify_get_db_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_get_db_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_get_db msg = {};
	uint8_t bad_blob[] = {
		0x02, 0x00, 0x00, 0x00, /* version = 2 */
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x02, 0x00, 0x00, 0x00, /* union discriminant */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_get_db_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_NOTIFY_DB */
static const uint8_t smb_notify_db_blob[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x00, 0x00, 0x00, 0x00, /* padding */
	0x02, 0x00, 0x00, 0x00, /* rec_index lo32 */
	0x01, 0x00, 0x00, 0x00, /* rec_index hi32 */
	0x04, 0x00, 0x00, 0x00, /* db.length = 4 */
	0x11, 0x22, 0x33, 0x44, /* db.data */
};

static const uint8_t smb_notify_db_blob_zero[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x00, 0x00, 0x00, 0x00, /* padding */
	0x00, 0x00, 0x00, 0x00, /* rec_index lo32 */
	0x00, 0x00, 0x00, 0x00, /* rec_index hi32 */
	0x00, 0x00, 0x00, 0x00, /* db.length = 0 */
};

static void test_ndr_messaging_smb_notify_db_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_db msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_notify_db_blob),
		.length = sizeof(smb_notify_db_blob),
	};
	static const uint8_t expected_db[] = {0x11, 0x22, 0x33, 0x44};
	enum ndr_err_code err;

	err = messaging_smb_notify_db_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_int_equal(0x0000000100000002ULL, msg.info.info1.rec_index);
	assert_int_equal(sizeof(expected_db), msg.info.info1.db.length);
	assert_memory_equal(expected_db, msg.info.info1.db.data, sizeof(expected_db));

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_db_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_db msg = {};
	DATA_BLOB blob = data_blob_null;
	static uint8_t db_data[] = {0x11, 0x22, 0x33, 0x44};
	const DATA_BLOB db = {
		.data = db_data,
		.length = sizeof(db_data),
	};
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_notify_db_blob),
		.length = sizeof(smb_notify_db_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_db_push(
		mem_ctx, &msg, 0x0000000100000002ULL, db, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_db_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_db orig = {};
	struct messaging_smb_notify_db decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_notify_db_push(
		mem_ctx, &orig, 0, data_blob_null, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(sizeof(smb_notify_db_blob_zero), blob.length);
	assert_memory_equal(smb_notify_db_blob_zero,
			    blob.data,
			    sizeof(smb_notify_db_blob_zero));

	err = messaging_smb_notify_db_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.info.info1.rec_index);
	assert_int_equal(0, decoded.info.info1.db.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_db_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_db msg = {};
	uint8_t bad_blob[] = {
		0x02, 0x00, 0x00, 0x00, /* version = 2 */
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x02, 0x00, 0x00, 0x00, /* union discriminant */
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_db_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_NOTIFY_REC_CHANGES */
static const uint8_t smb_notify_rec_changes_blob[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
	0x00, 0x00, 0x00, 0x00, /* padding */
	0x05, 0x00, 0x00, 0x00, /* reclog.rec_index lo32 */
	0x00, 0x00, 0x00, 0x00, /* reclog.rec_index hi32 */
	0x00, 0x00, 0x00, 0x00, /* reclog.num_recs = 0 */
};

static void test_ndr_messaging_smb_notify_rec_changes_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_rec_changes msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_notify_rec_changes_blob),
		.length = sizeof(smb_notify_rec_changes_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_rec_changes_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);
	assert_int_equal(5, msg.info.info1.reclog.rec_index);
	assert_int_equal(0, msg.info.info1.reclog.num_recs);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_rec_changes_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_rec_changes msg = {};
	struct messaging_reclog reclog = {
		.rec_index = 5,
		.num_recs = 0,
	};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_notify_rec_changes_blob),
		.length = sizeof(smb_notify_rec_changes_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_rec_changes_push(
		mem_ctx, &msg, &reclog, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_rec_changes_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_rec_changes orig = {};
	struct messaging_smb_notify_rec_changes decoded = {};
	struct messaging_reclog reclog = {
		.rec_index = 5,
		.num_recs = 0,
	};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_notify_rec_changes_push(
		mem_ctx, &orig, &reclog, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(sizeof(smb_notify_rec_changes_blob), blob.length);
	assert_memory_equal(smb_notify_rec_changes_blob,
			    blob.data,
			    sizeof(smb_notify_rec_changes_blob));

	err = messaging_smb_notify_rec_changes_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, decoded.version);
	assert_int_equal(5, decoded.info.info1.reclog.rec_index);
	assert_int_equal(0, decoded.info.info1.reclog.num_recs);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_rec_changes_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_rec_changes msg = {};
	uint8_t bad_blob[] = {
		0x02, 0x00, 0x00, 0x00, /* version = 2 */
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x02, 0x00, 0x00, 0x00, /* union discriminant */
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_rec_changes_pull(mem_ctx, &blob, &msg);
	assert_int_not_equal(NDR_ERR_SUCCESS, err);

	talloc_free(mem_ctx);
}

/* MSG_SMB_NOTIFY_STARTED */
static const uint8_t smb_notify_started_blob[] = {
	0x01, 0x00, 0x00, 0x00, /* version */
	0x00, 0x00, 0x00, 0x00, /* reserved */
	0x01, 0x00, 0x00, 0x00, /* union discriminant */
};

static void test_ndr_messaging_smb_notify_started_pull(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_started msg = {};
	const DATA_BLOB blob = {
		.data = discard_const_p(uint8_t, smb_notify_started_blob),
		.length = sizeof(smb_notify_started_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_started_pull(mem_ctx, &blob, &msg);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, msg.version);
	assert_int_equal(0, msg.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_started_push(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_started msg = {};
	DATA_BLOB blob = data_blob_null;
	const DATA_BLOB expected = {
		.data = discard_const_p(uint8_t, smb_notify_started_blob),
		.length = sizeof(smb_notify_started_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_started_push(mem_ctx, &msg, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(expected.length, blob.length);
	assert_memory_equal(expected.data, blob.data, expected.length);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_started_roundtrip(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_started orig = {};
	struct messaging_smb_notify_started decoded = {};
	DATA_BLOB blob = data_blob_null;
	enum ndr_err_code err;

	err = messaging_smb_notify_started_push(mem_ctx, &orig, &blob);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(sizeof(smb_notify_started_blob), blob.length);
	assert_memory_equal(smb_notify_started_blob,
			    blob.data,
			    sizeof(smb_notify_started_blob));

	err = messaging_smb_notify_started_pull(mem_ctx, &blob, &decoded);
	assert_int_equal(NDR_ERR_SUCCESS, err);

	assert_int_equal(MESSAGING_SMB_NOTIFY_VERSION_1, decoded.version);
	assert_int_equal(0, decoded.reserved);

	talloc_free(mem_ctx);
}

static void test_ndr_messaging_smb_notify_started_bad_version(void **state)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct messaging_smb_notify_started msg = {};
	uint8_t bad_blob[] = {
		0x02, 0x00, 0x00, 0x00, /* version = 2 */
		0x00, 0x00, 0x00, 0x00, /* reserved */
		0x02, 0x00, 0x00, 0x00, /* union discriminant */
	};
	const DATA_BLOB blob = {
		.data = bad_blob,
		.length = sizeof(bad_blob),
	};
	enum ndr_err_code err;

	err = messaging_smb_notify_started_pull(mem_ctx, &blob, &msg);
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
		cmocka_unit_test(test_ndr_messaging_req_profilelevel_pull),
		cmocka_unit_test(test_ndr_messaging_req_profilelevel_push),
		cmocka_unit_test(
			test_ndr_messaging_req_profilelevel_bad_version),
		cmocka_unit_test(test_ndr_messaging_profilelevel_pull),
		cmocka_unit_test(test_ndr_messaging_profilelevel_push),
		cmocka_unit_test(test_ndr_messaging_profilelevel_roundtrip),
		cmocka_unit_test(test_ndr_messaging_profilelevel_bad_version),
		cmocka_unit_test(test_ndr_messaging_ping_pull),
		cmocka_unit_test(test_ndr_messaging_ping_push),
		cmocka_unit_test(test_ndr_messaging_ping_roundtrip),
		cmocka_unit_test(test_ndr_messaging_ping_bad_version),
		cmocka_unit_test(test_ndr_messaging_pong_pull),
		cmocka_unit_test(test_ndr_messaging_pong_push),
		cmocka_unit_test(test_ndr_messaging_pong_bad_version),
		cmocka_unit_test(test_ndr_messaging_shutdown_pull),
		cmocka_unit_test(test_ndr_messaging_shutdown_push),
		cmocka_unit_test(test_ndr_messaging_shutdown_roundtrip),
		cmocka_unit_test(test_ndr_messaging_shutdown_bad_version),
		cmocka_unit_test(test_ndr_messaging_req_pool_usage_pull),
		cmocka_unit_test(test_ndr_messaging_req_pool_usage_push),
		cmocka_unit_test(test_ndr_messaging_req_pool_usage_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_req_pool_usage_bad_version),
		cmocka_unit_test(test_ndr_messaging_req_dmalloc_mark_pull),
		cmocka_unit_test(test_ndr_messaging_req_dmalloc_mark_push),
		cmocka_unit_test(
			test_ndr_messaging_req_dmalloc_mark_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_req_dmalloc_mark_bad_version),
		cmocka_unit_test(
			test_ndr_messaging_req_dmalloc_log_changed_pull),
		cmocka_unit_test(
			test_ndr_messaging_req_dmalloc_log_changed_push),
		cmocka_unit_test(
			test_ndr_messaging_req_dmalloc_log_changed_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_req_dmalloc_log_changed_bad_version),
		cmocka_unit_test(test_ndr_messaging_id_cache_delete_pull),
		cmocka_unit_test(test_ndr_messaging_id_cache_delete_push),
		cmocka_unit_test(test_ndr_messaging_id_cache_delete_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_id_cache_delete_bad_version),
		cmocka_unit_test(test_ndr_messaging_id_cache_kill_pull),
		cmocka_unit_test(test_ndr_messaging_id_cache_kill_push),
		cmocka_unit_test(test_ndr_messaging_id_cache_kill_roundtrip),
		cmocka_unit_test(test_ndr_messaging_id_cache_kill_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_conf_updated_pull),
		cmocka_unit_test(test_ndr_messaging_smb_conf_updated_push),
		cmocka_unit_test(
			test_ndr_messaging_smb_conf_updated_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_smb_conf_updated_bad_version),
		cmocka_unit_test(
			test_ndr_messaging_reload_tls_certificates_pull),
		cmocka_unit_test(
			test_ndr_messaging_reload_tls_certificates_push),
		cmocka_unit_test(
			test_ndr_messaging_reload_tls_certificates_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_reload_tls_certificates_bad_version),
		cmocka_unit_test(test_ndr_messaging_req_ringbuf_log_pull),
		cmocka_unit_test(test_ndr_messaging_req_ringbuf_log_push),
		cmocka_unit_test(
			test_ndr_messaging_req_ringbuf_log_bad_version),
		cmocka_unit_test(test_ndr_messaging_ringbuf_log_pull),
		cmocka_unit_test(test_ndr_messaging_ringbuf_log_push),
		cmocka_unit_test(test_ndr_messaging_ringbuf_log_roundtrip),
		cmocka_unit_test(test_ndr_messaging_ringbuf_log_bad_version),
		cmocka_unit_test(test_ndr_messaging_force_election_pull),
		cmocka_unit_test(test_ndr_messaging_force_election_push),
		cmocka_unit_test(test_ndr_messaging_force_election_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_force_election_bad_version),
		cmocka_unit_test(test_ndr_messaging_force_tdis_pull),
		cmocka_unit_test(test_ndr_messaging_force_tdis_push),
		cmocka_unit_test(test_ndr_messaging_force_tdis_roundtrip),
		cmocka_unit_test(test_ndr_messaging_force_tdis_bad_version),
		cmocka_unit_test(test_ndr_messaging_force_tdis_denied_pull),
		cmocka_unit_test(test_ndr_messaging_force_tdis_denied_push),
		cmocka_unit_test(
			test_ndr_messaging_force_tdis_denied_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_force_tdis_denied_bad_version),
		cmocka_unit_test(test_ndr_messaging_kill_client_ip_pull),
		cmocka_unit_test(test_ndr_messaging_kill_client_ip_push),
		cmocka_unit_test(test_ndr_messaging_kill_client_ip_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_kill_client_ip_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_ip_dropped_pull),
		cmocka_unit_test(test_ndr_messaging_smb_ip_dropped_push),
		cmocka_unit_test(test_ndr_messaging_smb_ip_dropped_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_smb_ip_dropped_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_sleep_pull),
		cmocka_unit_test(test_ndr_messaging_smb_sleep_push),
		cmocka_unit_test(test_ndr_messaging_smb_sleep_roundtrip),
		cmocka_unit_test(test_ndr_messaging_smb_sleep_bad_version),
		cmocka_unit_test(
			test_ndr_messaging_smb_tell_num_children_pull),
		cmocka_unit_test(
			test_ndr_messaging_smb_tell_num_children_push),
		cmocka_unit_test(
			test_ndr_messaging_smb_tell_num_children_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_num_children_pull),
		cmocka_unit_test(test_ndr_messaging_smb_num_children_push),
		cmocka_unit_test(
			test_ndr_messaging_smb_num_children_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_smb_num_children_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_inject_fault_pull),
		cmocka_unit_test(test_ndr_messaging_smb_inject_fault_push),
		cmocka_unit_test(
			test_ndr_messaging_smb_inject_fault_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_smb_inject_fault_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_close_file_pull),
		cmocka_unit_test(test_ndr_messaging_smb_close_file_push),
		cmocka_unit_test(test_ndr_messaging_smb_close_file_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_smb_close_file_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_file_rename_pull),
		cmocka_unit_test(test_ndr_messaging_smb_file_rename_push),
		cmocka_unit_test(test_ndr_messaging_smb_file_rename_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_smb_file_rename_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_notify_cleanup_pull),
		cmocka_unit_test(test_ndr_messaging_smb_notify_cleanup_push),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_cleanup_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_cleanup_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_scavenger_pull),
		cmocka_unit_test(test_ndr_messaging_smb_scavenger_push),
		cmocka_unit_test(test_ndr_messaging_smb_scavenger_roundtrip),
		cmocka_unit_test(test_ndr_messaging_smb_scavenger_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_notify_pull),
		cmocka_unit_test(test_ndr_messaging_smb_notify_push),
		cmocka_unit_test(test_ndr_messaging_smb_notify_roundtrip),
		cmocka_unit_test(test_ndr_messaging_smb_notify_bad_version),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_cancel_deleted_pull),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_cancel_deleted_push),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_cancel_deleted_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_cancel_deleted_bad_version),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_rec_change_pull),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_rec_change_push),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_rec_change_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_rec_change_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_notify_trigger_pull),
		cmocka_unit_test(test_ndr_messaging_smb_notify_trigger_push),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_trigger_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_trigger_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_notify_get_db_pull),
		cmocka_unit_test(test_ndr_messaging_smb_notify_get_db_push),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_get_db_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_get_db_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_notify_db_pull),
		cmocka_unit_test(test_ndr_messaging_smb_notify_db_push),
		cmocka_unit_test(test_ndr_messaging_smb_notify_db_roundtrip),
		cmocka_unit_test(test_ndr_messaging_smb_notify_db_bad_version),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_rec_changes_pull),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_rec_changes_push),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_rec_changes_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_rec_changes_bad_version),
		cmocka_unit_test(test_ndr_messaging_smb_notify_started_pull),
		cmocka_unit_test(test_ndr_messaging_smb_notify_started_push),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_started_roundtrip),
		cmocka_unit_test(
			test_ndr_messaging_smb_notify_started_bad_version),
	};
	if (!isatty(1)) {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}
	return cmocka_run_group_tests(tests, NULL, NULL);
}

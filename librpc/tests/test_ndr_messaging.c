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
	};
	if (!isatty(1)) {
		cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	}
	return cmocka_run_group_tests(tests, NULL, NULL);
}

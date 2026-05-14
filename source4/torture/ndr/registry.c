/* Dynamic round-trip tests for registry ndr operations */

#include "includes.h"
#include "torture/ndr/ndr.h"
#include "torture/ndr/proto.h"
#include "../source3/librpc/gen_ndr/ndr_registry.h"
#include "librpc/gen_ndr/ndr_winreg.h"

static bool test_registry_value_list_v4_empty(struct torture_context *tctx)
{
	struct registry_value_list_blob blob_out, blob_in;
	DATA_BLOB ndr_blob;
	enum ndr_err_code ndr_err;

	/* Create empty value list */
	ZERO_STRUCT(blob_out);
	blob_out.version = REGDB_VERSION_V4;
	blob_out.reserved = 0;
	blob_out.ctr.v4.num_values = 0;
	blob_out.ctr.v4.values = NULL;
	blob_out.ctr.v4.seqnum = 0;

	/* Pack */
	ndr_err = ndr_push_struct_blob(
		&ndr_blob,
		tctx,
		&blob_out,
		(ndr_push_flags_fn_t)ndr_push_registry_value_list_blob);
	torture_assert_ndr_success(tctx, ndr_err, "ndr_push failed");

	/* Unpack */
	ZERO_STRUCT(blob_in);
	ndr_err = ndr_pull_struct_blob(
		&ndr_blob,
		tctx,
		&blob_in,
		(ndr_pull_flags_fn_t)ndr_pull_registry_value_list_blob);
	torture_assert_ndr_success(tctx, ndr_err, "ndr_pull failed");

	/* Verify */
	torture_assert_int_equal(tctx,
				 blob_in.version,
				 REGDB_VERSION_V4,
				 "version");
	torture_assert_int_equal(tctx,
				 blob_in.ctr.v4.num_values,
				 0,
				 "num_values");
	torture_assert_int_equal(tctx, blob_in.ctr.v4.seqnum, 0, "seqnum");

	return true;
}

static bool //
test_registry_value_list_v4_single_string(struct torture_context *tctx)
{
	struct registry_value_list_blob blob_out, blob_in;
	DATA_BLOB ndr_blob;
	enum ndr_err_code ndr_err;
	const uint8_t string_data[] = {
		0x48,
		0x00,
		0x65,
		0x00,
		0x6c,
		0x00,
		0x6c,
		0x00,
		0x6f,
		0x00,
		0x00,
		0x00,
	}; /* "Hello" UTF-16LE */

	/* Create value list with one string */
	ZERO_STRUCT(blob_out);
	blob_out.version = REGDB_VERSION_V4;
	blob_out.reserved = 0;
	blob_out.ctr.v4.num_values = 1;
	blob_out.ctr.v4.seqnum = 10;
	blob_out.ctr.v4.values = talloc_array(tctx,
					      struct registry_value_v4,
					      1);
	torture_assert(tctx,
		       blob_out.ctr.v4.values != NULL,
		       "allocation failed");

	blob_out.ctr.v4.values[0].valuename_len = 8;
	blob_out.ctr.v4.values[0].valuename = (uint8_t *)
		talloc_strdup(tctx, "TestStr");
	blob_out.ctr.v4.values[0].type = REG_SZ;
	blob_out.ctr.v4.values[0].size = sizeof(string_data);
	blob_out.ctr.v4.values[0].data = talloc_memdup(tctx,
						       string_data,
						       sizeof(string_data));

	/* Pack */
	ndr_err = ndr_push_struct_blob(
		&ndr_blob,
		tctx,
		&blob_out,
		(ndr_push_flags_fn_t)ndr_push_registry_value_list_blob);
	torture_assert_ndr_success(tctx, ndr_err, "ndr_push failed");

	/* Unpack */
	ZERO_STRUCT(blob_in);
	ndr_err = ndr_pull_struct_blob(
		&ndr_blob,
		tctx,
		&blob_in,
		(ndr_pull_flags_fn_t)ndr_pull_registry_value_list_blob);
	torture_assert_ndr_success(tctx, ndr_err, "ndr_pull failed");

	/* Verify */
	torture_assert_int_equal(tctx,
				 blob_in.version,
				 REGDB_VERSION_V4,
				 "version");
	torture_assert_int_equal(tctx,
				 blob_in.ctr.v4.num_values,
				 1,
				 "num_values");
	torture_assert_int_equal(tctx, blob_in.ctr.v4.seqnum, 10, "seqnum");
	torture_assert_str_equal(
		tctx,
		(const char *)blob_in.ctr.v4.values[0].valuename,
		"TestStr",
		"value name");
	torture_assert_int_equal(tctx,
				 blob_in.ctr.v4.values[0].type,
				 REG_SZ,
				 "value type");
	torture_assert_int_equal(tctx,
				 blob_in.ctr.v4.values[0].size,
				 sizeof(string_data),
				 "data size");
	torture_assert_mem_equal(tctx,
				 blob_in.ctr.v4.values[0].data,
				 string_data,
				 sizeof(string_data),
				 "data content");

	return true;
}

static bool //
test_registry_value_list_v4_single_dword(struct torture_context *tctx)
{
	struct registry_value_list_blob blob_out, blob_in;
	DATA_BLOB ndr_blob;
	enum ndr_err_code ndr_err;
	uint32_t result_dword, dword_value = 0xDEADBEEF;

	/* Create value list with one DWORD */
	ZERO_STRUCT(blob_out);
	blob_out.version = REGDB_VERSION_V4;
	blob_out.reserved = 0;
	blob_out.ctr.v4.num_values = 1;
	blob_out.ctr.v4.seqnum = 5;
	blob_out.ctr.v4.values = talloc_array(tctx,
					      struct registry_value_v4,
					      1);
	torture_assert(tctx,
		       blob_out.ctr.v4.values != NULL,
		       "allocation failed");

	blob_out.ctr.v4.values[0].valuename_len = 10;
	blob_out.ctr.v4.values[0].valuename = (uint8_t *)
		talloc_strdup(tctx, "TestDWORD");
	blob_out.ctr.v4.values[0].type = REG_DWORD;
	blob_out.ctr.v4.values[0].size = sizeof(uint32_t);
	blob_out.ctr.v4.values[0].data = talloc_memdup(tctx,
						       &dword_value,
						       sizeof(uint32_t));

	/* Pack */
	ndr_err = ndr_push_struct_blob(
		&ndr_blob,
		tctx,
		&blob_out,
		(ndr_push_flags_fn_t)ndr_push_registry_value_list_blob);
	torture_assert_ndr_success(tctx, ndr_err, "ndr_push failed");

	/* Unpack */
	ZERO_STRUCT(blob_in);
	ndr_err = ndr_pull_struct_blob(
		&ndr_blob,
		tctx,
		&blob_in,
		(ndr_pull_flags_fn_t)ndr_pull_registry_value_list_blob);
	torture_assert_ndr_success(tctx, ndr_err, "ndr_pull failed");

	/* Verify */
	torture_assert_int_equal(tctx,
				 blob_in.version,
				 REGDB_VERSION_V4,
				 "version");
	torture_assert_int_equal(tctx,
				 blob_in.ctr.v4.num_values,
				 1,
				 "num_values");
	torture_assert_int_equal(tctx, blob_in.ctr.v4.seqnum, 5, "seqnum");
	torture_assert_str_equal(
		tctx,
		(const char *)blob_in.ctr.v4.values[0].valuename,
		"TestDWORD",
		"value name");
	torture_assert_int_equal(tctx,
				 blob_in.ctr.v4.values[0].type,
				 REG_DWORD,
				 "value type");
	torture_assert_int_equal(tctx,
				 blob_in.ctr.v4.values[0].size,
				 sizeof(uint32_t),
				 "data size");

	memcpy(&result_dword, blob_in.ctr.v4.values[0].data, sizeof(uint32_t));
	torture_assert_int_equal(tctx,
				 result_dword,
				 0xDEADBEEF,
				 "dword value");

	return true;
}

static bool test_registry_subkey_list_v4_empty(struct torture_context *tctx)
{
	struct registry_subkey_list_blob blob_out, blob_in;
	DATA_BLOB ndr_blob;
	enum ndr_err_code ndr_err;

	/* Create empty subkey list */
	ZERO_STRUCT(blob_out);
	blob_out.version = REGDB_VERSION_V4;
	blob_out.reserved = 0;
	blob_out.ctr.v4.num_subkeys = 0;
	blob_out.ctr.v4.subkeys = NULL;
	blob_out.ctr.v4.seqnum = 0;

	/* Pack */
	ndr_err = ndr_push_struct_blob(
		&ndr_blob,
		tctx,
		&blob_out,
		(ndr_push_flags_fn_t)ndr_push_registry_subkey_list_blob);
	torture_assert_ndr_success(tctx, ndr_err, "ndr_push failed");

	/* Unpack */
	ZERO_STRUCT(blob_in);
	ndr_err = ndr_pull_struct_blob(
		&ndr_blob,
		tctx,
		&blob_in,
		(ndr_pull_flags_fn_t)ndr_pull_registry_subkey_list_blob);
	torture_assert_ndr_success(tctx, ndr_err, "ndr_pull failed");

	/* Verify */
	torture_assert_int_equal(tctx,
				 blob_in.version,
				 REGDB_VERSION_V4,
				 "version");
	torture_assert_int_equal(tctx,
				 blob_in.ctr.v4.num_subkeys,
				 0,
				 "num_subkeys");
	torture_assert_int_equal(tctx, blob_in.ctr.v4.seqnum, 0, "seqnum");

	return true;
}

static bool test_registry_subkey_list_v4_multiple(struct torture_context *tctx)
{
	struct registry_subkey_list_blob blob_out, blob_in;
	DATA_BLOB ndr_blob;
	enum ndr_err_code ndr_err;

	/* Create subkey list with 3 subkeys */
	ZERO_STRUCT(blob_out);
	blob_out.version = REGDB_VERSION_V4;
	blob_out.reserved = 0;
	blob_out.ctr.v4.num_subkeys = 3;
	blob_out.ctr.v4.seqnum = 20;
	blob_out.ctr.v4.subkeys = talloc_zero_array(tctx, const char *, 3);
	torture_assert(tctx,
		       blob_out.ctr.v4.subkeys != NULL,
		       "allocation failed");

	/* Assign string literals */
	blob_out.ctr.v4.subkeys[0] = "Software";
	blob_out.ctr.v4.subkeys[1] = "System";
	blob_out.ctr.v4.subkeys[2] = "Hardware";

	/* Pack */
	ndr_err = ndr_push_struct_blob(
		&ndr_blob,
		tctx,
		&blob_out,
		(ndr_push_flags_fn_t)ndr_push_registry_subkey_list_blob);
	torture_assert_ndr_success(tctx, ndr_err, "ndr_push failed");

	/* Unpack */
	ZERO_STRUCT(blob_in);
	ndr_err = ndr_pull_struct_blob(
		&ndr_blob,
		tctx,
		&blob_in,
		(ndr_pull_flags_fn_t)ndr_pull_registry_subkey_list_blob);
	torture_assert_ndr_success(tctx, ndr_err, "ndr_pull failed");

	/* Verify */
	torture_assert_int_equal(tctx,
				 blob_in.version,
				 REGDB_VERSION_V4,
				 "version");
	torture_assert_int_equal(tctx,
				 blob_in.ctr.v4.num_subkeys,
				 3,
				 "num_subkeys");
	torture_assert_int_equal(tctx, blob_in.ctr.v4.seqnum, 20, "seqnum");

	/* Verify subkeys are not NULL and have content */
	torture_assert(tctx,
		       blob_in.ctr.v4.subkeys != NULL,
		       "subkeys array is NULL");
	torture_assert(tctx,
		       blob_in.ctr.v4.subkeys[0] != NULL,
		       "subkey 0 is NULL");
	torture_assert(tctx,
		       blob_in.ctr.v4.subkeys[1] != NULL,
		       "subkey 1 is NULL");
	torture_assert(tctx,
		       blob_in.ctr.v4.subkeys[2] != NULL,
		       "subkey 2 is NULL");

	/* Verify string content */
	torture_assert_str_equal(tctx,
				 blob_in.ctr.v4.subkeys[0],
				 "Software",
				 "subkey 0 name");
	torture_assert_str_equal(tctx,
				 blob_in.ctr.v4.subkeys[1],
				 "System",
				 "subkey 1 name");
	torture_assert_str_equal(tctx,
				 blob_in.ctr.v4.subkeys[2],
				 "Hardware",
				 "subkey 2 name");

	return true;
}

static bool //
test_registry_value_list_v4_multiple_types(struct torture_context *tctx)
{
	struct registry_value_list_blob blob_out, blob_in;
	DATA_BLOB ndr_blob;
	enum ndr_err_code ndr_err;
	uint32_t result_dword, dword_value = 42;
	const uint8_t binary_data[] = {
		0x01,
		0x02,
		0x03,
		0x04,
		0x05,
	};
	const uint8_t string_data[] = {
		0x54,
		0x00,
		0x65,
		0x00,
		0x73,
		0x00,
		0x74,
		0x00,
	}; /* "Test" UTF-16LE */

	/* Create value list with 3 values of different types */
	ZERO_STRUCT(blob_out);
	blob_out.version = REGDB_VERSION_V4;
	blob_out.reserved = 0;
	blob_out.ctr.v4.num_values = 3;
	blob_out.ctr.v4.seqnum = 15;
	blob_out.ctr.v4.values = talloc_array(tctx,
					      struct registry_value_v4,
					      3);
	torture_assert(tctx,
		       blob_out.ctr.v4.values != NULL,
		       "allocation failed");

	/* Value 0: DWORD */
	blob_out.ctr.v4.values[0].valuename_len = 6;
	blob_out.ctr.v4.values[0].valuename = (uint8_t *)
		talloc_strdup(tctx, "Value");
	blob_out.ctr.v4.values[0].type = REG_DWORD;
	blob_out.ctr.v4.values[0].size = sizeof(uint32_t);
	blob_out.ctr.v4.values[0].data = talloc_memdup(tctx,
						       &dword_value,
						       sizeof(uint32_t));

	/* Value 1: Binary */
	blob_out.ctr.v4.values[1].valuename_len = 7;
	blob_out.ctr.v4.values[1].valuename = (uint8_t *)
		talloc_strdup(tctx, "Binary");
	blob_out.ctr.v4.values[1].type = REG_BINARY;
	blob_out.ctr.v4.values[1].size = sizeof(binary_data);
	blob_out.ctr.v4.values[1].data = talloc_memdup(tctx,
						       binary_data,
						       sizeof(binary_data));

	/* Value 2: String */
	blob_out.ctr.v4.values[2].valuename_len = 4;
	blob_out.ctr.v4.values[2].valuename = (uint8_t *)talloc_strdup(tctx,
								       "Str");
	blob_out.ctr.v4.values[2].type = REG_SZ;
	blob_out.ctr.v4.values[2].size = sizeof(string_data);
	blob_out.ctr.v4.values[2].data = talloc_memdup(tctx,
						       string_data,
						       sizeof(string_data));

	/* Pack */
	ndr_err = ndr_push_struct_blob(
		&ndr_blob,
		tctx,
		&blob_out,
		(ndr_push_flags_fn_t)ndr_push_registry_value_list_blob);
	torture_assert_ndr_success(tctx, ndr_err, "ndr_push failed");

	/* Unpack */
	ZERO_STRUCT(blob_in);
	ndr_err = ndr_pull_struct_blob(
		&ndr_blob,
		tctx,
		&blob_in,
		(ndr_pull_flags_fn_t)ndr_pull_registry_value_list_blob);
	torture_assert_ndr_success(tctx, ndr_err, "ndr_pull failed");

	/* Verify */
	torture_assert_int_equal(tctx,
				 blob_in.version,
				 REGDB_VERSION_V4,
				 "version");
	torture_assert_int_equal(tctx,
				 blob_in.ctr.v4.num_values,
				 3,
				 "num_values");
	torture_assert_int_equal(tctx, blob_in.ctr.v4.seqnum, 15, "seqnum");

	/* Check value 0: DWORD */
	torture_assert_str_equal(
		tctx,
		(const char *)blob_in.ctr.v4.values[0].valuename,
		"Value",
		"value 0 name");
	torture_assert_int_equal(tctx,
				 blob_in.ctr.v4.values[0].type,
				 REG_DWORD,
				 "value 0 type");
	memcpy(&result_dword, blob_in.ctr.v4.values[0].data, sizeof(uint32_t));
	torture_assert_int_equal(tctx, result_dword, 42, "value 0 data");

	/* Check value 1: Binary */
	torture_assert_str_equal(
		tctx,
		(const char *)blob_in.ctr.v4.values[1].valuename,
		"Binary",
		"value 1 name");
	torture_assert_int_equal(tctx,
				 blob_in.ctr.v4.values[1].type,
				 REG_BINARY,
				 "value 1 type");
	torture_assert_mem_equal(tctx,
				 blob_in.ctr.v4.values[1].data,
				 binary_data,
				 sizeof(binary_data),
				 "value 1 data");

	/* Check value 2: String */
	torture_assert_str_equal(
		tctx,
		(const char *)blob_in.ctr.v4.values[2].valuename,
		"Str",
		"value 2 name");
	torture_assert_int_equal(tctx,
				 blob_in.ctr.v4.values[2].type,
				 REG_SZ,
				 "value 2 type");

	return true;
}

struct torture_suite *ndr_registry_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "registry");

	torture_suite_add_simple_test(suite,
				      "value_list_v4_empty",
				      test_registry_value_list_v4_empty);

	torture_suite_add_simple_test(suite,
				      "subkey_list_v4_empty",
				      test_registry_subkey_list_v4_empty);

	torture_suite_add_simple_test(
		suite,
		"value_list_v4_single_string",
		test_registry_value_list_v4_single_string);

	torture_suite_add_simple_test(
		suite,
		"value_list_v4_single_dword",
		test_registry_value_list_v4_single_dword);

	torture_suite_add_simple_test(suite,
				      "subkey_list_v4_multiple",
				      test_registry_subkey_list_v4_multiple);

	torture_suite_add_simple_test(
		suite,
		"value_list_v4_multiple_types",
		test_registry_value_list_v4_multiple_types);

	return suite;
}

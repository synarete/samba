/* Test registry format V4 (IDL) */

#include "includes.h"
#include "torture/proto.h"
#include "registry.h"
#include "registry/reg_objects.h"
#include "registry/reg_backend_db.h"
#include "librpc/gen_ndr/ndr_registry.h"

/* Empty V3 value list */
static uint8_t registry_value_list_v3_empty_data[] = {
	0x00,
	0x00,
	0x00,
	0x00, /* num_values = 0 */
};

/* V3 value list with single DWORD */
static uint8_t registry_value_list_v3_single_dword_data[] = {
	0x01, 0x00, 0x00, 0x00, /* num_values = 1 */
	0x54, 0x65, 0x73, 0x74, /* "Test" */
	0x56, 0x61, 0x6c, 0x00, /* "Val\0" */
	0x04, 0x00, 0x00, 0x00, /* type = REG_DWORD */
	0x04, 0x00, 0x00, 0x00, /* size = 4 */
	0x2a, 0x00, 0x00, 0x00, /* data = 42 */
};

/* V3 subkey list with two subkeys */
static uint8_t registry_subkey_list_v3_double_data[] = {
	0x02,
	0x00,
	0x00,
	0x00, /* num_subkeys = 2 */
	0x53,
	0x75,
	0x62,
	0x31, /* "Sub1" */
	0x00, /* null terminator */
	0x53,
	0x75,
	0x62,
	0x32, /* "Sub2" */
	0x00, /* null terminator */
};

/*
 * Test pack/unpack round-trip for registry values
 */
bool run_registry_pack_unpack_values(int dummy)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct regval_ctr *values_in = NULL;
	struct regval_ctr *values_out = NULL;
	uint8_t *buf = NULL;
	size_t buflen = 0;
	WERROR werr;
	bool result = false;
	int ret;
	uint32_t dword_val = 0x12345678;
	const char *test_string = "Hello World";
	uint8_t binary_data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
	uint32_t i;

	printf("test: registry_pack_unpack_values\n");

	mem_ctx = talloc_stackframe();
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_stackframe failed\n");
		return false;
	}

	/* Create input value container */
	werr = regval_ctr_init(mem_ctx, &values_in);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regval_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Add various types of values */
	ret = regval_ctr_addvalue_sz(values_in, "TestString", test_string);
	if (ret == -1) {
		fprintf(stderr, "Failed to add string value\n");
		goto done;
	}

	ret = regval_ctr_addvalue(values_in,
				  "TestDword",
				  REG_DWORD,
				  (uint8_t *)&dword_val,
				  sizeof(uint32_t));
	if (ret == -1) {
		fprintf(stderr, "Failed to add DWORD value\n");
		goto done;
	}

	ret = regval_ctr_addvalue(values_in,
				  "TestBinary",
				  REG_BINARY,
				  binary_data,
				  sizeof(binary_data));
	if (ret == -1) {
		fprintf(stderr, "Failed to add binary value\n");
		goto done;
	}

	/* Pack values using V4 format */
	werr = regdb_pack_values_v4(values_in, &buf, &buflen, mem_ctx);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_pack_values_v4 failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	printf("Packed %u values into %zu bytes\n",
	       regval_ctr_numvals(values_in),
	       buflen);

	/* Create output value container */
	werr = regval_ctr_init(mem_ctx, &values_out);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regval_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Unpack values */
	werr = regdb_unpack_values_v4(values_out, buf, buflen);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_unpack_values_v4 failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Verify value count */
	if (regval_ctr_numvals(values_in) != regval_ctr_numvals(values_out)) {
		fprintf(stderr,
			"Value count mismatch: %u != %u\n",
			regval_ctr_numvals(values_in),
			regval_ctr_numvals(values_out));
		goto done;
	}

	/* Verify each value */
	for (i = 0; i < regval_ctr_numvals(values_in); i++) {
		struct regval_blob *val_in = NULL, *val_out = NULL;

		val_in = regval_ctr_specific_value(values_in, i);
		val_out = regval_ctr_value_byname(values_out,
						  regval_name(val_in));

		if (val_out == NULL) {
			fprintf(stderr,
				"Value '%s' not found in output\n",
				regval_name(val_in));
			goto done;
		}

		if (regval_type(val_in) != regval_type(val_out)) {
			fprintf(stderr,
				"Type mismatch for '%s': %u != %u\n",
				regval_name(val_in),
				regval_type(val_in),
				regval_type(val_out));
			goto done;
		}

		if (regval_size(val_in) != regval_size(val_out)) {
			fprintf(stderr,
				"Size mismatch for '%s': %u != %u\n",
				regval_name(val_in),
				regval_size(val_in),
				regval_size(val_out));
			goto done;
		}

		if (memcmp(regval_data_p(val_in),
			   regval_data_p(val_out),
			   regval_size(val_in)) != 0)
		{
			fprintf(stderr,
				"Data mismatch for '%s'\n",
				regval_name(val_in));
			goto done;
		}
	}

	printf("All values verified successfully\n");
	result = true;

done:
	TALLOC_FREE(mem_ctx);
	printf("test: %s\n", result ? "success" : "failure");
	return result;
}

/*
 * Test pack/unpack round-trip for registry subkeys
 */
bool run_registry_pack_unpack_keys(int dummy)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct regsubkey_ctr *keys_in = NULL;
	struct regsubkey_ctr *keys_out = NULL;
	uint8_t *buf = NULL;
	size_t buflen = 0;
	WERROR werr;
	bool result = false;
	uint32_t i;
	const char *test_keys[] = {
		"Software",
		"System",
		"Hardware",
		"Security",
		NULL,
	};
	const char *expected_keys[] = {
		/* sorted */
		"Hardware",
		"Security",
		"Software",
		"System",
		NULL,
	};

	printf("test: registry_pack_unpack_keys\n");

	mem_ctx = talloc_stackframe();
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_stackframe failed\n");
		return false;
	}

	/* Create input subkey container */
	werr = regsubkey_ctr_init(mem_ctx, &keys_in);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regsubkey_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Add test subkeys */
	for (i = 0; test_keys[i] != NULL; i++) {
		werr = regsubkey_ctr_addkey(keys_in, test_keys[i]);
		if (!W_ERROR_IS_OK(werr)) {
			fprintf(stderr,
				"Failed to add subkey '%s': %s\n",
				test_keys[i],
				win_errstr(werr));
			goto done;
		}
	}

	/* Set sequence number */
	werr = regsubkey_ctr_set_seqnum(keys_in, 42);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"Failed to set seqnum: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Pack subkeys using V4 format */
	werr = regdb_pack_keys_v4(keys_in, &buf, &buflen, mem_ctx);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_pack_keys_v4 failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	printf("Packed %u subkeys into %zu bytes\n",
	       regsubkey_ctr_numkeys(keys_in),
	       buflen);

	/* Create output subkey container */
	werr = regsubkey_ctr_init(mem_ctx, &keys_out);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regsubkey_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Unpack subkeys */
	werr = regdb_unpack_keys_v4(keys_out, buf, buflen);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_unpack_keys_v4 failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Verify subkey count */
	if (regsubkey_ctr_numkeys(keys_in) != regsubkey_ctr_numkeys(keys_out))
	{
		fprintf(stderr,
			"Subkey count mismatch: %u != %u\n",
			regsubkey_ctr_numkeys(keys_in),
			regsubkey_ctr_numkeys(keys_out));
		goto done;
	}

	/* Verify sequence number */
	if (regsubkey_ctr_get_seqnum(keys_in) !=
	    regsubkey_ctr_get_seqnum(keys_out))
	{
		fprintf(stderr,
			"Seqnum mismatch: %d != %d\n",
			regsubkey_ctr_get_seqnum(keys_in),
			regsubkey_ctr_get_seqnum(keys_out));
		goto done;
	}

	/* Verify V4 canonicalizes subkeys into sorted order */
	for (i = 0; expected_keys[i] != NULL; i++) {
		const char *key_out = regsubkey_ctr_specific_key(keys_out, i);

		if (strcmp(expected_keys[i], key_out) != 0) {
			fprintf(stderr,
				"Subkey mismatch at index %u: '%s' != '%s'\n",
				i,
				expected_keys[i],
				key_out);
			goto done;
		}
	}

	printf("All subkeys verified successfully\n");
	result = true;

done:
	TALLOC_FREE(mem_ctx);
	printf("test: %s\n", result ? "success" : "failure");
	return result;
}

/*
 * Test empty value list
 */
bool run_registry_empty_values(int dummy)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct regval_ctr *values_in = NULL;
	struct regval_ctr *values_out = NULL;
	uint8_t *buf = NULL;
	size_t buflen = 0;
	WERROR werr;
	bool result = false;

	printf("test: registry_empty_values\n");

	mem_ctx = talloc_stackframe();
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_stackframe failed\n");
		return false;
	}

	/* Create empty value container */
	werr = regval_ctr_init(mem_ctx, &values_in);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regval_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Pack empty values */
	werr = regdb_pack_values_v4(values_in, &buf, &buflen, mem_ctx);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_pack_values_v4 failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	printf("Packed empty value list into %zu bytes\n", buflen);

	/* Create output value container */
	werr = regval_ctr_init(mem_ctx, &values_out);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regval_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Unpack empty values */
	werr = regdb_unpack_values_v4(values_out, buf, buflen);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_unpack_values_v4 failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Verify empty */
	if (regval_ctr_numvals(values_out) != 0) {
		fprintf(stderr,
			"Expected 0 values, got %u\n",
			regval_ctr_numvals(values_out));
		goto done;
	}

	printf("Empty value list verified successfully\n");
	result = true;

done:
	TALLOC_FREE(mem_ctx);
	printf("test: %s\n", result ? "success" : "failure");
	return result;
}

/*
 * Test empty subkey list
 */
bool run_registry_empty_keys(int dummy)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct regsubkey_ctr *keys_in = NULL;
	struct regsubkey_ctr *keys_out = NULL;
	uint8_t *buf = NULL;
	size_t buflen = 0;
	WERROR werr;
	bool result = false;

	printf("test: registry_empty_keys\n");

	mem_ctx = talloc_stackframe();
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_stackframe failed\n");
		return false;
	}

	/* Create empty subkey container */
	werr = regsubkey_ctr_init(mem_ctx, &keys_in);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regsubkey_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Pack empty subkeys */
	werr = regdb_pack_keys_v4(keys_in, &buf, &buflen, mem_ctx);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_pack_keys_v4 failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	printf("Packed empty subkey list into %zu bytes\n", buflen);

	/* Create output subkey container */
	werr = regsubkey_ctr_init(mem_ctx, &keys_out);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regsubkey_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Unpack empty subkeys */
	werr = regdb_unpack_keys_v4(keys_out, buf, buflen);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_unpack_keys_v4 failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Verify empty */
	if (regsubkey_ctr_numkeys(keys_out) != 0) {
		fprintf(stderr,
			"Expected 0 subkeys, got %u\n",
			regsubkey_ctr_numkeys(keys_out));
		goto done;
	}

	printf("Empty subkey list verified successfully\n");
	result = true;

done:
	TALLOC_FREE(mem_ctx);
	printf("test: %s\n", result ? "success" : "failure");
	return result;
}

/*
 * Test regsubkey_ctr sorted insertion, lookup and deletion semantics
 */
bool run_registry_subkey_ctr_binary_search(int dummy)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct regsubkey_ctr *ctr = NULL;
	WERROR werr;
	bool result = false;
	uint32_t i;
	const char *expected_keys[] = {
		"Hardware", "Security", "Software", "System", NULL};
	const char *input_keys[] = {
		"Software", "System", "Hardware", "Security", NULL};

	printf("test: registry_subkey_ctr_binary_search\n");

	mem_ctx = talloc_stackframe();
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_stackframe failed\n");
		return false;
	}

	werr = regsubkey_ctr_init(mem_ctx, &ctr);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regsubkey_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	for (i = 0; input_keys[i] != NULL; i++) {
		werr = regsubkey_ctr_addkey(ctr, input_keys[i]);
		if (!W_ERROR_IS_OK(werr)) {
			fprintf(stderr,
				"Failed to add subkey '%s': %s\n",
				input_keys[i],
				win_errstr(werr));
			goto done;
		}
	}

	if (!regsubkey_ctr_key_exists(ctr, "Hardware") ||
	    !regsubkey_ctr_key_exists(ctr, "Software") ||
	    regsubkey_ctr_key_exists(ctr, "Missing"))
	{
		fprintf(stderr,
			"Binary-search-backed key existence check failed\n");
		goto done;
	}

	for (i = 0; expected_keys[i] != NULL; i++) {
		const char *key = regsubkey_ctr_specific_key(ctr, i);

		if (key == NULL || strcmp(key, expected_keys[i]) != 0) {
			fprintf(stderr,
				"Unexpected sorted key at index %u: '%s' != "
				"'%s'\n",
				i,
				expected_keys[i],
				key ? key : "(null)");
			goto done;
		}
	}

	werr = regsubkey_ctr_addkey(ctr, "Software");
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"Duplicate add failed unexpectedly: %s\n",
			win_errstr(werr));
		goto done;
	}

	if (regsubkey_ctr_numkeys(ctr) != 4) {
		fprintf(stderr,
			"Duplicate add changed key count: %u\n",
			regsubkey_ctr_numkeys(ctr));
		goto done;
	}

	werr = regsubkey_ctr_delkey(ctr, "Security");
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr, "Delete failed: %s\n", win_errstr(werr));
		goto done;
	}

	if (regsubkey_ctr_key_exists(ctr, "Security")) {
		fprintf(stderr, "Deleted key still exists\n");
		goto done;
	}

	if (regsubkey_ctr_numkeys(ctr) != 3) {
		fprintf(stderr,
			"Unexpected key count after delete: %u\n",
			regsubkey_ctr_numkeys(ctr));
		goto done;
	}

	if (strcmp(regsubkey_ctr_specific_key(ctr, 0), "Hardware") != 0 ||
	    strcmp(regsubkey_ctr_specific_key(ctr, 1), "Software") != 0 ||
	    strcmp(regsubkey_ctr_specific_key(ctr, 2), "System") != 0)
	{
		fprintf(stderr, "Sorted order not preserved after delete\n");
		goto done;
	}

	printf("Sorted insertion, lookup and deletion verified "
	       "successfully\n");
	result = true;

done:
	TALLOC_FREE(mem_ctx);
	printf("test: %s\n", result ? "success" : "failure");
	return result;
}

/*
 * Test V3 to V4 upgrade for registry values
 */
bool run_registry_v3_to_v4_values(int dummy)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct regval_ctr *values_in = NULL;
	struct regval_ctr *values_out = NULL;
	uint8_t v3_buf[4096];
	uint8_t *v4_buf = NULL;
	size_t v4_buflen = 0;
	int v3_len;
	int ret;
	WERROR werr;
	bool result = false;
	uint32_t dword_val = 0xDEADBEEF;
	const char *test_string = "V3 to V4 Test";
	uint32_t i;

	printf("test: registry_v3_to_v4_values\n");

	mem_ctx = talloc_stackframe();
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_stackframe failed\n");
		return false;
	}

	/* Create test data in V3 format */
	werr = regval_ctr_init(mem_ctx, &values_in);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regval_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Add test values */
	ret = regval_ctr_addvalue_sz(values_in, "V3String", test_string);
	if (ret == -1) {
		fprintf(stderr, "Failed to add string value\n");
		goto done;
	}

	ret = regval_ctr_addvalue(values_in,
				  "V3Dword",
				  REG_DWORD,
				  (uint8_t *)&dword_val,
				  sizeof(uint32_t));
	if (ret == -1) {
		fprintf(stderr, "Failed to add DWORD value\n");
		goto done;
	}

	/* Pack using V3 format (legacy) */
	v3_len = regdb_pack_values_v3(values_in, v3_buf, sizeof(v3_buf));
	if (v3_len <= 0) {
		fprintf(stderr, "regdb_pack_values_v3 failed\n");
		goto done;
	}

	printf("Packed %u values into %d bytes (V3 format)\n",
	       regval_ctr_numvals(values_in),
	       v3_len);

	/* Unpack using V4 unpack function (should handle V3 via fallback) */
	werr = regval_ctr_init(mem_ctx, &values_out);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regval_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	werr = regdb_unpack_values_v4(values_out, v3_buf, v3_len);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_unpack_values_v4 failed to read V3 format: "
			"%s\n",
			win_errstr(werr));
		goto done;
	}

	printf("Successfully unpacked V3 format using V4 unpack function\n");

	/* Verify value count */
	if (regval_ctr_numvals(values_in) != regval_ctr_numvals(values_out)) {
		fprintf(stderr,
			"Value count mismatch: %u != %u\n",
			regval_ctr_numvals(values_in),
			regval_ctr_numvals(values_out));
		goto done;
	}

	/* Verify each value */
	for (i = 0; i < regval_ctr_numvals(values_in); i++) {
		struct regval_blob *val_in;
		struct regval_blob *val_out;

		val_in = regval_ctr_specific_value(values_in, i);
		val_out = regval_ctr_value_byname(values_out,
						  regval_name(val_in));

		if (val_out == NULL) {
			fprintf(stderr,
				"Value '%s' not found after upgrade\n",
				regval_name(val_in));
			goto done;
		}

		if (regval_type(val_in) != regval_type(val_out)) {
			fprintf(stderr,
				"Type mismatch for '%s'\n",
				regval_name(val_in));
			goto done;
		}

		if (regval_size(val_in) != regval_size(val_out)) {
			fprintf(stderr,
				"Size mismatch for '%s'\n",
				regval_name(val_in));
			goto done;
		}

		if (memcmp(regval_data_p(val_in),
			   regval_data_p(val_out),
			   regval_size(val_in)) != 0)
		{
			fprintf(stderr,
				"Data mismatch for '%s'\n",
				regval_name(val_in));
			goto done;
		}
	}

	/* Now repack using V4 format */
	werr = regdb_pack_values_v4(values_out, &v4_buf, &v4_buflen, mem_ctx);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_pack_values_v4 failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	printf("Repacked into %zu bytes (V4 format)\n", v4_buflen);
	printf("V3 to V4 upgrade successful\n");

	result = true;

done:
	TALLOC_FREE(mem_ctx);
	printf("test: %s\n", result ? "success" : "failure");
	return result;
}

/*
 * Test V3 to V4 upgrade for registry subkeys
 */
bool run_registry_v3_to_v4_keys(int dummy)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct regsubkey_ctr *keys_in = NULL;
	struct regsubkey_ctr *keys_out = NULL;
	uint8_t v3_buf[4096];
	uint8_t *v4_buf = NULL;
	size_t v4_buflen = 0;
	int v3_len;
	WERROR werr;
	bool result = false;
	uint32_t i;
	const char *test_keys[] = {"V3Key1", "V3Key2", "V3Key3", NULL};

	printf("test: registry_v3_to_v4_keys\n");

	mem_ctx = talloc_stackframe();
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_stackframe failed\n");
		return false;
	}

	/* Create test data in V3 format */
	werr = regsubkey_ctr_init(mem_ctx, &keys_in);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regsubkey_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Add test subkeys */
	for (i = 0; test_keys[i] != NULL; i++) {
		werr = regsubkey_ctr_addkey(keys_in, test_keys[i]);
		if (!W_ERROR_IS_OK(werr)) {
			fprintf(stderr,
				"Failed to add subkey '%s': %s\n",
				test_keys[i],
				win_errstr(werr));
			goto done;
		}
	}

	/* Pack using V3 format (legacy) */
	v3_len = regdb_pack_keys_v3(keys_in, v3_buf, sizeof(v3_buf));
	if (v3_len <= 0) {
		fprintf(stderr, "regdb_pack_keys_v3 failed\n");
		goto done;
	}

	printf("Packed %u subkeys into %d bytes (V3 format)\n",
	       regsubkey_ctr_numkeys(keys_in),
	       v3_len);

	/* Unpack using V4 unpack function (should handle V3 via fallback) */
	werr = regsubkey_ctr_init(mem_ctx, &keys_out);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regsubkey_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	werr = regdb_unpack_keys_v4(keys_out, v3_buf, v3_len);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_unpack_keys_v4 failed to read V3 format: %s\n",
			win_errstr(werr));
		goto done;
	}

	printf("Successfully unpacked V3 format using V4 unpack function\n");

	/* Verify subkey count */
	if (regsubkey_ctr_numkeys(keys_in) != regsubkey_ctr_numkeys(keys_out))
	{
		fprintf(stderr,
			"Subkey count mismatch: %u != %u\n",
			regsubkey_ctr_numkeys(keys_in),
			regsubkey_ctr_numkeys(keys_out));
		goto done;
	}

	/* V3 fallback preserves legacy order */
	for (i = 0; i < regsubkey_ctr_numkeys(keys_in); i++) {
		const char *key_in = regsubkey_ctr_specific_key(keys_in, i);
		const char *key_out = regsubkey_ctr_specific_key(keys_out, i);

		if (strcmp(key_in, key_out) != 0) {
			fprintf(stderr,
				"Subkey mismatch at index %u: '%s' != '%s'\n",
				i,
				key_in,
				key_out);
			goto done;
		}
	}

	/* Now repack using V4 format */
	werr = regdb_pack_keys_v4(keys_out, &v4_buf, &v4_buflen, mem_ctx);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_pack_keys_v4 failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	printf("Repacked into %zu bytes (V4 format)\n", v4_buflen);
	printf("V3 to V4 upgrade successful\n");

	result = true;

done:
	TALLOC_FREE(mem_ctx);
	printf("test: %s\n", result ? "success" : "failure");
	return result;
}

/*
 * Test unpacking V3 empty value list using raw test vector
 */
bool run_registry_v3_empty_values_vector(int dummy)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct regval_ctr *values_out = NULL;
	WERROR werr;
	bool result = false;

	printf("test: registry_v3_empty_values_vector\n");

	mem_ctx = talloc_stackframe();
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_stackframe failed\n");
		return false;
	}

	/* Create output value container */
	werr = regval_ctr_init(mem_ctx, &values_out);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regval_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Unpack V3 empty value list */
	werr = regdb_unpack_values_v4(
		values_out,
		registry_value_list_v3_empty_data,
		sizeof(registry_value_list_v3_empty_data));
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_unpack_values_v4 failed on V3 empty data: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Verify empty */
	if (regval_ctr_numvals(values_out) != 0) {
		fprintf(stderr,
			"Expected 0 values, got %u\n",
			regval_ctr_numvals(values_out));
		goto done;
	}

	printf("V3 empty value list vector verified successfully\n");
	result = true;

done:
	TALLOC_FREE(mem_ctx);
	printf("test: %s\n", result ? "success" : "failure");
	return result;
}

/*
 * Test unpacking V3 single DWORD value using raw test vector
 */
bool run_registry_v3_single_dword_vector(int dummy)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct regval_ctr *values_out = NULL;
	struct regval_blob *val = NULL;
	WERROR werr;
	bool result = false;
	uint32_t dword_val;

	printf("test: registry_v3_single_dword_vector\n");

	mem_ctx = talloc_stackframe();
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_stackframe failed\n");
		return false;
	}

	/* Create output value container */
	werr = regval_ctr_init(mem_ctx, &values_out);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regval_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Unpack V3 single DWORD value list */
	werr = regdb_unpack_values_v4(
		values_out,
		registry_value_list_v3_single_dword_data,
		sizeof(registry_value_list_v3_single_dword_data));
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_unpack_values_v4 failed on V3 single DWORD "
			"data: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Verify value count */
	if (regval_ctr_numvals(values_out) != 1) {
		fprintf(stderr,
			"Expected 1 value, got %u\n",
			regval_ctr_numvals(values_out));
		goto done;
	}

	/* Get the value */
	val = regval_ctr_value_byname(values_out, "TestVal");
	if (val == NULL) {
		fprintf(stderr, "Value 'TestVal' not found\n");
		goto done;
	}

	/* Verify type */
	if (regval_type(val) != REG_DWORD) {
		fprintf(stderr,
			"Expected type REG_DWORD (4), got %u\n",
			regval_type(val));
		goto done;
	}

	/* Verify size */
	if (regval_size(val) != 4) {
		fprintf(stderr, "Expected size 4, got %u\n", regval_size(val));
		goto done;
	}

	/* Verify data */
	memcpy(&dword_val, regval_data_p(val), sizeof(uint32_t));
	if (dword_val != 42) {
		fprintf(stderr, "Expected value 42, got %u\n", dword_val);
		goto done;
	}

	printf("V3 single DWORD value vector verified successfully\n");
	result = true;

done:
	TALLOC_FREE(mem_ctx);
	printf("test: %s\n", result ? "success" : "failure");
	return result;
}

/*
 * Test unpacking V3 double subkey list using raw test vector
 */
bool run_registry_v3_double_subkeys_vector(int dummy)
{
	TALLOC_CTX *mem_ctx = NULL;
	struct regsubkey_ctr *keys_out = NULL;
	WERROR werr;
	bool result = false;
	const char *key1, *key2;

	printf("test: registry_v3_double_subkeys_vector\n");

	mem_ctx = talloc_stackframe();
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_stackframe failed\n");
		return false;
	}

	/* Create output subkey container */
	werr = regsubkey_ctr_init(mem_ctx, &keys_out);
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regsubkey_ctr_init failed: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Unpack V3 double subkey list */
	werr = regdb_unpack_keys_v4(
		keys_out,
		registry_subkey_list_v3_double_data,
		sizeof(registry_subkey_list_v3_double_data));
	if (!W_ERROR_IS_OK(werr)) {
		fprintf(stderr,
			"regdb_unpack_keys_v4 failed on V3 double subkey "
			"data: %s\n",
			win_errstr(werr));
		goto done;
	}

	/* Verify subkey count */
	if (regsubkey_ctr_numkeys(keys_out) != 2) {
		fprintf(stderr,
			"Expected 2 subkeys, got %u\n",
			regsubkey_ctr_numkeys(keys_out));
		goto done;
	}

	/* Verify first subkey */
	key1 = regsubkey_ctr_specific_key(keys_out, 0);
	if (key1 == NULL || strcmp(key1, "Sub1") != 0) {
		fprintf(stderr,
			"Expected first subkey 'Sub1', got '%s'\n",
			key1 ? key1 : "(null)");
		goto done;
	}

	/* Verify second subkey */
	key2 = regsubkey_ctr_specific_key(keys_out, 1);
	if (key2 == NULL || strcmp(key2, "Sub2") != 0) {
		fprintf(stderr,
			"Expected second subkey 'Sub2', got '%s'\n",
			key2 ? key2 : "(null)");
		goto done;
	}

	printf("V3 double subkey list vector verified successfully\n");
	result = true;

done:
	TALLOC_FREE(mem_ctx);
	printf("test: %s\n", result ? "success" : "failure");
	return result;
}

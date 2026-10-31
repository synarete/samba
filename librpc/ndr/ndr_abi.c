/*
   Unix SMB/CIFS implementation.

   NDR wire format ABI checks

   Copyright (C) Stefan Metzmacher 2026

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/time.h"
#include "librpc/ndr/libndr.h"
#include "lib/util/bytearray.h"
#include "librpc/gen_ndr/security.h"
#include "librpc/gen_ndr/witness.h"
#include "librpc/gen_ndr/file_id.h"
#include "librpc/ndr/ndr_abi.h"

void ndr_abi_invalid_selection(struct ndr_abi_state *state,
			       const char *union_name)
{
	fprintf(stderr,
		"%s: invalid union arm selection for %s\n",
		state->sample->name,
		union_name);
	state->failed = true;
}

void *ndr_abi_talloc_zero(struct ndr_abi_state *state, size_t size)
{
	void *ptr = talloc_zero_size(state->mem_ctx, size);
	if (ptr == NULL) {
		fprintf(stderr, "%s: out of memory\n", state->sample->name);
		abort();
	}
	return ptr;
}

void *ndr_abi_talloc_zero_array(struct ndr_abi_state *state,
				size_t el_size,
				size_t count)
{
	if (count == 0) {
		return NULL;
	}
	return ndr_abi_talloc_zero(state, el_size * count);
}

/*
 * Each byte gets a different value, so that
 * changes in size or byte order are visible.
 */
uint64_t ndr_abi_uint(struct ndr_abi_state *state, unsigned bits)
{
	uint8_t n = (uint8_t)++state->counter;
	uint64_t v = 0;
	unsigned i;

	for (i = 0; i < bits / 8; i++) {
		uint64_t b = (uint8_t)(n + i);
		v |= b << (i * 8);
	}

	return v;
}

int64_t ndr_abi_range(struct ndr_abi_state *state, int64_t min, int64_t max)
{
	uint64_t n = ndr_abi_uint(state, 32);
	uint64_t span;

	if (max < min) {
		fprintf(stderr,
			"%s: invalid range(%" PRId64 ",%" PRId64 ")\n",
			state->sample->name, min, max);
		state->failed = true;
		return min;
	}

	span = (uint64_t)max - (uint64_t)min;
	if (span == UINT64_MAX) {
		return (int64_t)n;
	}

	return min + (int64_t)(n % (span + 1));
}

uint32_t ndr_abi_count(struct ndr_abi_state *state, int64_t min, int64_t max)
{
	int64_t v = state->min_counts ? 0 : 2;

	if (v < min) {
		v = min;
	}
	if (v > max) {
		v = max;
	}

	return (uint32_t)v;
}

/*
 * All strings have 14 characters, e.g. "string00000013",
 * so null terminated strings have an odd length in 8-bit
 * encodings and a length not aligned to 4 in UTF-16,
 * which makes alignment problems of the following
 * elements visible.
 */
const char *ndr_abi_string(struct ndr_abi_state *state)
{
	const char *s = talloc_asprintf(state->mem_ctx,
					"string%08" PRIu64,
					++state->counter % 100000000);
	if (s == NULL) {
		fprintf(stderr, "%s: out of memory\n", state->sample->name);
		abort();
	}
	return s;
}

void ndr_abi_fill_uint8(struct ndr_abi_state *state, uint8_t *v)
{
	*v = ndr_abi_uint(state, 8);
}

void ndr_abi_fill_int8(struct ndr_abi_state *state, int8_t *v)
{
	*v = ndr_abi_uint(state, 8);
}

void ndr_abi_fill_uint16(struct ndr_abi_state *state, uint16_t *v)
{
	*v = ndr_abi_uint(state, 16);
}

void ndr_abi_fill_int16(struct ndr_abi_state *state, int16_t *v)
{
	*v = ndr_abi_uint(state, 16);
}

void ndr_abi_fill_uint1632(struct ndr_abi_state *state, uint16_t *v)
{
	*v = ndr_abi_uint(state, 16);
}

void ndr_abi_fill_uint32(struct ndr_abi_state *state, uint32_t *v)
{
	*v = ndr_abi_uint(state, 32);
}

void ndr_abi_fill_int32(struct ndr_abi_state *state, int32_t *v)
{
	*v = ndr_abi_uint(state, 32);
}

void ndr_abi_fill_uint3264(struct ndr_abi_state *state, uint32_t *v)
{
	*v = ndr_abi_uint(state, 32);
}

void ndr_abi_fill_hyper(struct ndr_abi_state *state, uint64_t *v)
{
	*v = ndr_abi_uint(state, 64);
}

void ndr_abi_fill_int64(struct ndr_abi_state *state, int64_t *v)
{
	*v = ndr_abi_uint(state, 64);
}

void ndr_abi_fill_dlong(struct ndr_abi_state *state, int64_t *v)
{
	*v = ndr_abi_uint(state, 64);
}

void ndr_abi_fill_udlong(struct ndr_abi_state *state, uint64_t *v)
{
	*v = ndr_abi_uint(state, 64);
}

void ndr_abi_fill_udlongr(struct ndr_abi_state *state, uint64_t *v)
{
	*v = ndr_abi_uint(state, 64);
}

/*
 * The bit patterns of the sample values,
 * so that each byte is visible like for integers.
 */
void ndr_abi_fill_float(struct ndr_abi_state *state, float *v)
{
	uint32_t bits = ndr_abi_uint(state, 32);

	static_assert(sizeof(*v) == sizeof(bits), "float is not 32-bit");
	memcpy(v, &bits, sizeof(bits));
}

void ndr_abi_fill_double(struct ndr_abi_state *state, double *v)
{
	uint64_t bits = ndr_abi_uint(state, 64);

	static_assert(sizeof(*v) == sizeof(bits), "double is not 64-bit");
	memcpy(v, &bits, sizeof(bits));
}

void ndr_abi_fill_NTTIME(struct ndr_abi_state *state, NTTIME *v)
{
	*v = ndr_abi_uint(state, 64);
}

void ndr_abi_fill_NTTIME_1sec(struct ndr_abi_state *state, NTTIME *v)
{
	*v = ndr_abi_uint(state, 64);
}

void ndr_abi_fill_NTTIME_hyper(struct ndr_abi_state *state, NTTIME *v)
{
	*v = ndr_abi_uint(state, 64);
}

/*
 * time_t, uid_t and gid_t may be 32-bit on some
 * platforms, so we only use 31 bits.
 */
void ndr_abi_fill_time_t(struct ndr_abi_state *state, time_t *v)
{
	*v = ndr_abi_uint(state, 32) & INT32_MAX;
}

void ndr_abi_fill_uid_t(struct ndr_abi_state *state, uid_t *v)
{
	*v = ndr_abi_uint(state, 32) & INT32_MAX;
}

void ndr_abi_fill_gid_t(struct ndr_abi_state *state, gid_t *v)
{
	*v = ndr_abi_uint(state, 32) & INT32_MAX;
}

void ndr_abi_fill_NTSTATUS(struct ndr_abi_state *state, NTSTATUS *v)
{
	*v = NT_STATUS(ndr_abi_uint(state, 32));
}

void ndr_abi_fill_WERROR(struct ndr_abi_state *state, WERROR *v)
{
	*v = W_ERROR(ndr_abi_uint(state, 32));
}

void ndr_abi_fill_DATA_BLOB(struct ndr_abi_state *state, DATA_BLOB *v)
{
	uint8_t buf[4];

	PUSH_LE_U32(buf, 0, ndr_abi_uint(state, 32));
	*v = data_blob_talloc(state->mem_ctx, buf, sizeof(buf));
	if (v->data == NULL) {
		fprintf(stderr, "%s: out of memory\n", state->sample->name);
		abort();
	}
}

void ndr_abi_fill_string(struct ndr_abi_state *state, const char **v)
{
	*v = ndr_abi_string(state);
}

/*
 * string_array is a NULL terminated array of strings
 */
void ndr_abi_fill_string_array(struct ndr_abi_state *state, const char ***v)
{
	size_t count = state->min_counts ? 0 : 2;
	const char **a = NULL;
	size_t i;

	a = ndr_abi_talloc_zero(state, sizeof(a[0]) * (count + 1));
	for (i = 0; i < count; i++) {
		a[i] = ndr_abi_string(state);
	}

	*v = a;
}

/*
 * ipv4address and ipv6address are strings,
 * but only valid addresses can be pushed.
 */
void ndr_abi_fill_ipv4address(struct ndr_abi_state *state, const char **v)
{
	uint32_t a = ndr_abi_uint(state, 32);

	*v = talloc_asprintf(state->mem_ctx,
			     "%u.%u.%u.%u",
			     (unsigned)((a >> 24) & 0xff),
			     (unsigned)((a >> 16) & 0xff),
			     (unsigned)((a >> 8) & 0xff),
			     (unsigned)(a & 0xff));
	if (*v == NULL) {
		fprintf(stderr, "%s: out of memory\n", state->sample->name);
		abort();
	}
}

void ndr_abi_fill_ipv6address(struct ndr_abi_state *state, const char **v)
{
	uint16_t a[8];
	size_t i;

	for (i = 0; i < ARRAY_SIZE(a); i++) {
		a[i] = ndr_abi_uint(state, 16);
	}

	*v = talloc_asprintf(state->mem_ctx,
			     "%x:%x:%x:%x:%x:%x:%x:%x",
			     a[0], a[1], a[2], a[3],
			     a[4], a[5], a[6], a[7]);
	if (*v == NULL) {
		fprintf(stderr, "%s: out of memory\n", state->sample->name);
		abort();
	}
}

void ndr_abi_fill_timeval(struct ndr_abi_state *state, struct timeval *v)
{
	v->tv_sec = ndr_abi_uint(state, 32) & INT32_MAX;
	v->tv_usec = ndr_abi_range(state, 0, 999999);
}

void ndr_abi_fill_timeval_legacy(struct ndr_abi_state *state,
				 struct timeval *v)
{
	ndr_abi_fill_timeval(state, v);
}

void ndr_abi_fill_timespec(struct ndr_abi_state *state, struct timespec *v)
{
	v->tv_sec = ndr_abi_uint(state, 32) & INT32_MAX;
	v->tv_nsec = ndr_abi_range(state, 0, 999999999);
}

void ndr_abi_fill_timespec_legacy(struct ndr_abi_state *state,
				  struct timespec *v)
{
	ndr_abi_fill_timespec(state, v);
}

void ndr_abi_fill_dom_sid(struct ndr_abi_state *state, struct dom_sid *v)
{
	int8_t i;

	*v = (struct dom_sid) {
		.sid_rev_num = 1,
		.num_auths = state->min_counts ? 0 : 4,
		.id_auth = { 0, 0, 0, 0, 0, 5 },
	};

	for (i = 0; i < v->num_auths; i++) {
		v->sub_auths[i] = ndr_abi_uint(state, 32);
	}
}

/*
 * dom_sid2, dom_sid28, dom_sid68 and dom_sid0 are all struct dom_sid,
 * but with different (hand-written) wire formats,
 * dom_sid28 only allows up to 5 sub_auths.
 */
void ndr_abi_fill_dom_sid2(struct ndr_abi_state *state, struct dom_sid *v)
{
	ndr_abi_fill_dom_sid(state, v);
}

void ndr_abi_fill_dom_sid28(struct ndr_abi_state *state, struct dom_sid *v)
{
	ndr_abi_fill_dom_sid(state, v);
}

void ndr_abi_fill_dom_sid68(struct ndr_abi_state *state, struct dom_sid *v)
{
	ndr_abi_fill_dom_sid(state, v);
}

void ndr_abi_fill_dom_sid0(struct ndr_abi_state *state, struct dom_sid *v)
{
	ndr_abi_fill_dom_sid(state, v);
}

static void ndr_abi_fill_guid(struct ndr_abi_state *state, struct GUID *v)
{
	size_t i;

	v->time_low = ndr_abi_uint(state, 32);
	v->time_mid = ndr_abi_uint(state, 16);
	v->time_hi_and_version = ndr_abi_uint(state, 16);
	for (i = 0; i < ARRAY_SIZE(v->clock_seq); i++) {
		v->clock_seq[i] = ndr_abi_uint(state, 8);
	}
	for (i = 0; i < ARRAY_SIZE(v->node); i++) {
		v->node[i] = ndr_abi_uint(state, 8);
	}
}

/*
 * security_ace is hand-written, we cycle through
 * a simple, an object and a callback ACE in order
 * to cover the different code paths.
 */
void ndr_abi_fill_security_ace(struct ndr_abi_state *state,
			       struct security_ace *v)
{
	static const enum security_ace_type types[] = {
		SEC_ACE_TYPE_ACCESS_ALLOWED,
		SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT,
		SEC_ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
	};
	uint64_t n = ndr_abi_uint(state, 8);

	*v = (struct security_ace) {
		.type = types[n % ARRAY_SIZE(types)],
	};

	v->flags = ndr_abi_uint(state, 8);
	v->access_mask = ndr_abi_uint(state, 32);

	switch (v->type) {
	case SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT: {
		struct security_ace_object *o = &v->object.object;

		o->flags = SEC_ACE_OBJECT_TYPE_PRESENT |
			   SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT;
		ndr_abi_fill_guid(state, &o->type.type);
		ndr_abi_fill_guid(state, &o->inherited_type.inherited_type);
		break;
	}
	default:
		break;
	}

	ndr_abi_fill_dom_sid(state, &v->trustee);

	switch (v->type) {
	case SEC_ACE_TYPE_ACCESS_ALLOWED_CALLBACK:
		ndr_abi_fill_DATA_BLOB(state, &v->coda.conditions);
		break;
	default:
		break;
	}
}

/*
 * file_id_hyper is a struct file_id with a hand-written
 * wire format, see librpc/ndr/ndr_file_id.c
 */
void ndr_abi_fill_file_id_hyper(struct ndr_abi_state *state, struct file_id *v)
{
	ndr_abi_fill_hyper(state, &v->devid);
	ndr_abi_fill_hyper(state, &v->inode);
	ndr_abi_fill_hyper(state, &v->extid);
}

/*
 * file_id_devino is a struct file_id with only
 * devid and inode on the wire.
 */
void ndr_abi_fill_file_id_devino(struct ndr_abi_state *state,
				 struct file_id *v)
{
	ndr_abi_fill_udlong(state, &v->devid);
	ndr_abi_fill_udlong(state, &v->inode);
	v->extid = 0;
}

/*
 * witness_notifyResponse is hand-written, we cycle through
 * a resource change and a client move message in order
 * to cover the different code paths.
 */
void ndr_abi_fill_witness_notifyResponse(struct ndr_abi_state *state,
					 struct witness_notifyResponse *v)
{
	static const enum witness_notifyResponse_type types[] = {
		WITNESS_NOTIFY_RESOURCE_CHANGE,
		WITNESS_NOTIFY_CLIENT_MOVE,
	};
	uint64_t n = ndr_abi_uint(state, 8);
	uint32_t i;

	*v = (struct witness_notifyResponse) {
		.type = types[n % ARRAY_SIZE(types)],
		.num = state->min_counts ? 0 : 1,
	};

	v->messages = ndr_abi_talloc_zero_array(state,
						sizeof(v->messages[0]),
						v->num);

	for (i = 0; i < v->num; i++) {
		union witness_notifyResponse_message *m = &v->messages[i];

		switch (v->type) {
		case WITNESS_NOTIFY_RESOURCE_CHANGE:
			m->resource_change.type =
				WITNESS_RESOURCE_STATE_AVAILABLE;
			ndr_abi_fill_string(state, &m->resource_change.name);
			break;
		default: {
			struct witness_IPaddrInfoList *l = &m->client_move;

			l->num = 1;
			l->addr = ndr_abi_talloc_zero_array(state,
							    sizeof(l->addr[0]),
							    l->num);
			l->addr[0].flags = WITNESS_IPADDR_V4 |
					   WITNESS_IPADDR_V6 |
					   WITNESS_IPADDR_ONLINE;
			ndr_abi_fill_ipv4address(state, &l->addr[0].ipv4);
			ndr_abi_fill_ipv6address(state, &l->addr[0].ipv6);
			break;
		}
		}
	}
}

static void ndr_abi_print_hex(const DATA_BLOB *blob)
{
	size_t ofs;

	for (ofs = 0; ofs < blob->length; ofs += 16) {
		size_t i;

		printf("\t[%04zx]", ofs);
		for (i = ofs; i < MIN(ofs + 16, blob->length); i++) {
			if (i == ofs + 8) {
				printf(" ");
			}
			printf(" %02x", blob->data[i]);
		}
		printf("\n");
	}
}

static void ndr_abi_print_comment(const char *txt)
{
	const char *p = txt;

	while (*p != '\0') {
		const char *e = strchr(p, '\n');
		size_t len;

		if (e == NULL) {
			len = strlen(p);
		} else {
			len = e - p;
		}
		printf("#\t%.*s\n", (int)len, p);
		p += len;
		if (*p == '\n') {
			p++;
		}
	}
}

/*
 * Returns false only for internal errors,
 * problems of the NDR code are reported via
 * *_status, as they are part of the ABI.
 */
static bool ndr_abi_sample(TALLOC_CTX *mem_ctx,
			   const struct ndr_abi_sample *sample,
			   DATA_BLOB *_blob,
			   const char **_status,
			   char **_print)
{
	struct ndr_abi_state state = {
		.mem_ctx = mem_ctx,
		.sample = sample,
		.null_pointers = sample->null_pointers,
		.min_counts = sample->min_counts,
		.selections = sample->selections,
	};
	enum ndr_err_code ndr_err;
	DATA_BLOB blob = { .length = 0, };
	DATA_BLOB blob2 = { .length = 0, };
	const char *status = NULL;
	void *r = NULL;
	void *r2 = NULL;

	r = sample->fill(&state);
	if (state.failed) {
		return false;
	}

	ndr_err = ndr_push_struct_blob(&blob, mem_ctx, r, sample->push);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		fprintf(stderr, "%s: ndr_push_%s() failed: %s\n",
			sample->name, sample->type_name,
			ndr_map_error2string(ndr_err));
		return false;
	}

	r2 = talloc_zero_size(mem_ctx, sample->struct_size);
	if (r2 == NULL) {
		fprintf(stderr, "%s: out of memory\n", sample->name);
		return false;
	}

	ndr_err = ndr_pull_struct_blob_all(&blob, r2, r2, sample->pull);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = talloc_asprintf(mem_ctx,
					 "pull_error(%s)",
					 ndr_map_error2string(ndr_err));
		goto done;
	}

	ndr_err = ndr_push_struct_blob(&blob2, mem_ctx, r2, sample->push);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = talloc_asprintf(mem_ctx,
					 "repush_error(%s)",
					 ndr_map_error2string(ndr_err));
		goto done;
	}

	if (!data_blob_equal_const_time(&blob, &blob2)) {
		status = "repush_mismatch";
		goto done;
	}

	/*
	 * We print what we got from the wire,
	 * as it also includes [value()] elements.
	 */
	r = r2;
	status = "";
done:
	if (status == NULL) {
		fprintf(stderr, "%s: out of memory\n", sample->name);
		return false;
	}
	if (status[0] != '\0') {
		fprintf(stderr,
			"WARNING: %s: %s, this is recorded in the ABI file\n",
			sample->name, status);
	}

	*_print = ndr_print_struct_string(mem_ctx,
					  sample->print,
					  sample->type_name,
					  r);
	if (*_print == NULL) {
		fprintf(stderr, "%s: out of memory\n", sample->name);
		return false;
	}

	*_blob = blob;
	*_status = status;
	return true;
}

static bool ndr_abi_blob_seen(const DATA_BLOB *blobs, const DATA_BLOB *blob)
{
	size_t i;

	for (i = 0; i < talloc_array_length(blobs); i++) {
		if (data_blob_equal_const_time(&blobs[i], blob)) {
			return true;
		}
	}

	return false;
}

int ndr_abi_main(const struct ndr_abi_table *table,
		 int argc,
		 const char *argv[])
{
	TALLOC_CTX *frame = talloc_new(NULL);
	const char *last_type = NULL;
	DATA_BLOB *type_blobs = NULL;
	bool ok = true;
	size_t i;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		fprintf(stderr, "Prints the NDR wire format ABI of %s.idl\n",
			table->idl_name);
		TALLOC_FREE(frame);
		return 1;
	}

	/*
	 * The comments contain the NDR print output,
	 * which uses the local timezone for time values,
	 * use UTC in order to get the same output everywhere.
	 */
	setenv("TZ", "UTC", 1);
	tzset();

	printf("# NDR wire format ABI of %s.idl\n", table->idl_name);
	printf("#\n");
	printf("# This is the output of ndr_abi_%s (generated by\n",
	       table->idl_name);
	printf("# 'pidl --ndr-abi'), see librpc/ndr/ndr_abi.h.\n");
	printf("#\n");
	printf("# Lines starting with '#' and everything after '\\t#'\n");
	printf("# are comments, they are not compared.\n");
	printf("\n");
	printf("%s", table->types);

	for (i = 0; i < table->num_samples; i++) {
		const struct ndr_abi_sample *sample = &table->samples[i];
		DATA_BLOB blob = { .length = 0, };
		const char *status = NULL;
		char *print = NULL;

		if (!ndr_abi_sample(frame, sample, &blob, &status, &print)) {
			ok = false;
			continue;
		}

		if (last_type == NULL ||
		    strcmp(last_type, sample->type_name) != 0)
		{
			TALLOC_FREE(type_blobs);
			last_type = sample->type_name;
		}

		if (ndr_abi_blob_seen(type_blobs, &blob)) {
			/*
			 * The sample is not different from
			 * a previous sample of the same
			 * structure, so we skip it.
			 */
			continue;
		}

		type_blobs = talloc_realloc(frame,
					    type_blobs,
					    DATA_BLOB,
					    talloc_array_length(type_blobs) + 1);
		if (type_blobs == NULL) {
			fprintf(stderr, "%s: out of memory\n", sample->name);
			abort();
		}
		type_blobs[talloc_array_length(type_blobs) - 1] = blob;

		printf("sample %s length(%zu)%s%s {\n",
		       sample->name,
		       blob.length,
		       status[0] != '\0' ? " " : "",
		       status);
		ndr_abi_print_hex(&blob);
		printf("}\n");
		ndr_abi_print_comment(print);
		printf("\n");
	}

	TALLOC_FREE(frame);
	if (!ok) {
		return 1;
	}
	return 0;
}

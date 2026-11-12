/*
   ctdb_ltdb and ctdb_marshall tests

   Verify that the code copying struct ctdb_ltdb_header and
   struct ctdb_rec_data_old with memcpy() creates the same
   bytes as the protocol library.

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
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"

#include <assert.h>
#include <talloc.h>
#include <tdb.h>

#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/debug.h"

#include "ctdb_private.h"

#include "common/common.h"

#include "protocol/protocol_api.h"

/*
 * ctdbd and its clients copy these structures with memcpy()
 * into the local databases and onto the wire.
 *
 * The size of struct ctdb_ltdb_header depends on the alignment
 * of uint64_t: 24 bytes on most platforms, 20 bytes on i386.
 * ctdb_ltdb_header_push() adds the same padding after the 20
 * bytes of fields.
 */
BUILD_ASSERT(offsetof(struct ctdb_ltdb_header, rsn) == 0);
BUILD_ASSERT(offsetof(struct ctdb_ltdb_header, dmaster) == 8);
BUILD_ASSERT(offsetof(struct ctdb_ltdb_header, reserved1) == 12);
BUILD_ASSERT(offsetof(struct ctdb_ltdb_header, flags) == 16);
BUILD_ASSERT(sizeof(struct ctdb_ltdb_header) == 20 ||
	     sizeof(struct ctdb_ltdb_header) == 24);

BUILD_ASSERT(offsetof(struct ctdb_rec_data_old, length) == 0);
BUILD_ASSERT(offsetof(struct ctdb_rec_data_old, reqid) == 4);
BUILD_ASSERT(offsetof(struct ctdb_rec_data_old, keylen) == 8);
BUILD_ASSERT(offsetof(struct ctdb_rec_data_old, datalen) == 12);
BUILD_ASSERT(offsetof(struct ctdb_rec_data_old, data) == 16);

BUILD_ASSERT(offsetof(struct ctdb_marshall_buffer, db_id) == 0);
BUILD_ASSERT(offsetof(struct ctdb_marshall_buffer, count) == 4);
BUILD_ASSERT(offsetof(struct ctdb_marshall_buffer, data) == 8);

static const uint8_t fills[] = { 0xa5, 0x5a };

struct ltdb_sample {
	uint32_t reqid;
	const char *key;
	size_t keylen;
	uint64_t rsn;
	uint32_t dmaster;
	uint32_t reserved1;
	uint32_t flags;
	const char *data;
	size_t datalen;
};

#define SAMPLE_STR(s) s, sizeof(s) - 1

/*
 * The odd key and data lengths make sure the following records
 * are not aligned.
 */
static const struct ltdb_sample ltdb_samples[] = {
	{
		.reqid = 0,
		SAMPLE_STR("abc"),
		.rsn = 0x0102030405060708,
		.dmaster = 0x11121314,
		.reserved1 = 0x21222324,
		.flags = CTDB_REC_FLAG_PERSISTENT |
			 CTDB_REC_FLAG_MIGRATED_WITH_DATA,
		SAMPLE_STR("hello"),
	},
	{
		.reqid = 0x31323334,
		SAMPLE_STR("k"),
		.rsn = 1,
		.dmaster = 2,
		.reserved1 = 0,
		.flags = 0,
		.data = "",
		.datalen = 0,
	},
	{
		.reqid = 7,
		.key = "",
		.keylen = 0,
		.rsn = UINT64_MAX,
		.dmaster = UINT32_MAX,
		.reserved1 = UINT32_MAX,
		.flags = UINT32_MAX,
		SAMPLE_STR("x"),
	},
};

static void sample_header(const struct ltdb_sample *s,
			  struct ctdb_ltdb_header *h)
{
	/*
	 * The memcpy() based code copies the padding as is,
	 * so it needs to be initialized.
	 */
	ZERO_STRUCTP(h);
	h->rsn = s->rsn;
	h->dmaster = s->dmaster;
	h->reserved1 = s->reserved1;
	h->flags = s->flags;
}

static TDB_DATA sample_key(const struct ltdb_sample *s)
{
	return (TDB_DATA) {
		.dptr = discard_const_p(uint8_t, s->key),
		.dsize = s->keylen,
	};
}

static TDB_DATA sample_data(const struct ltdb_sample *s)
{
	return (TDB_DATA) {
		.dptr = discard_const_p(uint8_t, s->data),
		.dsize = s->datalen,
	};
}

static void assert_header_equal(const struct ctdb_ltdb_header *h1,
				const struct ctdb_ltdb_header *h2)
{
	assert(h1->rsn == h2->rsn);
	assert(h1->dmaster == h2->dmaster);
	assert(h1->reserved1 == h2->reserved1);
	assert(h1->flags == h2->flags);
}

static void assert_tdb_data_equal(TDB_DATA d1, TDB_DATA d2)
{
	assert(d1.dsize == d2.dsize);
	if (d1.dsize != 0) {
		assert(memcmp(d1.dptr, d2.dptr, d1.dsize) == 0);
	}
}

/*
 * The expected ltdb record: the header pushed by the
 * protocol library followed by the data.
 */
static TDB_DATA ltdb_record(TALLOC_CTX *mem_ctx,
			    struct ctdb_ltdb_header *h,
			    TDB_DATA data)
{
	TDB_DATA rec;
	size_t hlen, np = 0;

	hlen = ctdb_ltdb_header_len(h);
	rec.dsize = hlen + data.dsize;
	rec.dptr = talloc_size(mem_ctx, rec.dsize);
	assert(rec.dptr != NULL);

	ctdb_ltdb_header_push(h, rec.dptr, &np);
	assert(np == hlen);
	if (data.dsize != 0) {
		memcpy(rec.dptr + hlen, data.dptr, data.dsize);
	}

	return rec;
}

/*
 * Let the next allocation of up to 'size' bytes in 'pool' get
 * memory filled with 'fill', returns the expected pointer.
 */
static void *pool_prefill(TALLOC_CTX *pool, size_t size, uint8_t fill)
{
	void *p = talloc_size(pool, size);

	assert(p != NULL);
	memset(p, fill, size);
	talloc_free(p);

	return p;
}

static struct ctdb_db_context *test_db(TALLOC_CTX *mem_ctx,
				       uint32_t pnn)
{
	static unsigned int num;
	struct ctdb_context *ctdb = NULL;
	struct ctdb_db_context *ctdb_db = NULL;

	ctdb = talloc_zero(mem_ctx, struct ctdb_context);
	assert(ctdb != NULL);

	ctdb->pnn = pnn;
	ctdb->vnn_map = talloc_zero(ctdb, struct ctdb_vnn_map);
	assert(ctdb->vnn_map != NULL);
	ctdb->vnn_map->size = 1;
	ctdb->vnn_map->map = talloc_zero_array(ctdb->vnn_map, uint32_t, 1);
	assert(ctdb->vnn_map->map != NULL);
	ctdb->vnn_map->map[0] = pnn;

	ctdb_db = talloc_zero(ctdb, struct ctdb_db_context);
	assert(ctdb_db != NULL);

	ctdb_db->ctdb = ctdb;
	/*
	 * tdb_wrap_open() would return an already open tdb
	 * with the same name.
	 */
	ctdb_db->db_name = talloc_asprintf(ctdb_db,
					   "ctdb_ltdb_test_%u.tdb",
					   num++);
	assert(ctdb_db->db_name != NULL);
	ctdb_db->ltdb = tdb_wrap_open(ctdb_db,
				      ctdb_db->db_name,
				      0,
				      TDB_INTERNAL,
				      O_RDWR|O_CREAT,
				      0600);
	assert(ctdb_db->ltdb != NULL);

	return ctdb_db;
}

static void test_ltdb_header_len(void)
{
	struct ctdb_ltdb_header h;
	uint8_t buf[sizeof(h)];
	size_t np = 0;

	sample_header(&ltdb_samples[0], &h);

	assert(ctdb_ltdb_header_len(&h) == sizeof(h));

	ctdb_ltdb_header_push(&h, buf, &np);
	assert(np == sizeof(h));
	assert(memcmp(buf, &h, sizeof(h)) == 0);
}

/*
 * ctdb_ltdb_store() writes the same record as
 * ctdb_ltdb_header_push() and ctdb_ltdb_fetch() reads it.
 */
static void test_ltdb_store_fetch(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct ctdb_db_context *ctdb_db = NULL;
	size_t i, f;
	int ret;

	assert(mem_ctx != NULL);

	ctdb_db = test_db(mem_ctx, 0);

	for (i = 0; i < ARRAY_SIZE(ltdb_samples); i++) {
		const struct ltdb_sample *s = &ltdb_samples[i];
		struct ctdb_ltdb_header h;
		TDB_DATA expected, rec;

		sample_header(s, &h);
		expected = ltdb_record(mem_ctx, &h, sample_data(s));

		ret = ctdb_ltdb_store(ctdb_db, sample_key(s), &h,
				      sample_data(s));
		assert(ret == 0);

		rec = tdb_fetch(ctdb_db->ltdb->tdb, sample_key(s));
		assert(rec.dptr != NULL);
		assert_tdb_data_equal(rec, expected);
		free(rec.dptr);

		for (f = 0; f < ARRAY_SIZE(fills); f++) {
			struct ctdb_ltdb_header fh;
			TDB_DATA data = tdb_null;

			memset(&fh, fills[f], sizeof(fh));

			ret = ctdb_ltdb_fetch(ctdb_db, sample_key(s), &fh,
					      mem_ctx, &data);
			assert(ret == 0);
			assert(memcmp(&fh, expected.dptr, sizeof(fh)) == 0);
			assert_header_equal(&fh, &h);
			assert_tdb_data_equal(data, sample_data(s));
		}
	}

	talloc_free(mem_ctx);
}

/*
 * ctdb_ltdb_fetch() of a missing record stores an initial
 * header, which must not contain the old content of the
 * caller's header.
 */
static void test_ltdb_fetch_initial(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	size_t f;
	int ret;

	assert(mem_ctx != NULL);

	for (f = 0; f < ARRAY_SIZE(fills); f++) {
		struct ctdb_db_context *ctdb_db = test_db(mem_ctx, 3);
		const struct ltdb_sample *s = &ltdb_samples[0];
		struct ctdb_ltdb_header fh, eh;
		TDB_DATA data = tdb_null;
		TDB_DATA expected, rec;

		memset(&fh, fills[f], sizeof(fh));

		ret = ctdb_ltdb_fetch(ctdb_db, sample_key(s), &fh,
				      mem_ctx, &data);
		assert(ret == 0);
		assert(data.dsize == 0);

		ZERO_STRUCT(eh);
		eh.dmaster = 3;
		eh.flags = CTDB_REC_FLAG_AUTOMATIC;
		expected = ltdb_record(mem_ctx, &eh, tdb_null);

		assert(memcmp(&fh, expected.dptr, sizeof(fh)) == 0);

		rec = tdb_fetch(ctdb_db->ltdb->tdb, sample_key(s));
		assert(rec.dptr != NULL);
		assert_tdb_data_equal(rec, expected);
		free(rec.dptr);
	}

	talloc_free(mem_ctx);
}

/*
 * ctdb_fetch_with_header_func() returns the same bytes as an
 * ltdb record created with ctdb_ltdb_header_push().
 */
static void test_fetch_with_header_func(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	size_t i, f;
	int ret;

	assert(mem_ctx != NULL);

	for (i = 0; i < ARRAY_SIZE(ltdb_samples); i++) {
		const struct ltdb_sample *s = &ltdb_samples[i];
		struct ctdb_ltdb_header h;
		TDB_DATA expected;

		sample_header(s, &h);
		expected = ltdb_record(mem_ctx, &h, sample_data(s));

		for (f = 0; f < ARRAY_SIZE(fills); f++) {
			struct ctdb_call_info *call = NULL;
			TALLOC_CTX *pool = NULL;
			void *p = NULL;

			pool = talloc_pool(mem_ctx, 1024);
			assert(pool != NULL);

			call = talloc_zero(pool, struct ctdb_call_info);
			assert(call != NULL);
			call->key = sample_key(s);
			call->header = &h;
			call->record_data = sample_data(s);

			/*
			 * The reply_data TDB_DATA is allocated first,
			 * fill the memory behind it.
			 */
			p = pool_prefill(pool,
					 sizeof(TDB_DATA) + 256 +
					 expected.dsize,
					 fills[f]);
			assert(p != NULL);

			ret = ctdb_fetch_with_header_func(call);
			assert(ret == 0);
			assert(call->reply_data != NULL);
			assert_tdb_data_equal(*call->reply_data, expected);

			talloc_free(pool);
		}
	}

	talloc_free(mem_ctx);
}

/*
 * ctdb_marshall_record() and ctdb_marshall_add() create the
 * same records as the protocol library, without leaving any
 * byte uninitialized.
 */
static void test_marshall_record(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	size_t i, f;

	assert(mem_ctx != NULL);

	for (i = 0; i < ARRAY_SIZE(ltdb_samples); i++) {
		const struct ltdb_sample *s = &ltdb_samples[i];
		struct ctdb_ltdb_header h;
		struct ctdb_rec_data rd;
		uint8_t *expected = NULL;
		size_t len, np = 0;

		sample_header(s, &h);

		rd = (struct ctdb_rec_data) {
			.reqid = s->reqid,
			.header = &h,
			.key = sample_key(s),
			.data = sample_data(s),
		};
		len = ctdb_rec_data_len(&rd);
		expected = talloc_size(mem_ctx, len);
		assert(expected != NULL);
		ctdb_rec_data_push(&rd, expected, &np);
		assert(np == len);

		for (f = 0; f < ARRAY_SIZE(fills); f++) {
			TALLOC_CTX *pool = NULL;
			struct ctdb_rec_data_old *r = NULL;
			void *p = NULL;

			pool = talloc_pool(mem_ctx, 1024);
			assert(pool != NULL);

			p = pool_prefill(pool, len, fills[f]);

			r = ctdb_marshall_record(pool,
						 s->reqid,
						 sample_key(s),
						 &h,
						 sample_data(s));
			assert(r != NULL);
			assert(r == p);
			assert(talloc_get_size(r) == len);
			assert(memcmp(r, expected, len) == 0);

			talloc_free(pool);
		}
	}

	talloc_free(mem_ctx);
}

static TDB_DATA marshall_samples_protocol(TALLOC_CTX *mem_ctx,
					   uint32_t db_id)
{
	struct ctdb_rec_buffer *recbuf = NULL;
	TDB_DATA blob;
	size_t i, np = 0;
	int ret;

	recbuf = ctdb_rec_buffer_init(mem_ctx, db_id);
	assert(recbuf != NULL);

	for (i = 0; i < ARRAY_SIZE(ltdb_samples); i++) {
		const struct ltdb_sample *s = &ltdb_samples[i];
		struct ctdb_ltdb_header h;

		sample_header(s, &h);

		ret = ctdb_rec_buffer_add(recbuf,
					  recbuf,
					  s->reqid,
					  &h,
					  sample_key(s),
					  sample_data(s));
		assert(ret == 0);
	}

	blob.dsize = ctdb_rec_buffer_len(recbuf);
	blob.dptr = talloc_size(mem_ctx, blob.dsize);
	assert(blob.dptr != NULL);
	ctdb_rec_buffer_push(recbuf, blob.dptr, &np);
	assert(np == blob.dsize);

	talloc_free(recbuf);
	return blob;
}

static void test_marshall_buffer(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	const uint32_t db_id = 0x51525354;
	struct ctdb_marshall_buffer *m = NULL;
	struct ctdb_rec_data_old *r = NULL;
	TDB_DATA expected;
	TDB_DATA data;
	size_t i;

	assert(mem_ctx != NULL);

	expected = marshall_samples_protocol(mem_ctx, db_id);

	for (i = 0; i < ARRAY_SIZE(ltdb_samples); i++) {
		const struct ltdb_sample *s = &ltdb_samples[i];
		struct ctdb_ltdb_header h;

		sample_header(s, &h);

		m = ctdb_marshall_add(mem_ctx,
				      m,
				      db_id,
				      s->reqid,
				      sample_key(s),
				      &h,
				      sample_data(s));
		assert(m != NULL);
	}

	data = ctdb_marshall_finish(m);
	assert(data.dsize == expected.dsize);
	assert(memcmp(data.dptr, expected.dptr, expected.dsize) == 0);

	/*
	 * ctdb_marshall_loop_next() parses the buffer created
	 * by ctdb_rec_buffer_push().
	 */
	m = (struct ctdb_marshall_buffer *)expected.dptr;
	assert(m->db_id == db_id);
	assert(m->count == ARRAY_SIZE(ltdb_samples));

	for (i = 0; i < m->count; i++) {
		const struct ltdb_sample *s = &ltdb_samples[i];
		struct ctdb_ltdb_header h, eh;
		uint32_t reqid = 0;
		TDB_DATA key;

		r = ctdb_marshall_loop_next(m, r, &reqid, &h, &key, &data);
		assert(r != NULL);
		assert(reqid == s->reqid);
		sample_header(s, &eh);
		assert(memcmp(&h, &eh, sizeof(h)) == 0);
		assert_tdb_data_equal(key, sample_key(s));
		assert_tdb_data_equal(data, sample_data(s));
	}
	assert((uint8_t *)r + r->length == expected.dptr + expected.dsize);

	talloc_free(mem_ctx);
}

int main(int argc, const char **argv)
{
	test_ltdb_header_len();
	test_ltdb_store_fetch();
	test_ltdb_fetch_initial();
	test_fetch_with_header_func();
	test_marshall_record();
	test_marshall_buffer();

	return 0;
}

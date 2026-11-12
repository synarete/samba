/*
 * Unix SMB/CIFS implementation.
 *
 * Verify that the hand-marshalled records of dbwrap_ctdb.c
 * match the ctdb protocol library.
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

#include "dbwrap_ctdb.c"
#include <cmocka.h>

/*
 * dbwrap_ctdb.c copies these structures with memcpy() into records
 * sent to ctdbd (e.g. CTDB_CONTROL_TRANS3_COMMIT) and into the local
 * tdb copies of the databases, which are read by ctdbd.
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

struct marshall_sample {
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
 * are not aligned. The 3rd record overwrites the 1st one, as
 * db_ctdb_transaction_store() does for a key stored twice in
 * a transaction.
 */
static const struct marshall_sample marshall_samples[] = {
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
		.reqid = 0,
		SAMPLE_STR("abc"),
		.rsn = 0x0102030405060709,
		.dmaster = 0x41424344,
		.reserved1 = 0,
		.flags = CTDB_REC_FLAG_AUTOMATIC,
		SAMPLE_STR("world!"),
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

static void sample_header(const struct marshall_sample *s,
			  struct ctdb_ltdb_header *h)
{
	/*
	 * dbwrap_ctdb.c copies the padding as is, all callers
	 * use ZERO_STRUCT() or a header from an existing record.
	 */
	ZERO_STRUCTP(h);
	h->rsn = s->rsn;
	h->dmaster = s->dmaster;
	h->reserved1 = s->reserved1;
	h->flags = s->flags;
}

static TDB_DATA sample_key(const struct marshall_sample *s)
{
	return make_tdb_data((const uint8_t *)s->key, s->keylen);
}

static TDB_DATA sample_data(const struct marshall_sample *s)
{
	return make_tdb_data((const uint8_t *)s->data, s->datalen);
}

static void assert_header_equal(const struct ctdb_ltdb_header *h1,
				const struct ctdb_ltdb_header *h2)
{
	assert_int_equal(h1->rsn, h2->rsn);
	assert_int_equal(h1->dmaster, h2->dmaster);
	assert_int_equal(h1->reserved1, h2->reserved1);
	assert_int_equal(h1->flags, h2->flags);
}

static void assert_tdb_data_equal(TDB_DATA d1, TDB_DATA d2)
{
	assert_int_equal(d1.dsize, d2.dsize);
	if (d1.dsize != 0) {
		assert_memory_equal(d1.dptr, d2.dptr, d1.dsize);
	}
}

static void test_ltdb_header_len(void **state)
{
	struct ctdb_ltdb_header h;
	uint8_t buf[sizeof(h)];
	size_t np = 0;

	sample_header(&marshall_samples[0], &h);

	assert_int_equal(ctdb_ltdb_header_len(&h), sizeof(h));

	ctdb_ltdb_header_push(&h, buf, &np);
	assert_int_equal(np, sizeof(h));
	assert_memory_equal(buf, &h, sizeof(h));
}

/*
 * db_ctdb_marshall_record() uses talloc_size(), check that it
 * doesn't leave any byte uninitialized by reusing memory of a
 * talloc pool filled with different patterns.
 */
static void test_marshall_record(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const uint8_t fills[] = { 0xa5, 0x5a };
	size_t i, f;

	for (i = 0; i < ARRAY_SIZE(marshall_samples); i++) {
		const struct marshall_sample *s = &marshall_samples[i];
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
		expected = talloc_size(frame, len);
		assert_non_null(expected);
		ctdb_rec_data_push(&rd, expected, &np);
		assert_int_equal(np, len);

		for (f = 0; f < ARRAY_SIZE(fills); f++) {
			TALLOC_CTX *pool = NULL;
			struct ctdb_rec_data_old *r = NULL;
			uint8_t *p = NULL;

			pool = talloc_pool(frame, 1024);
			assert_non_null(pool);
			p = talloc_size(pool, len);
			assert_non_null(p);
			memset(p, fills[f], len);
			talloc_free(p);

			r = db_ctdb_marshall_record(pool,
						    s->reqid,
						    sample_key(s),
						    &h,
						    sample_data(s));
			assert_non_null(r);
			assert_ptr_equal(r, p);
			assert_int_equal(talloc_get_size(r), len);
			assert_memory_equal(r, expected, len);

			TALLOC_FREE(pool);
		}
	}

	TALLOC_FREE(frame);
}

static DATA_BLOB marshall_samples_ctdb(TALLOC_CTX *mem_ctx, uint32_t db_id)
{
	struct ctdb_rec_buffer *recbuf = NULL;
	DATA_BLOB blob;
	size_t i, np = 0;
	int ret;

	recbuf = ctdb_rec_buffer_init(mem_ctx, db_id);
	assert_non_null(recbuf);

	for (i = 0; i < ARRAY_SIZE(marshall_samples); i++) {
		const struct marshall_sample *s = &marshall_samples[i];
		struct ctdb_ltdb_header h;

		sample_header(s, &h);

		ret = ctdb_rec_buffer_add(recbuf,
					  recbuf,
					  s->reqid,
					  &h,
					  sample_key(s),
					  sample_data(s));
		assert_int_equal(ret, 0);
	}

	blob = data_blob_talloc(mem_ctx, NULL, ctdb_rec_buffer_len(recbuf));
	assert_non_null(blob.data);
	ctdb_rec_buffer_push(recbuf, blob.data, &np);
	assert_int_equal(np, blob.length);

	TALLOC_FREE(recbuf);
	return blob;
}

static struct ctdb_marshall_buffer *marshall_samples_dbwrap(
	TALLOC_CTX *mem_ctx, uint32_t db_id)
{
	struct ctdb_marshall_buffer *m = NULL;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(marshall_samples); i++) {
		const struct marshall_sample *s = &marshall_samples[i];
		struct ctdb_ltdb_header h;

		sample_header(s, &h);

		m = db_ctdb_marshall_add(mem_ctx,
					 m,
					 db_id,
					 s->reqid,
					 sample_key(s),
					 &h,
					 sample_data(s));
		assert_non_null(m);
	}

	return m;
}

/*
 * db_ctdb_marshall_add() and db_ctdb_marshall_finish() create the
 * same buffer as ctdb_rec_buffer_push().
 */
static void test_marshall_buffer(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const uint32_t db_id = 0x51525354;
	struct ctdb_marshall_buffer *m = NULL;
	DATA_BLOB expected;
	TDB_DATA data;

	expected = marshall_samples_ctdb(frame, db_id);

	m = marshall_samples_dbwrap(frame, db_id);
	data = db_ctdb_marshall_finish(m);

	assert_int_equal(m->db_id, db_id);
	assert_int_equal(m->count, ARRAY_SIZE(marshall_samples));
	assert_int_equal(data.dsize, expected.length);
	assert_memory_equal(data.dptr, expected.data, expected.length);

	TALLOC_FREE(frame);
}

/*
 * The parsers of dbwrap_ctdb.c understand a buffer created by
 * ctdb_rec_buffer_push().
 */
static void test_marshall_parse_ctdb(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const uint32_t db_id = 0x51525354;
	struct ctdb_marshall_buffer *m = NULL;
	struct ctdb_rec_data_old *r = NULL;
	const struct marshall_sample *s = NULL;
	struct ctdb_ltdb_header h, eh;
	DATA_BLOB blob;
	TDB_DATA data;
	size_t i;
	bool ok;

	blob = marshall_samples_ctdb(frame, db_id);
	m = (struct ctdb_marshall_buffer *)blob.data;

	assert_int_equal(m->db_id, db_id);
	assert_int_equal(m->count, ARRAY_SIZE(marshall_samples));

	for (i = 0; i < m->count; i++) {
		struct ctdb_ltdb_header *ph = NULL;
		uint32_t reqid = 0;
		TDB_DATA key;

		s = &marshall_samples[i];

		r = db_ctdb_marshall_loop_next_key(m, r, &key);
		assert_non_null(r);
		assert_tdb_data_equal(key, sample_key(s));

		ok = db_ctdb_marshall_buf_parse(r, &reqid, &ph, &data);
		assert_true(ok);
		assert_int_equal(reqid, s->reqid);
		sample_header(s, &eh);
		assert_header_equal(ph, &eh);
		assert_tdb_data_equal(data, sample_data(s));
	}
	assert_ptr_equal((uint8_t *)r + r->length, blob.data + blob.length);

	/*
	 * The 3rd sample overwrites the 1st one
	 */
	s = &marshall_samples[2];
	ok = pull_newest_from_marshall_buffer(m, sample_key(s), &h,
					      frame, &data);
	assert_true(ok);
	sample_header(s, &eh);
	assert_header_equal(&h, &eh);
	assert_tdb_data_equal(data, sample_data(s));

	ok = pull_newest_from_marshall_buffer(m,
					      string_tdb_data("ab"),
					      &h, frame, &data);
	assert_false(ok);

	TALLOC_FREE(frame);
}

struct parse_dbwrap_state {
	size_t idx;
};

static int parse_dbwrap_fn(uint32_t reqid,
			   struct ctdb_ltdb_header *header,
			   TDB_DATA key,
			   TDB_DATA data,
			   void *private_data)
{
	struct parse_dbwrap_state *state = private_data;
	const struct marshall_sample *s = NULL;
	struct ctdb_ltdb_header h, eh;
	int ret;

	assert_in_range(state->idx, 0, ARRAY_SIZE(marshall_samples) - 1);
	s = &marshall_samples[state->idx++];

	assert_int_equal(reqid, s->reqid);

	/*
	 * ctdb_rec_buffer_traverse() passes the header as part of data
	 */
	assert_null(header);
	ret = ctdb_ltdb_header_extract(&data, &h);
	assert_int_equal(ret, 0);
	sample_header(s, &eh);
	assert_header_equal(&h, &eh);
	assert_tdb_data_equal(key, sample_key(s));
	assert_tdb_data_equal(data, sample_data(s));

	return 0;
}

/*
 * The ctdb protocol library understands a buffer created by
 * db_ctdb_marshall_add() and db_ctdb_marshall_finish().
 */
static void test_marshall_parse_dbwrap(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const uint32_t db_id = 0x51525354;
	struct ctdb_marshall_buffer *m = NULL;
	struct ctdb_rec_buffer *recbuf = NULL;
	struct parse_dbwrap_state pstate = { .idx = 0, };
	TDB_DATA data;
	size_t np = 0;
	int ret;

	m = marshall_samples_dbwrap(frame, db_id);
	data = db_ctdb_marshall_finish(m);

	ret = ctdb_rec_buffer_pull(data.dptr, data.dsize, frame,
				   &recbuf, &np);
	assert_int_equal(ret, 0);
	assert_int_equal(np, data.dsize);
	assert_int_equal(recbuf->db_id, db_id);
	assert_int_equal(recbuf->count, ARRAY_SIZE(marshall_samples));

	ret = ctdb_rec_buffer_traverse(recbuf, parse_dbwrap_fn, &pstate);
	assert_int_equal(ret, 0);
	assert_int_equal(pstate.idx, ARRAY_SIZE(marshall_samples));

	TALLOC_FREE(frame);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ltdb_header_len),
		cmocka_unit_test(test_marshall_record),
		cmocka_unit_test(test_marshall_buffer),
		cmocka_unit_test(test_marshall_parse_ctdb),
		cmocka_unit_test(test_marshall_parse_dbwrap),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}

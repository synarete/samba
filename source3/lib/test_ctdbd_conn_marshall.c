/*
 * Unix SMB/CIFS implementation.
 *
 * Verify that the hand-marshalled packets of ctdbd_conn.c
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

#include "ctdbd_conn.c"
#include "ctdb/protocol/protocol_api.h"
#include "ctdb_srvids.h"
#include <setjmp.h>
#include <cmocka.h>

/*
 * The srvids used by Samba processes to talk to each other via
 * ctdb, also between different versions on different nodes:
 *
 * - messaging_send_iov_from() sends messages for other nodes to
 *   the srvid dst.pid, messaging_ctdb_init() registers the pid.
 *
 * - messaging_ctdb_init() registers the unique_id of the process
 *   as srvid, ctdbd_process_exists() checks it with
 *   CTDB_CONTROL_CHECK_PID_SRVID.
 *
 * - the srvids below.
 *
 * CTDB_SRVID_SAMBA_NOTIFY and the srvid ranges are part of
 * ctdb/protocol/ABI/ctdb_protocol.ndrabi.
 */
BUILD_ASSERT(CTDB_SRVID_SAMBA_NOTIFY == 0xFE00000000000000LL);
BUILD_ASSERT(CTDB_SRVID_SAMBA_NOTIFY_PROXY == 0xFE00000000000001LL);
BUILD_ASSERT(CTDB_SRVID_SAMBA_PROCESS == 0xFE00000000000002LL);

/*
 * Most of the controls go to the local ctdbd, which comes from the
 * same build. But the payload of some controls and messages is
 * passed to (or comes from) ctdbd and smbd on other nodes unchanged,
 * which may run a different version:
 *
 * - CTDB_CONTROL_PROCESS_EXISTS and CTDB_CONTROL_CHECK_PID_SRVID
 *   are sent to the ctdbd of the node of a server_id, see
 *   ctdbd_process_exists().
 *
 * - The reply to CTDB_CONTROL_GET_PUBLIC_IPS comes from the ctdbd
 *   of each node, see ctdbd_control_get_public_ips().
 *
 * - CTDB_REQ_MESSAGE packets are delivered to smbd processes on
 *   other nodes, see ctdbd_messaging_send_iov().
 *
 * The tests use a socketpair as the connection to ctdbd. A reply is
 * written before calling the function, as the reqid is predictable,
 * the request is read and parsed with the ctdb protocol library
 * afterwards.
 */

struct test_conn {
	struct ctdbd_connection *conn;
	int ctdbd_fd;
};

static struct test_conn test_conn_setup(TALLOC_CTX *mem_ctx)
{
	struct test_conn tc = { .ctdbd_fd = -1, };
	int fds[2];
	int ret;

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	assert_int_equal(ret, 0);

	tc.conn = talloc_zero(mem_ctx, struct ctdbd_connection);
	assert_non_null(tc.conn);

	tc.conn->reqid = 0x1000;
	tc.conn->our_vnn = 3;
	tc.conn->fd = fds[0];
	tc.conn->timeout = -1;
	tc.ctdbd_fd = fds[1];

	return tc;
}

static void test_conn_teardown(struct test_conn *tc)
{
	close(tc->conn->fd);
	close(tc->ctdbd_fd);
	TALLOC_FREE(tc->conn);
}

static void test_write_reply_reqid(struct test_conn *tc,
				   uint32_t reqid,
				   uint32_t opcode,
				   int32_t status,
				   struct ctdb_reply_control_data *rdata)
{
	struct ctdb_req_header h;
	struct ctdb_reply_control c = {
		.status = status,
		.rdata = *rdata,
	};
	uint8_t *buf = NULL;
	size_t buflen;
	ssize_t nwritten;
	int ret;

	c.rdata.opcode = opcode;

	ctdb_req_header_fill(&h, 0, CTDB_REPLY_CONTROL,
			     tc->conn->our_vnn, 7,
			     reqid);

	buflen = ctdb_reply_control_len(&h, &c);
	buf = talloc_size(tc->conn, buflen);
	assert_non_null(buf);
	ret = ctdb_reply_control_push(&h, &c, buf, &buflen);
	assert_int_equal(ret, 0);

	nwritten = write_data(tc->ctdbd_fd, buf, buflen);
	assert_int_equal(nwritten, buflen);

	TALLOC_FREE(buf);
}

static void test_write_reply(struct test_conn *tc,
			     uint32_t opcode,
			     int32_t status,
			     struct ctdb_reply_control_data *rdata)
{
	/* the reqid of the next request */
	test_write_reply_reqid(tc, tc->conn->reqid + 1,
			       opcode, status, rdata);
}

/*
 * A record of a traverse, as sent by ctdbd to the srvid of the
 * traverse.
 */
static void test_write_traverse_record(struct test_conn *tc,
				       uint64_t srvid,
				       uint32_t reqid,
				       TDB_DATA key,
				       TDB_DATA data)
{
	struct ctdb_rec_data rec = {
		.reqid = reqid,
		.key = key,
		.data = data,
	};
	struct ctdb_req_header h;
	struct ctdb_req_message_data m = {
		.srvid = srvid,
	};
	uint8_t *buf = NULL;
	size_t buflen, np;
	ssize_t nwritten;
	int ret;

	m.data.dsize = ctdb_rec_data_len(&rec);
	m.data.dptr = talloc_size(tc->conn, m.data.dsize);
	assert_non_null(m.data.dptr);
	ctdb_rec_data_push(&rec, m.data.dptr, &np);
	assert_int_equal(np, m.data.dsize);

	ctdb_req_header_fill(&h, 0, CTDB_REQ_MESSAGE,
			     tc->conn->our_vnn, 7, 0);

	buflen = ctdb_req_message_data_len(&h, &m);
	buf = talloc_size(tc->conn, buflen);
	assert_non_null(buf);
	ret = ctdb_req_message_data_push(&h, &m, buf, &buflen);
	assert_int_equal(ret, 0);

	nwritten = write_data(tc->ctdbd_fd, buf, buflen);
	assert_int_equal(nwritten, buflen);

	TALLOC_FREE(buf);
	TALLOC_FREE(m.data.dptr);
}

static TDB_DATA test_read_packet(struct test_conn *tc, TALLOC_CTX *mem_ctx)
{
	TDB_DATA pkt;
	uint32_t length;
	ssize_t nread;

	nread = read_data(tc->ctdbd_fd, &length, sizeof(length));
	assert_int_equal(nread, sizeof(length));
	assert_in_range(length, sizeof(struct ctdb_req_header), 4096);

	pkt.dsize = length;
	pkt.dptr = talloc_size(mem_ctx, pkt.dsize);
	assert_non_null(pkt.dptr);
	memcpy(pkt.dptr, &length, sizeof(length));

	nread = read_data(tc->ctdbd_fd,
			  pkt.dptr + sizeof(length),
			  pkt.dsize - sizeof(length));
	assert_int_equal(nread, pkt.dsize - sizeof(length));

	return pkt;
}

/*
 * Parse the request with the protocol library and check
 * that pushing it again gives the same bytes.
 */
static void test_read_control(struct test_conn *tc,
			      TALLOC_CTX *mem_ctx,
			      uint32_t vnn,
			      uint32_t opcode,
			      struct ctdb_req_control *c)
{
	struct ctdb_req_header h;
	TDB_DATA pkt;
	uint8_t *buf = NULL;
	size_t buflen;
	int ret;

	pkt = test_read_packet(tc, mem_ctx);

	ret = ctdb_req_control_pull(pkt.dptr, pkt.dsize, &h, mem_ctx, c);
	assert_int_equal(ret, 0);

	assert_int_equal(h.length, pkt.dsize);
	assert_int_equal(h.ctdb_magic, CTDB_MAGIC);
	assert_int_equal(h.ctdb_version, CTDB_PROTOCOL);
	assert_int_equal(h.operation, CTDB_REQ_CONTROL);
	assert_int_equal(h.destnode, vnn);
	assert_int_equal(h.reqid, tc->conn->reqid);
	assert_int_equal(c->opcode, opcode);
	assert_int_equal(c->rdata.opcode, opcode);

	buflen = ctdb_req_control_len(&h, c);
	assert_int_equal(buflen, pkt.dsize);
	buf = talloc_size(mem_ctx, buflen);
	assert_non_null(buf);
	ret = ctdb_req_control_push(&h, c, buf, &buflen);
	assert_int_equal(ret, 0);
	assert_int_equal(buflen, pkt.dsize);
	assert_memory_equal(buf, pkt.dptr, pkt.dsize);
}

static void test_process_exists(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct test_conn tc = test_conn_setup(frame);
	struct ctdb_reply_control_data rdata = { 0, };
	struct ctdb_req_control c;
	bool ok;

	test_write_reply(&tc, CTDB_CONTROL_PROCESS_EXISTS, 0, &rdata);

	ok = ctdbd_process_exists(tc.conn, 5, 0x12345678,
				  SERVERID_UNIQUE_ID_NOT_TO_VERIFY);
	assert_true(ok);

	test_read_control(&tc, frame, 5, CTDB_CONTROL_PROCESS_EXISTS, &c);
	assert_int_equal(c.rdata.data.pid, 0x12345678);

	test_conn_teardown(&tc);
	TALLOC_FREE(frame);
}

static void test_check_pid_srvid(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct test_conn tc = test_conn_setup(frame);
	struct ctdb_reply_control_data rdata = { 0, };
	struct ctdb_req_control c;
	bool ok;

	/* a failing status means the process doesn't exist */
	test_write_reply(&tc, CTDB_CONTROL_CHECK_PID_SRVID, -1, &rdata);

	ok = ctdbd_process_exists(tc.conn, 5, 0x12345678,
				  0x0102030405060708);
	assert_false(ok);

	test_read_control(&tc, frame, 5, CTDB_CONTROL_CHECK_PID_SRVID, &c);
	assert_non_null(c.rdata.data.pid_srvid);
	assert_int_equal(c.rdata.data.pid_srvid->pid, 0x12345678);
	assert_int_equal(c.rdata.data.pid_srvid->srvid, 0x0102030405060708);

	test_conn_teardown(&tc);
	TALLOC_FREE(frame);
}

static void test_get_public_ips(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct test_conn tc = test_conn_setup(frame);
	struct ctdb_public_ip ip[2] = {
		{ .pnn = 1, },
		{ .pnn = 0x11223344, },
	};
	struct ctdb_public_ip_list list = {
		.num = ARRAY_SIZE(ip),
		.ip = ip,
	};
	struct ctdb_reply_control_data rdata = {
		.data.pubip_list = &list,
	};
	struct ctdb_public_ip_list_old *ips = NULL;
	struct ctdb_req_control c;
	uint32_t i;
	int ret;

	ip[0].addr.ip.sin_family = AF_INET;
	ip[0].addr.ip.sin_port = htons(445);
	ip[0].addr.ip.sin_addr.s_addr = htonl(0x0a000001);
	ip[1].addr.ip6.sin6_family = AF_INET6;
	ip[1].addr.ip6.sin6_port = htons(445);
	ip[1].addr.ip6.sin6_addr.s6_addr[0] = 0xfd;
	ip[1].addr.ip6.sin6_addr.s6_addr[15] = 0x02;

	test_write_reply(&tc, CTDB_CONTROL_GET_PUBLIC_IPS, 0, &rdata);

	ret = ctdbd_control_get_public_ips(tc.conn, 5, 0, frame, &ips);
	assert_int_equal(ret, 0);
	assert_non_null(ips);

	assert_int_equal(ips->num, ARRAY_SIZE(ip));
	for (i = 0; i < ips->num; i++) {
		assert_int_equal(ips->ips[i].pnn, ip[i].pnn);
		assert_memory_equal(&ips->ips[i].addr,
				    &ip[i].addr,
				    sizeof(ip[i].addr));
	}

	test_read_control(&tc, frame, 5, CTDB_CONTROL_GET_PUBLIC_IPS, &c);

	test_conn_teardown(&tc);
	TALLOC_FREE(frame);
}

static void test_messaging_send(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct test_conn tc = test_conn_setup(frame);
	uint8_t payload1[] = { 0x01, 0x02, 0x03 };
	uint8_t payload2[] = { 0x11, 0x12, 0x13, 0x14, 0x15 };
	struct iovec iov[] = {
		{ .iov_base = payload1, .iov_len = sizeof(payload1), },
		{ .iov_base = payload2, .iov_len = sizeof(payload2), },
	};
	struct ctdb_req_header h;
	struct ctdb_req_message_data m;
	TDB_DATA pkt;
	uint8_t *buf = NULL;
	size_t buflen;
	int ret;

	ret = ctdbd_messaging_send_iov(tc.conn, 5, 0x0102030405060708,
				       iov, ARRAY_SIZE(iov));
	assert_int_equal(ret, 0);

	pkt = test_read_packet(&tc, frame);

	ret = ctdb_req_message_data_pull(pkt.dptr, pkt.dsize, &h, frame, &m);
	assert_int_equal(ret, 0);

	assert_int_equal(h.length, pkt.dsize);
	assert_int_equal(h.ctdb_magic, CTDB_MAGIC);
	assert_int_equal(h.ctdb_version, CTDB_PROTOCOL);
	assert_int_equal(h.operation, CTDB_REQ_MESSAGE);
	assert_int_equal(h.destnode, 5);
	assert_int_equal(h.srcnode, tc.conn->our_vnn);
	assert_int_equal(m.srvid, 0x0102030405060708);
	assert_int_equal(m.data.dsize, sizeof(payload1) + sizeof(payload2));
	assert_memory_equal(m.data.dptr, payload1, sizeof(payload1));
	assert_memory_equal(m.data.dptr + sizeof(payload1),
			    payload2,
			    sizeof(payload2));

	buflen = ctdb_req_message_data_len(&h, &m);
	assert_int_equal(buflen, pkt.dsize);
	buf = talloc_size(frame, buflen);
	assert_non_null(buf);
	ret = ctdb_req_message_data_push(&h, &m, buf, &buflen);
	assert_int_equal(ret, 0);
	assert_int_equal(buflen, pkt.dsize);
	assert_memory_equal(buf, pkt.dptr, pkt.dsize);

	test_conn_teardown(&tc);
	TALLOC_FREE(frame);
}

struct test_traverse_state {
	size_t num;
};

static void test_traverse_fn(TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct test_traverse_state *state = private_data;

	switch (state->num) {
	case 0:
		assert_int_equal(key.dsize, 3);
		assert_memory_equal(key.dptr, "abc", 3);
		assert_int_equal(data.dsize, 5);
		assert_memory_equal(data.dptr, "hello", 5);
		break;
	case 1:
		assert_int_equal(key.dsize, 1);
		assert_memory_equal(key.dptr, "k", 1);
		assert_int_equal(data.dsize, 0);
		break;
	default:
		fail_msg("unexpected record %zu", state->num);
	}

	state->num += 1;
}

/*
 * The records of a traverse come from the ctdbd of all nodes,
 * which may run different versions. ctdbd_traverse() casts them
 * to struct ctdb_rec_data_old.
 */
static void test_traverse(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct test_conn tc = test_conn_setup(frame);
	struct ctdb_reply_control_data rdata = { 0, };
	struct test_traverse_state tstate = { .num = 0, };
	struct ctdb_req_control c;
	uint32_t traverse_reqid;
	int ret;

	tc.conn->rand_srvid = 0x0102030405060708;

	/*
	 * ctdbd_traverse() uses the next reqid for the traverse,
	 * the one after it for the control.
	 */
	traverse_reqid = tc.conn->reqid + 1;
	test_write_reply_reqid(&tc, traverse_reqid + 1,
			       CTDB_CONTROL_TRAVERSE_START, 0, &rdata);

	test_write_traverse_record(&tc, tc.conn->rand_srvid, traverse_reqid,
				   make_tdb_data((const uint8_t *)"abc", 3),
				   make_tdb_data((const uint8_t *)"hello", 5));
	test_write_traverse_record(&tc, tc.conn->rand_srvid, traverse_reqid,
				   make_tdb_data((const uint8_t *)"k", 1),
				   tdb_null);
	/* an empty record ends the traverse */
	test_write_traverse_record(&tc, tc.conn->rand_srvid, traverse_reqid,
				   tdb_null, tdb_null);

	ret = ctdbd_traverse(tc.conn, 0x11223344, test_traverse_fn, &tstate);
	assert_int_equal(ret, 0);
	assert_int_equal(tstate.num, 2);

	test_read_control(&tc, frame, CTDB_CURRENT_NODE,
			  CTDB_CONTROL_TRAVERSE_START, &c);
	assert_int_equal(c.srvid, 0x0102030405060708);
	assert_non_null(c.rdata.data.traverse_start);
	assert_int_equal(c.rdata.data.traverse_start->db_id, 0x11223344);
	assert_int_equal(c.rdata.data.traverse_start->reqid, traverse_reqid);
	assert_int_equal(c.rdata.data.traverse_start->srvid,
			 0x0102030405060708);

	test_conn_teardown(&tc);
	TALLOC_FREE(frame);
}

int main(int argc, char **argv)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_process_exists),
		cmocka_unit_test(test_check_pid_srvid),
		cmocka_unit_test(test_get_public_ips),
		cmocka_unit_test(test_messaging_send),
		cmocka_unit_test(test_traverse),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}

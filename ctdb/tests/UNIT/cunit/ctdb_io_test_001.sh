#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

ok_null

unit_test ctdb_io_test 1
unit_test ctdb_io_test 2
unit_test ctdb_io_test 3
unit_test ctdb_io_test 4
unit_test ctdb_io_test 6

ok "test queue: packet with a different byte order (length 0x28000000, magic 0x42445443), the peer uses a different architecture"
unit_test ctdb_io_test 5

ok "test queue: non CTDB packet (length 0x10000000, magic 0x11223344)"
unit_test ctdb_io_test 7

ok "test queue: bad CTDB version 0x2"
unit_test ctdb_io_test 8

ok "test queue: packet length 16 is smaller than the header"
unit_test ctdb_io_test 9

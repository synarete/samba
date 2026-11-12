#!/usr/bin/env bash

# Check that nodes with a different wire format are rejected

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init

select_test_node

d="$CTDB_TEST_HELPER_BINDIR"
try_command_on_node "$test_node" "${d}/ctdb-path" "pidfile" "ctdbd"
# $out assigned above by try_command_on_node()
# shellcheck disable=SC2154
pidfile="$out"

# The size of struct ctdb_statistics differs between e.g.
# 32-bit and 64-bit builds. The restarted node started
# later, so it should notice the different size and exit.
export CTDB_TEST_STATISTICS_SIZE_DELTA=-4
printf '\nRestarting node %d with CTDB_TEST_STATISTICS_SIZE_DELTA=%d\n' \
	"$test_node" \
	"$CTDB_TEST_STATISTICS_SIZE_DELTA"
ctdb_nodes_restart "$test_node"
echo "Will use PID file ${pidfile} to check for ctdbd exit"
wait_until 30 ! test -f "$pidfile"
echo "GOOD: ctdbd exited early on node ${test_node}"

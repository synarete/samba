#!/usr/bin/env bash

# Verify that a 2-node cluster can operate with nodes running different
# ctdbd binaries.
#
# The test requires the environment variable CTDB_TEST_MIXED_VERSIONS_CTDBD
# to be set to the path of an alternate ctdbd binary (typically a build from a
# different code revision).  If the variable is unset the test is skipped.
#
# Node 0 runs the default ctdbd (from PATH); node 1 runs the alternate binary.
# The cluster must form, become healthy and survive a basic connectivity check.

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

if [ -z "${CTDB_TEST_MIXED_VERSIONS_CTDBD:-}" ]; then
	ctdb_test_skip \
		"SKIPPING: CTDB_TEST_MIXED_VERSIONS_CTDBD is not set"
fi

if [ ! -x "$CTDB_TEST_MIXED_VERSIONS_CTDBD" ]; then
	ctdb_test_error \
		"CTDB_TEST_MIXED_VERSIONS_CTDBD=${CTDB_TEST_MIXED_VERSIONS_CTDBD} is not executable"
fi

echo "Node 0: default ctdbd (from PATH)"
echo "Node 1: ${CTDB_TEST_MIXED_VERSIONS_CTDBD}"

# setup_ctdb_mixed_versions is provided by integration_local_daemons.bash.
# First argument is the binary for node 0 (empty = default),
# second is the binary for node 1.
# -n 2 : only 2 nodes needed for this test.
ctdb_test_init -n
setup_ctdb_mixed_versions "" "$CTDB_TEST_MIXED_VERSIONS_CTDBD" -n 2

echo "Starting cluster..."
ctdb_init || ctdb_test_error "Cluster startup failed"

echo "*** SETUP COMPLETE, RUNNING TEST..."

wait_until_ready 120

echo "Cluster is healthy with mixed ctdbd versions"

# Confirm both nodes are reachable and report a PNN
try_command_on_node -v 0 ctdb pnn
try_command_on_node -v 1 ctdb pnn

echo "GOOD: both nodes are reachable"

# A basic inter-node ping exercises the messaging path between the two
# different builds.
try_command_on_node -v 0 ctdb ping -n 1
echo "GOOD: node 0 can ping node 1"

try_command_on_node -v 1 ctdb ping -n 0
echo "GOOD: node 1 can ping node 0"

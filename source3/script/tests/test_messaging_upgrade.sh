#!/usr/bin/env bash
#
# Test that a cluster can be upgraded from legacy messaging format (cluster
# level 0.1, pre-NDR) to NDR-based messaging (level 1.0) without interrupting
# SMB service.
#
# The clusteredmember_msg_upgrade environment starts all three nodes with
# cluster_level.tdb pre-seeded to level 0.1 so that smbd operates in legacy
# mode. Then test:
#
#  1. Verifies that all three nodes serve SMB traffic at level 0.1.
#  2. Verifies that legacy messages works at level 0.1.
#  3. Runs "net clusterlevel upgrade --apply" to raise the level to 1.0.
#  4. Verifies the new level is reported by "net clusterlevel show".
#  5. Verifies that new NDR messages works fine
#  6. Verifies that all three nodes still serve SMB traffic after the upgrade.
#
# Expected arguments:
#   $1  CONFIGURATION  – --configfile=... for node 0 (used by net/smbcontrol)
#   $2  NODE0          – hostname/IP for node 0
#   $3  NODE1          – hostname/IP for node 1
#   $4  NODE2          – hostname/IP for node 2
#   $5  SHARENAME      – share to connect to

if [ $# -lt 5 ]; then
	echo "Usage: $0 CONF NODE0 NODE1 NODE2 SHARE"
	exit 1
fi

CONF=$1
NODE0=$2
NODE1=$3
NODE2=$4
SHARE=$5

SMBCLIENT="$BINDIR/smbclient"
SMBCONTROL="$BINDIR/smbcontrol"
NET="$BINDIR/net"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir/subunit.sh"

failed=0

# Run a command with uid_wrapper posing as root (ruid=0, euid=0).
run_as_root()
{
	UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 "$@"
}

# Run smbclient ls against one node and check it succeeds
smbclient_ls()
{
	local name="$1"
	local server="$2"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$SMBCLIENT" "//$server/$SHARE" \
		-U"${DC_USERNAME}%${DC_PASSWORD}" \
		-c ls 2>&1)
	local st=$?
	if [ $st -eq 0 ]; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
	fi
	return $st
}

# Send smbcontrol ping to all smbd and verify at least one PONG is received.
smbcontrol_ping()
{
	local name="$1"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$SMBCONTROL" "$CONF" smbd ping 2>&1)
	local st=$?
	if [ $st -eq 0 ] && echo "$out" | grep -q "^PONG from pid "; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
		return 1
	fi
	return 0
}

# Send "smbcontrol smbd debug <level>" (fire-and-forget); success means the
# message was dispatched without error.
smbcontrol_debug()
{
	local name="$1"
	local level="$2"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$SMBCONTROL" "$CONF" smbd debug "$level" 2>&1)
	local st=$?
	if [ $st -eq 0 ]; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
	fi
	return $st
}

# Query current debug levels from all smbd processes; expects at least one
# reply.
smbcontrol_debuglevel()
{
	local name="$1"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$SMBCONTROL" "$CONF" smbd debuglevel 2>&1)
	local st=$?
	# success requires both a zero exit status and at least one reply line
	if [ $st -eq 0 ] && echo "$out" | grep -q .; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
		return 1
	fi
	return 0
}

# Helper: send "smbcontrol smbd profile <cmd>" (fire-and-forget).
smbcontrol_profile()
{
	local name="$1"
	local cmd="$2"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$SMBCONTROL" "$CONF" smbd profile "$cmd" 2>&1)
	local st=$?
	if [ $st -eq 0 ]; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
	fi
	return $st
}

# Query current profile level from all smbd processes; expects at least one
# reply.  If profiling support was not compiled in, smbcontrol exits non-zero
# with "No replies received" – treat that as a skip rather than a failure.
smbcontrol_profilelevel()
{
	local name="$1"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$SMBCONTROL" "$CONF" smbd profilelevel 2>&1)
	local st=$?
	if [ $st -eq 0 ] && echo "$out" | grep -q .; then
		subunit_pass_test "$name"
	elif echo "$out" | grep -qF "No replies received"; then
		echo "profiling not compiled in" | subunit_skip_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
		return 1
	fi
	return 0
}

# Apply the cluster functional level upgrade via net
cluster_level_upgrade()
{
	local name="$1"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$NET" "$CONF" clusterlevel upgrade --apply 2>&1)
	local st=$?
	if [ $st -eq 0 ]; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
	fi
	return $st
}

# Check that net clusterlevel show reports the expected level string
cluster_level_show()
{
	local name="$1"
	local expected="$2"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$NET" "$CONF" clusterlevel show 2>&1)
	local st=$?
	if [ $st -eq 0 ] && echo "$out" | grep -qF "$expected"; then
		subunit_pass_test "$name"
	else
		echo "Expected '$expected' in output: $out" | \
			subunit_fail_test "$name"
		return 1
	fi
	return 0
}

# Poll "net clusterlevel show" until it reports the expected level string
# or the timeout (in seconds) expires.  Returns 0 on success, 1 on timeout.
wait_for_cluster_level()
{
	local expected="$1"
	local timeout="${2:-10}"
	local i=0
	local out

	while [ "$i" -lt "$timeout" ]; do
		out=$(run_as_root "$NET" "$CONF" clusterlevel show 2>&1)
		echo "$out" | grep -qF "$expected" && return 0
		sleep 1
		i=$((i + 1))
	done
	return 1
}

# ===========================================================================
# Step 1 – verify baseline operation at legacy level 0.1
# ===========================================================================

# If the starting level is wrong the environment was not set up correctly;
# all subsequent steps would be meaningless, so abort immediately.
if ! cluster_level_show \
	"step1: cluster level is 0.1 at startup" "0.1"; then
	failed=$((failed + 1))
	echo "FATAL: expected starting level 0.1 - aborting test" >&2
	testok "$0" "$failed"
	exit 1
fi

smbclient_ls "step1: smbclient node0 (level 0.1)" "$NODE0" \
	|| failed=$((failed + 1))
smbclient_ls "step1: smbclient node1 (level 0.1)" "$NODE1" \
	|| failed=$((failed + 1))
smbclient_ls "step1: smbclient node2 (level 0.1)" "$NODE2" \
	|| failed=$((failed + 1))

# At level 0.1 smbcontrol sends legacy messages (non NDR)
smbcontrol_ping "step1: smbcontrol ping (legacy MSG_PING at level 0.1)" \
	|| failed=$((failed + 1))

smbcontrol_debug "step1: smbcontrol debug (legacy MSG_DEBUG at level 0.1)" \
	"3" || failed=$((failed + 1))

smbcontrol_debuglevel \
	"step1: smbcontrol debuglevel (legacy MSG_REQ_DEBUGLEVEL at level 0.1)" \
	|| failed=$((failed + 1))

smbcontrol_profile \
	"step1: smbcontrol profile off (legacy MSG_PROFILE at level 0.1)" \
	"off" || failed=$((failed + 1))

smbcontrol_profilelevel \
	"step1: smbcontrol profilelevel (legacy MSG_REQ_PROFILELEVEL at level 0.1)" \
	|| failed=$((failed + 1))

# ===========================================================================
# Step 2 – upgrade cluster level from 0.1 to 1.0
# ===========================================================================

cluster_level_upgrade "step2: net clusterlevel upgrade --apply (0.1 -> 1.0)" \
	|| failed=$((failed + 1))

# Poll until all smbd processes have received MSG_CLUSTER_LEVEL_UPGRADED
# and updated their in-memory cached level (up to 10 s).
if ! wait_for_cluster_level "1.0"; then
	echo "Timed out waiting for cluster level 1.0" >&2
fi

cluster_level_show "step2: cluster level is 1.0 after upgrade" "1.0" \
	|| failed=$((failed + 1))

# ===========================================================================
# Step 3 – verify NDR messaging and continued SMB service at level 1.0
# ===========================================================================

# At level 1.0 smbcontrol switches to NDR-encoded messages.  A reply
# means both the sender and receiver handle the new format correctly.
smbcontrol_ping "step3: smbcontrol ping (NDR MSG_PING_V1 at level 1.0)" \
	|| failed=$((failed + 1))

smbcontrol_debug "step3: smbcontrol debug (NDR MSG_DEBUG_V1 at level 1.0)" \
	"3" || failed=$((failed + 1))

smbcontrol_debuglevel \
	"step3: smbcontrol debuglevel (NDR MSG_REQ_DEBUGLEVEL_V1 at level 1.0)" \
	|| failed=$((failed + 1))

smbcontrol_profile \
	"step3: smbcontrol profile off (NDR MSG_PROFILE_V1 at level 1.0)" \
	"off" || failed=$((failed + 1))

smbcontrol_profilelevel \
	"step3: smbcontrol profilelevel (NDR MSG_REQ_PROFILELEVEL_V1 at level 1.0)" \
	|| failed=$((failed + 1))

# Verify smbd is alive
smbclient_ls "step3: smbclient node0 (level 1.0)" "$NODE0" \
	|| failed=$((failed + 1))
smbclient_ls "step3: smbclient node1 (level 1.0)" "$NODE1" \
	|| failed=$((failed + 1))
smbclient_ls "step3: smbclient node2 (level 1.0)" "$NODE2" \
	|| failed=$((failed + 1))

testok "$0" "$failed"

#!/usr/bin/env bash
#
# Test that a cluster can be upgraded from legacy messaging format (cluster
# level 0.1, pre-NDR) to NDR-based messaging (level 1.0) without interrupting
# SMB service.
#
# The clusteredmember_msg_upgrade environment starts all three nodes with
# cluster_level.tdb pre-seeded to level 0.1 so that smbd operates in legacy
# mode.  This test then:
#
#   1. Verifies that all three nodes serve SMB traffic at level 0.1.
#   2. Verifies that smbcontrol ping succeeds at level 0.1 (legacy MSG_PING).
#   3. Runs "net clusterlevel upgrade --apply" to raise the level to 1.0.
#   4. Verifies the new level is reported by "net clusterlevel show".
#   5. Verifies that smbcontrol ping now uses the NDR format (MSG_PING_V1).
#   6. Verifies that all three nodes still serve SMB traffic after the upgrade.
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

# ---------------------------------------------------------------------------
# Helper: run smbclient ls against one node and check it succeeds
# ---------------------------------------------------------------------------
smbclient_ls()
{
	local name="$1"
	local server="$2"
	subunit_start_test "$name"
	local out
	out=$(UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 \
		"$SMBCLIENT" "//$server/$SHARE" \
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

# ---------------------------------------------------------------------------
# Helper: send smbcontrol ping to all smbd and expect at least one reply
# ---------------------------------------------------------------------------
smbcontrol_ping()
{
	local name="$1"
	subunit_start_test "$name"
	local out
	out=$(UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 \
		"$SMBCONTROL" "$CONF" smbd ping 2>&1)
	local st=$?
	if [ $st -eq 0 ]; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
	fi
	return $st
}

# ---------------------------------------------------------------------------
# Helper: apply the cluster functional level upgrade via net
# ---------------------------------------------------------------------------
cluster_level_upgrade()
{
	local name="$1"
	subunit_start_test "$name"
	local out
	out=$(UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 \
		"$NET" "$CONF" clusterlevel upgrade --apply 2>&1)
	local st=$?
	if [ $st -eq 0 ]; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
	fi
	return $st
}

# ---------------------------------------------------------------------------
# Helper: check that net clusterlevel show reports the expected level string
# ---------------------------------------------------------------------------
cluster_level_show()
{
	local name="$1"
	local expected="$2"
	subunit_start_test "$name"
	local out
	out=$(UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 \
		"$NET" "$CONF" clusterlevel show 2>&1)
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

# ===========================================================================
# Step 1 – verify baseline operation at legacy level 0.1
# ===========================================================================

cluster_level_show "step1: cluster level is 0.1 at startup" "0.1" \
	|| failed=$((failed + 1))

smbclient_ls "step1: smbclient node0 (level 0.1)" "$NODE0" \
	|| failed=$((failed + 1))
smbclient_ls "step1: smbclient node1 (level 0.1)" "$NODE1" \
	|| failed=$((failed + 1))
smbclient_ls "step1: smbclient node2 (level 0.1)" "$NODE2" \
	|| failed=$((failed + 1))

# At level 0.1 smbcontrol sends legacy MSG_PING and expects MSG_PONG back.
smbcontrol_ping "step1: smbcontrol ping (legacy MSG_PING at level 0.1)" \
	|| failed=$((failed + 1))

# ===========================================================================
# Step 2 – upgrade cluster level from 0.1 to 1.0
# ===========================================================================

cluster_level_upgrade "step2: net clusterlevel upgrade --apply (0.1 -> 1.0)" \
	|| failed=$((failed + 1))

# Give all smbd processes time to receive MSG_CLUSTER_LEVEL_UPGRADED and
# update their in-memory cached level.
sleep 2

cluster_level_show "step2: cluster level is 1.0 after upgrade" "1.0" \
	|| failed=$((failed + 1))

# ===========================================================================
# Step 3 – verify NDR messaging and continued SMB service at level 1.0
# ===========================================================================

# At level 1.0 smbcontrol switches to MSG_PING_V1 (NDR-encoded).  A reply
# means both the sender and receiver handle the new format correctly.
smbcontrol_ping "step3: smbcontrol ping (NDR MSG_PING_V1 at level 1.0)" \
	|| failed=$((failed + 1))

smbclient_ls "step3: smbclient node0 (level 1.0)" "$NODE0" \
	|| failed=$((failed + 1))
smbclient_ls "step3: smbclient node1 (level 1.0)" "$NODE1" \
	|| failed=$((failed + 1))
smbclient_ls "step3: smbclient node2 (level 1.0)" "$NODE2" \
	|| failed=$((failed + 1))

testok "$0" "$failed"

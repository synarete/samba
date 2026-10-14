#!/usr/bin/env bash
#
# Test that a cluster can be upgraded from legacy messaging format (cluster
# level 1.0, pre-NDR) to NDR-based messaging (level 2.0) without interrupting
# SMB service.
#
# The clusteredmember_msg_upgrade environment starts all three nodes with
# cluster_level.tdb pre-seeded to level 1.0 so that smbd operates in
# legacy mode. The test then does:
#
#  Step 1 (level 1.0):
#   - verifies the cluster starts at level 1.0 (abort otherwise),
#   - verifies that all three nodes serve SMB traffic, including file I/O
#     (put/get/rm),
#   - verifies that legacy (non-NDR) messages work.
#  Step 2:
#   - runs "net clusterlevel upgrade --apply" to raise the level to 2.0,
#   - verifies the new level is reported by "net clusterlevel show".
#  Step 3 (level 2.0):
#   - verifies that the new NDR messages work,
#   - verifies that all three nodes still serve SMB traffic, including file
#     I/O (put/get/rm), after the upgrade.
#
# Expected arguments:
#   $1  CONF   - --configfile=... for node 0 (used by net/smbcontrol)
#   $2  NODE0  - hostname/IP for node 0
#   $3  NODE1  - hostname/IP for node 1
#   $4  NODE2  - hostname/IP for node 2
#   $5  SHARE  - share to connect to

if [ $# -lt 5 ]; then
	echo "Usage: $0 CONF NODE0 NODE1 NODE2 SHARE" >&2
	exit 1
fi

CONF=$1
NODE0=$2
NODE1=$3
NODE2=$4
SHARE=$5

SMBCLIENT="$BINDIR/smbclient"
SMBCONTROL="$BINDIR/smbcontrol"
SMBSTATUS="$BINDIR/smbstatus"
NET="$BINDIR/net"

CREDS="-U${DC_USERNAME}%${DC_PASSWORD}"

# A share name which does not exist, so that sending it in close-share and
# close-denied-share does not tear down the connections used by the test.
NO_SUCH_SHARE="msg_upgrade_no_such_share"

# An address from the TEST-NET-1 range (RFC 5737), so that kill-client-ip
# does not disconnect any client used by the test.
TEST_NET_1_IP="192.0.2.1"

incdir=$(dirname "$0")/../../../testprogs/blackbox
. "$incdir/subunit.sh"

failed=0

cd "$SELFTEST_TMPDIR" || exit 1

# Command prefix to run a command with uid_wrapper posing as root (ruid=0,
# euid=0).
#
# This is deliberately not a shell function: when a function is run in the
# background, $! is the pid of the subshell running it rather than the pid of
# the command, so killing it would leave the command itself running.  With a
# prefix, the command is exec'ed directly and $! is its own pid.
AS_ROOT=(env UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0)

# Report the result of a test in the subunit format.
#   $1  test name
#   $2  exit status of the test (0 means pass)
#   $3  output to show if the test failed
subunit_report()
{
	local name="$1"
	local st="$2"
	local out="$3"

	if [ "$st" -eq 0 ]; then
		subunit_pass_test "$name"
		return 0
	fi
	printf '%s\n' "$out" | subunit_fail_test "$name"
	return 1
}

# Run a test function as "<func> <test name> [args...]" and count it as
# failed if it fails.
run_test()
{
	local func="$1"
	shift

	"$func" "$@" || failed=$((failed + 1))
}

# Run a test function which exercises a specific message, with a test name
# built from the current phase (see run_messaging_tests):
#
#   "<STEP>: <description> (<MSG_KIND> <messages> at level <LEVEL>)"
#
#   $1  test description
#   $2  name(s) of the message(s) exercised, separated by "/".  The phase's
#       version suffix is appended to each of them.
#   $3  test function, called as "<func> <test name> [args...]"
#   $4+ additional arguments to the test function
run_msg_test()
{
	local desc="$1"
	local msgs="$2"
	local func="$3"
	shift 3

	if [ -n "$MSG_SFX" ]; then
		msgs="${msgs//\//${MSG_SFX}/}${MSG_SFX}"
	fi

	run_test "$func" \
		"$STEP: $desc ($MSG_KIND $msgs at level $LEVEL)" "$@"
}

# Run smbclient ls against one node and check it succeeds.
smbclient_ls()
{
	local name="$1"
	local server="$2"
	subunit_start_test "$name"

	local out
	out=$("${AS_ROOT[@]}" "$SMBCLIENT" "//$server/$SHARE" "$CREDS" \
		-c ls 2>&1)
	local st=$?

	subunit_report "$name" "$st" "$out"
}

# Write a small file to the share, read it back, compare, and delete it.
# This verifies actual file I/O (write + read) works on the given node.
smbclient_put_get_rm()
{
	local name="$1"
	local server="$2"
	subunit_start_test "$name"

	local src="msg_upgrade_io_$$.tmp"
	local dst="${src}.got"
	echo "messaging upgrade I/O test" >"$src"

	local out
	out=$("${AS_ROOT[@]}" "$SMBCLIENT" "//$server/$SHARE" "$CREDS" \
		-c "put $src $src; get $src $dst; rm $src" 2>&1)
	local st=$?

	if [ $st -eq 0 ] && ! diff -q "$src" "$dst" >/dev/null 2>&1; then
		out="$out
Content of $dst differs from $src"
		st=1
	fi
	rm -f "$src" "$dst"

	subunit_report "$name" "$st" "$out"
}

# Run "smbcontrol <args>" and check it succeeds.  Used for messages which
# do not produce a reply (fire-and-forget); success means the message was
# dispatched without error.
#   $1  test name
#   $2+ arguments to smbcontrol (destination and command)
smbcontrol_ok()
{
	local name="$1"
	shift
	subunit_start_test "$name"

	local out
	out=$("${AS_ROOT[@]}" "$SMBCONTROL" "$CONF" "$@" 2>&1)
	local st=$?

	subunit_report "$name" "$st" "$out"
}

# Run "smbcontrol <args>" and check it succeeds and that at least one line of
# its output matches an (extended) regular expression.  Used for messages
# which are expected to get a reply.
#   $1  test name
#   $2  regular expression the output is matched against
#   $3+ arguments to smbcontrol (destination and command)
smbcontrol_reply()
{
	local name="$1"
	local pattern="$2"
	shift 2
	subunit_start_test "$name"

	local out
	out=$("${AS_ROOT[@]}" "$SMBCONTROL" "$CONF" "$@" 2>&1)
	local st=$?

	if [ $st -eq 0 ] && ! printf '%s\n' "$out" | grep -qE "$pattern"; then
		out="Unexpected reply (expected '$pattern'): $out"
		st=1
	fi

	subunit_report "$name" "$st" "$out"
}

# Query current profile level from all smbd processes; expects at least one
# reply.  If profiling support was not compiled in, smbcontrol exits non-zero
# with "No replies received" - treat that as a skip rather than a failure.
smbcontrol_profilelevel()
{
	local name="$1"
	subunit_start_test "$name"

	local out
	out=$("${AS_ROOT[@]}" "$SMBCONTROL" "$CONF" smbd profilelevel 2>&1)
	local st=$?

	if [ $st -ne 0 ] && echo "$out" | grep -qF "No replies received"; then
		echo "profiling not compiled in" | subunit_skip_test "$name"
		return 0
	fi
	if [ $st -eq 0 ] && ! echo "$out" | grep -q .; then
		out="No reply received"
		st=1
	fi

	subunit_report "$name" "$st" "$out"
}

# Send "smbcontrol <pid> pool-usage" to a smbd process.
# Because pool-usage requires a specific PID (it passes an fd) and smbstatus
# only lists processes that have active sessions, we open a background
# smbclient connection to guarantee at least one session exists while we
# query smbstatus AND while smbcontrol sends the message.
smbcontrol_pool_usage()
{
	local name="$1"
	subunit_start_test "$name"

	# Open a persistent smbclient connection in interactive mode via a
	# fifo so that smbstatus sees at least one active session.
	local fifo_in="$SELFTEST_TMPDIR/pool_usage_in_$$"
	rm -f "$fifo_in"
	mkfifo "$fifo_in"

	# smbclient reads commands from $fifo_in; we hold the write end open
	# (fd 9) so it blocks waiting for input and keeps the session alive.
	"${AS_ROOT[@]}" "$SMBCLIENT" "//$NODE0/$SHARE" "$CREDS" \
		<"$fifo_in" >/dev/null 2>&1 &
	local client_pid=$!
	exec 9>"$fifo_in"

	# Give smbd a moment to register the session.
	sleep 1

	# Discover a smbd PID via smbstatus.
	local smbd_pid
	smbd_pid=$("${AS_ROOT[@]}" "$SMBSTATUS" "$CONF" -p 2>/dev/null |
		awk '/^[0-9]/{print $1; exit}')

	local out
	local st
	if [ -z "$smbd_pid" ]; then
		out="Could not find a smbd PID via smbstatus"
		st=1
	else
		# Send pool-usage while the smbclient session is still alive
		# so that smbd is guaranteed to be running when the message
		# arrives.
		out=$("${AS_ROOT[@]}" "$SMBCONTROL" "$CONF" "$smbd_pid" \
			pool-usage 2>&1)
		st=$?
	fi

	# Now close our end of the fifo; smbclient will get EOF and exit.
	exec 9>&-
	wait "$client_pid" 2>/dev/null
	rm -f "$fifo_in"

	subunit_report "$name" "$st" "$out"
}

# Apply the cluster functional level upgrade via net
cluster_level_upgrade()
{
	local name="$1"
	subunit_start_test "$name"

	local out
	out=$("${AS_ROOT[@]}" "$NET" "$CONF" clusterlevel upgrade --apply 2>&1)
	local st=$?

	subunit_report "$name" "$st" "$out"
}

# Check that the output of net clusterlevel show reports the expected level
# (e.g. "2.0").
#   $1  expected level
#   $2  output of net clusterlevel show
cluster_level_in()
{
	echo "$2" | grep -qF "Active cluster functional level: $1"
}

# Test that net clusterlevel show reports the expected level.
cluster_level_show()
{
	local name="$1"
	local expected="$2"
	subunit_start_test "$name"

	local out
	out=$("${AS_ROOT[@]}" "$NET" "$CONF" clusterlevel show 2>&1)
	local st=$?

	if [ $st -eq 0 ] && ! cluster_level_in "$expected" "$out"; then
		st=1
	fi

	subunit_report "$name" "$st" \
		"Expected level '$expected' in output: $out"
}

# Poll "net clusterlevel show" until it reports the expected level or the
# timeout (in seconds) expires.  Returns 0 on success, 1 on timeout.
wait_for_cluster_level()
{
	local expected="$1"
	local timeout="${2:-10}"
	local out
	local i

	for ((i = 0; i < timeout; i++)); do
		out=$("${AS_ROOT[@]}" "$NET" "$CONF" clusterlevel show 2>&1)
		if cluster_level_in "$expected" "$out"; then
			return 0
		fi
		sleep 1
	done
	return 1
}

# Verify smbd is alive on all nodes and file I/O works.
#   $1  step name, used as test name prefix
#   $2  cluster level, used in the test names
check_smb_service()
{
	local step="$1"
	local level="$2"
	local nodes=("$NODE0" "$NODE1" "$NODE2")
	local i

	for i in 0 1 2; do
		run_test smbclient_ls \
			"$step: smbclient node$i (level $level)" "${nodes[i]}"
	done

	for i in 0 1 2; do
		run_test smbclient_put_get_rm \
			"$step: I/O node$i put/get/rm (level $level)" \
			"${nodes[i]}"
	done
}

# Send each of the messages tested by this script, which are sent as legacy
# messages at level 1.0 and as NDR-encoded messages (with a "_V1" suffix) at
# level 2.0, and verify that sender and receiver handle them correctly.
#   $1  step name, used as test name prefix
#   $2  cluster level, used in the test names
#   $3  kind of messages sent at this level ("legacy" or "NDR"), used in the
#       test names
#   $4  suffix of the names of the messages sent at this level (empty or
#       "_V1"), used in the test names
run_messaging_tests()
{
	STEP="$1"
	LEVEL="$2"
	MSG_KIND="$3"
	MSG_SFX="$4"

	run_msg_test "smbcontrol ping" "MSG_PING" \
		smbcontrol_reply "^PONG from pid " smbd ping

	run_msg_test "smbcontrol debug" "MSG_DEBUG" \
		smbcontrol_ok smbd debug 3

	run_msg_test "smbcontrol debuglevel" "MSG_REQ_DEBUGLEVEL" \
		smbcontrol_reply "." smbd debuglevel

	run_msg_test "smbcontrol profile off" "MSG_PROFILE" \
		smbcontrol_ok smbd profile off

	run_msg_test "smbcontrol profilelevel" "MSG_REQ_PROFILELEVEL" \
		smbcontrol_profilelevel

	run_msg_test "smbcontrol pool-usage" "MSG_REQ_POOL_USAGE" \
		smbcontrol_pool_usage

	run_msg_test "smbcontrol dmalloc-mark" "MSG_REQ_DMALLOC_MARK" \
		smbcontrol_ok smbd dmalloc-mark

	run_msg_test "smbcontrol dmalloc-log-changed" \
		"MSG_REQ_DMALLOC_LOG_CHANGED" \
		smbcontrol_ok smbd dmalloc-log-changed

	run_msg_test "smbcontrol idmap delete" "ID_CACHE_DELETE" \
		smbcontrol_ok smbd idmap delete "UID 0"

	run_msg_test "smbcontrol idmap kill" "ID_CACHE_KILL" \
		smbcontrol_ok smbd idmap kill "UID 0"

	run_msg_test "smbcontrol reload-config" "MSG_SMB_CONF_UPDATED" \
		smbcontrol_ok smbd reload-config

	run_msg_test "smbcontrol reload-certs" "MSG_RELOAD_TLS_CERTIFICATES" \
		smbcontrol_ok smbd reload-certs

	run_msg_test "smbcontrol ringbuf-log" "MSG_REQ_RINGBUF_LOG" \
		smbcontrol_reply "." smbd ringbuf-log

	run_msg_test "smbcontrol close-share" "MSG_SMB_FORCE_TDIS" \
		smbcontrol_ok smbd close-share "$NO_SUCH_SHARE"

	run_msg_test "smbcontrol close-denied-share" \
		"MSG_SMB_FORCE_TDIS_DENIED" \
		smbcontrol_ok smbd close-denied-share "$NO_SUCH_SHARE"

	run_msg_test "smbcontrol kill-client-ip" "MSG_SMB_KILL_CLIENT_IP" \
		smbcontrol_ok smbd kill-client-ip "$TEST_NET_1_IP"

	run_msg_test "smbcontrol sleep" "MSG_SMB_SLEEP" \
		smbcontrol_ok smbd sleep 1

	# Only the smbd parent process replies.
	run_msg_test "smbcontrol num-children" "MSG_SMB_TELL_NUM_CHILDREN" \
		smbcontrol_reply "^[0-9]+ children$" smbd num-children

	# Inject SIGHUP: reload config
	run_msg_test "smbcontrol inject hup" "MSG_SMB_INJECT_FAULT" \
		smbcontrol_ok smbd inject hup
}

# ===========================================================================
# Step 1 - verify baseline operation at legacy level 1.0
# ===========================================================================

# If the starting level is wrong the environment was not set up correctly;
# all subsequent steps would be meaningless, so abort immediately.
if ! cluster_level_show "step1: cluster level is 1.0 at startup" "1.0"; then
	failed=$((failed + 1))
	echo "FATAL: expected starting level 1.0 - aborting test" >&2
	testok "$0" "$failed"
fi

check_smb_service "step1" "1.0"

# At level 1.0 smbcontrol sends legacy messages (non NDR)
run_messaging_tests "step1" "1.0" "legacy" ""

# ===========================================================================
# Step 2 - upgrade cluster level from 1.0 to 2.0
# ===========================================================================

run_test cluster_level_upgrade \
	"step2: net clusterlevel upgrade --apply (1.0 -> 2.0)"

# Poll until the new level is reported (up to 10 s).
if ! wait_for_cluster_level "2.0"; then
	echo "Timed out waiting for cluster level 2.0" >&2
fi

# Allow a moment for the MSG_CLUSTER_LEVEL_UPGRADED broadcast to propagate to
# all running daemons (smbd, notifyd, cleanupd, etc.) so that they update
# their in-memory cached level.
sleep 2

run_test cluster_level_show \
	"step2: cluster level is 2.0 after upgrade" "2.0"

# ===========================================================================
# Step 3 - verify NDR messaging and continued SMB service at level 2.0
# ===========================================================================

# At level 2.0 smbcontrol switches to NDR-encoded messages.  A reply
# means both the sender and receiver handle the new format correctly.
run_messaging_tests "step3" "2.0" "NDR" "_V1"

check_smb_service "step3" "2.0"

testok "$0" "$failed"

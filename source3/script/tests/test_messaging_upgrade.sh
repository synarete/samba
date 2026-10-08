#!/usr/bin/env bash
#
# Test that a cluster can be upgraded from legacy messaging format (cluster
# level 0.1, pre-NDR) to NDR-based messaging (level 1.0) without interrupting
# SMB service.
#
# The clusteredmember_msg_upgrade environment starts all three nodes with
# cluster_level.tdb pre-seeded to level 0.1 so that smbd operates in
# legacy mode. Then test:
#
#  1. Verifies that all three nodes serve SMB traffic at level 0.1.
#  2. Verifies file I/O (put/get/rm) on each node at level 0.1.
#  3. Verifies that legacy messages works at level 0.1.
#  4. Runs "net clusterlevel upgrade --apply" to raise the level to 1.0.
#  5. Verifies the new level is reported by "net clusterlevel show".
#  6. Verifies that new NDR messages works fine.
#  7. Verifies file I/O (put/get/rm) on each node at level 1.0.
#  8. Verifies that all three nodes still serve SMB traffic after upgrade.
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

cd "$SELFTEST_TMPDIR" || exit 1

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
	out=$(run_as_root "$SMBCLIENT" "//$server/$SHARE" \
		-U"${DC_USERNAME}%${DC_PASSWORD}" \
		-c "put $src $src; get $src $dst; rm $src" \
		2>&1)
	local st=$?

	if [ $st -eq 0 ] && diff -q "$src" "$dst" >/dev/null 2>&1; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
		st=1
	fi
	rm -f "$src" "$dst"
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

# Send "smbcontrol <pid> pool-usage" to a smbd process on a given node.
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
	local fifo_in
	fifo_in="$SELFTEST_TMPDIR/pool_usage_in_$$"
	mkfifo "$fifo_in"

	# smbclient reads commands from $fifo_in; we hold the write end open
	# (fd 9) so it blocks waiting for input and keeps the session alive.
	run_as_root "$SMBCLIENT" "//$NODE0/$SHARE" \
		-U"${DC_USERNAME}%${DC_PASSWORD}" \
		< "$fifo_in" >/dev/null 2>&1 &
	local client_pid=$!
	exec 9>"$fifo_in"

	# Give smbd a moment to register the session.
	sleep 1

	# Discover a smbd PID on the target node via smbstatus.
	local smbd_pid
	smbd_pid=$(run_as_root "$BINDIR/smbstatus" "$CONF" \
		-p 2>/dev/null | awk '/^[0-9]/{print $1; exit}')

	if [ -z "$smbd_pid" ]; then
		# Close our end of the fifo before failing.
		exec 9>&-
		wait "$client_pid" 2>/dev/null
		rm -f "$fifo_in"
		echo "Could not find a smbd PID via smbstatus" |
			subunit_fail_test "$name"
		return 1
	fi

	# Send pool-usage while the smbclient session is still alive so that
	# smbd is guaranteed to be running when the message arrives.
	local out
	out=$(run_as_root "$SMBCONTROL" "$CONF" "$smbd_pid" pool-usage 2>&1)
	local st=$?

	# Now close our end of the fifo; smbclient will get EOF and exit.
	exec 9>&-
	wait "$client_pid" 2>/dev/null
	rm -f "$fifo_in"

	if [ $st -eq 0 ]; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
	fi
	return $st
}

# Send "smbcontrol smbd dmalloc-mark" to all smbd processes (fire-and-forget).
smbcontrol_dmalloc_mark()
{
	local name="$1"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$SMBCONTROL" "$CONF" smbd dmalloc-mark 2>&1)
	local st=$?
	if [ $st -eq 0 ]; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
	fi
	return $st
}

# Send "smbcontrol smbd dmalloc-log-changed" to all smbd processes
# (fire-and-forget).
smbcontrol_dmalloc_log_changed()
{
	local name="$1"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$SMBCONTROL" "$CONF" smbd dmalloc-log-changed 2>&1)
	local st=$?
	if [ $st -eq 0 ]; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
	fi
	return $st
}

# Send "smbcontrol smbd idmap delete <id>" to all smbd processes
# (fire-and-forget).
smbcontrol_idmap_delete()
{
	local name="$1"
	local id="$2"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$SMBCONTROL" "$CONF" smbd idmap delete "$id" 2>&1)
	local st=$?
	if [ $st -eq 0 ]; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
	fi
	return $st
}

# Send "smbcontrol smbd idmap kill <id>" to all smbd processes
# (fire-and-forget).
smbcontrol_idmap_kill()
{
	local name="$1"
	local id="$2"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$SMBCONTROL" "$CONF" smbd idmap kill "$id" 2>&1)
	local st=$?
	if [ $st -eq 0 ]; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
	fi
	return $st
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

# Send "smbcontrol smbd reload-config" to all smbd processes (fire-and-forget).
smbcontrol_reload_config()
{
	local name="$1"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$SMBCONTROL" "$CONF" smbd reload-config 2>&1)
	local st=$?
	if [ $st -eq 0 ]; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
	fi
	return $st
}

# Send "smbcontrol smbd reload-certs" to all smbd processes (fire-and-forget).
smbcontrol_reload_certs()
{
	local name="$1"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$SMBCONTROL" "$CONF" smbd reload-certs 2>&1)
	local st=$?
	if [ $st -eq 0 ]; then
		subunit_pass_test "$name"
	else
		echo "$out" | subunit_fail_test "$name"
	fi
	return $st
}

# Send "smbcontrol smbd ringbuf-log" to all smbd processes; expects at least
# one reply with log content.
smbcontrol_ringbuf_log()
{
	local name="$1"
	subunit_start_test "$name"

	local out
	out=$(run_as_root "$SMBCONTROL" "$CONF" smbd ringbuf-log 2>&1)
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

smbclient_put_get_rm \
	"step1: I/O node0 put/get/rm (level 0.1)" "$NODE0" \
	|| failed=$((failed + 1))
smbclient_put_get_rm \
	"step1: I/O node1 put/get/rm (level 0.1)" "$NODE1" \
	|| failed=$((failed + 1))
smbclient_put_get_rm \
	"step1: I/O node2 put/get/rm (level 0.1)" "$NODE2" \
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

smbcontrol_pool_usage \
	"step1: smbcontrol pool-usage (legacy MSG_REQ_POOL_USAGE at level 0.1)" \
	|| failed=$((failed + 1))

smbcontrol_dmalloc_mark \
	"step1: smbcontrol dmalloc-mark (legacy MSG_REQ_DMALLOC_MARK at level 0.1)" \
	|| failed=$((failed + 1))

smbcontrol_dmalloc_log_changed \
	"step1: smbcontrol dmalloc-log-changed (legacy MSG_REQ_DMALLOC_LOG_CHANGED at level 0.1)" \
	|| failed=$((failed + 1))

smbcontrol_idmap_delete \
	"step1: smbcontrol idmap delete (legacy ID_CACHE_DELETE at level 0.1)" \
	"UID 0" || failed=$((failed + 1))

smbcontrol_idmap_kill \
	"step1: smbcontrol idmap kill (legacy ID_CACHE_KILL at level 0.1)" \
	"UID 0" || failed=$((failed + 1))

smbcontrol_reload_config \
	"step1: smbcontrol reload-config (legacy MSG_SMB_CONF_UPDATED at level 0.1)" \
	|| failed=$((failed + 1))

smbcontrol_reload_certs \
	"step1: smbcontrol reload-certs (legacy MSG_RELOAD_TLS_CERTIFICATES at level 0.1)" \
	|| failed=$((failed + 1))

smbcontrol_ringbuf_log \
	"step1: smbcontrol ringbuf-log (legacy MSG_REQ_RINGBUF_LOG at level 0.1)" \
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

smbcontrol_pool_usage \
	"step3: smbcontrol pool-usage (NDR MSG_REQ_POOL_USAGE_V1 at level 1.0)" \
	|| failed=$((failed + 1))

smbcontrol_dmalloc_mark \
	"step3: smbcontrol dmalloc-mark (NDR MSG_REQ_DMALLOC_MARK_V1 at level 1.0)" \
	|| failed=$((failed + 1))

smbcontrol_dmalloc_log_changed \
	"step3: smbcontrol dmalloc-log-changed (NDR MSG_REQ_DMALLOC_LOG_CHANGED_V1 at level 1.0)" \
	|| failed=$((failed + 1))

smbcontrol_idmap_delete \
	"step3: smbcontrol idmap delete (NDR ID_CACHE_DELETE_V1 at level 1.0)" \
	"UID 0" || failed=$((failed + 1))

smbcontrol_idmap_kill \
	"step3: smbcontrol idmap kill (NDR ID_CACHE_KILL_V1 at level 1.0)" \
	"UID 0" || failed=$((failed + 1))

smbcontrol_reload_config \
	"step3: smbcontrol reload-config (NDR MSG_SMB_CONF_UPDATED_V1 at level 1.0)" \
	|| failed=$((failed + 1))

smbcontrol_reload_certs \
	"step3: smbcontrol reload-certs (NDR MSG_RELOAD_TLS_CERTIFICATES_V1 at level 1.0)" \
	|| failed=$((failed + 1))

smbcontrol_ringbuf_log \
	"step3: smbcontrol ringbuf-log (NDR MSG_REQ_RINGBUF_LOG_V1 at level 1.0)" \
	|| failed=$((failed + 1))

# Verify smbd is alive and file I/O works
smbclient_ls "step3: smbclient node0 (level 1.0)" "$NODE0" \
	|| failed=$((failed + 1))
smbclient_ls "step3: smbclient node1 (level 1.0)" "$NODE1" \
	|| failed=$((failed + 1))
smbclient_ls "step3: smbclient node2 (level 1.0)" "$NODE2" \
	|| failed=$((failed + 1))

smbclient_put_get_rm \
	"step3: I/O node0 put/get/rm (level 1.0)" "$NODE0" \
	|| failed=$((failed + 1))
smbclient_put_get_rm \
	"step3: I/O node1 put/get/rm (level 1.0)" "$NODE1" \
	|| failed=$((failed + 1))
smbclient_put_get_rm \
	"step3: I/O node2 put/get/rm (level 1.0)" "$NODE2" \
	|| failed=$((failed + 1))

testok "$0" "$failed"

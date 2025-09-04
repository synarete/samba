#!/usr/bin/env bash
#
# Test VFS module aio_ratelimit

SELF=$(basename "$0")
if [ $# -lt 6 ]; then
	echo Usage: "${SELF}" SERVERCONFFILE SMBCLIENT \
		SERVER LOCAL_PATH PREFIX SHARENAME
	exit 1
fi

CONF="$1"
SMBCLIENT="$2"
SERVER="$3"
LOCAL_PATH="$4"
PREFIX="$5"
SHARE="$6"

# Do not let deprecated option warnings muck this up
SAMBA_DEPRECATED_SUPPRESS=1
export SAMBA_DEPRECATED_SUPPRESS

incdir="$(dirname "$0")/../../../testprogs/blackbox"
. $incdir/subunit.sh

failed=0
sharedir="${LOCAL_PATH}/${SHARE}"

# Prepare
cd $SELFTEST_TMPDIR || exit 1

# Sub tests
test_aio_ratelimit()
{
	local testfile="${FUNCNAME[0]}"
	local src="${LOCAL_PATH}/${testfile}-src"
	local dst="${testfile}-dst"
	local tgt="${testfile}-tgt"
	local secs

	# Create source file
	dd if=/dev/urandom of="${src}" bs=1M count=1
	stat "$src"

	# Write
	CLI_FORCE_INTERACTIVE=1 ${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} \
		-U${USER}%${PASSWORD} -c "put ${src} ${dst}"
	ret=$?
	if [ $ret != 0 ]; then
		printf "failed to write file: %s\n" "${ret}"
		return 1
	fi

	# Read multiple times
	for i in {1..10}; do
		CLI_FORCE_INTERACTIVE=1 \
			${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} \
			-U${USER}%${PASSWORD} -c "get ${dst} ${tgt}"
		ret=$?
		if [ $ret != 0 ]; then
			printf "failed to read file: %s\n" "${ret}"
			return 1
		fi
	done

	# Expect a forced-delay
	secs=$((SECONDS - secs))
	if [ ${secs} -lt 10 ]; then
		printf "no delay: elapsed-secs=%d\n" "${secs}"
		return 1
	fi

	# Delete
	CLI_FORCE_INTERACTIVE=1 ${SMBCLIENT} //${SERVER}/${SHARE} ${CONF} \
	    -U${USER}%${PASSWORD} -c "del ${dst}"
	ret=$?
	if [ $ret != 0 ]; then
		printf "failed to delete file: %s\n" "${ret}"
		return 1
	fi

	# Cleanups
	rm -f "${src}" "${tgt}"
}

# Actual tests
testit "test_aio_ratelimit" \
	test_aio_ratelimit ||
	failed=$(expr $failed + 1)

testok $0 $failed

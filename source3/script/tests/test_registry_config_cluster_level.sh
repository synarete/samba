#!/bin/sh
#
# Blackbox tests for loading the registry configuration before the
# level of the cluster is known.
#
# db_open_ex() activates the oldest cluster level while
# lp_smbconf_ctx() opens registry.tdb, which forgets it again and the
# level of the cluster is activated afterwards. Requires a running
# CTDB cluster (clusteredmember selftest environment).
#
# Usage:
#   test_registry_config_cluster_level.sh NET CONFIGURATION
#

if [ $# -lt 2 ]; then
	cat <<EOF
Usage: test_registry_config_cluster_level.sh NET CONFIGURATION
EOF
	exit 1
fi

NET="$1"
CONFIGURATION="$2"

incdir=$(dirname $0)/../../../testprogs/blackbox
. "$incdir/subunit.sh"

failed=0

SMB_CONF="${CONFIGURATION#--configfile=}"
TMP_CONF="$(dirname "$SMB_CONF")/registry_config_cluster_level.conf"

#
# Only the [global] section of the configuration of the environment,
# which has 'include = registry' after 'clustering = yes'.
#
global_section()
{
	awk '/^[[:space:]]*\[/ && !/^[[:space:]]*\[global\]/ {exit} {print}' \
		"$SMB_CONF"
}

run_net()
{
	UID_WRAPPER_ROOT=1 UID_WRAPPER_INITIAL_RUID=0 UID_WRAPPER_INITIAL_EUID=0 \
		$NET --configfile="$TMP_CONF" "$@"
}

test_setparm()
{
	run_net conf setparm global "server string" "cluster level test"
}

test_getparm()
{
	local out

	out=$(run_net conf getparm global "server string")
	if [ $? -ne 0 ]; then
		echo "FAIL: net conf getparm failed: $out"
		return 1
	fi
	if [ "$out" != "cluster level test" ]; then
		echo "FAIL: net conf getparm returned '$out'"
		return 1
	fi

	return 0
}

test_delparm()
{
	run_net conf delparm global "server string"
}

#
# A registry.tdb not using ctdb, opened before messaging can be
# initialized.
#
global_section | \
	sed 's/^\([[:space:]]*clustering = yes\)$/\1\n\tctdb:registry.tdb = no/' \
	> "$TMP_CONF"

testit "local registry: setparm" test_setparm ||
	failed=$(expr $failed + 1)
testit "local registry: list" run_net conf list ||
	failed=$(expr $failed + 1)
testit "local registry: getparm" test_getparm ||
	failed=$(expr $failed + 1)
testit_grep "local registry: clusterlevel show" "active_level" \
	run_net clusterlevel show --json ||
	failed=$(expr $failed + 1)
testit "local registry: delparm" test_delparm ||
	failed=$(expr $failed + 1)

#
# 'include = registry' before 'clustering = yes', the registry
# configuration is loaded before clustering is known.
#
global_section | \
	sed '/^[[:space:]]*include = registry$/d' | \
	sed 's/^\([[:space:]]*clustering = yes\)$/\tinclude = registry\n\1/' \
	> "$TMP_CONF"

testit "include before clustering: list" run_net conf list ||
	failed=$(expr $failed + 1)
testit_grep "include before clustering: clusterlevel show" "active_level" \
	run_net clusterlevel show --json ||
	failed=$(expr $failed + 1)

rm -f "$TMP_CONF"

testok $0 $failed

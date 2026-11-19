#!/usr/bin/env bash
#
# Run the cluster rolling upgrade messaging selftests.
#
# The rolling upgrade suite checks smbcontrol messaging (ping, debug,
# debuglevel, profile, profilelevel) at the old cluster functional level, on
# a mixed-version cluster while nodes are being upgraded, and at the new
# level after the upgrade.  Messages cross between the stable and the build
# under test during the mixed phase.
#
# This script:
#   1. builds (or reuses a cached) stable Samba release that the current tree
#      upgrades from,
#   2. builds the current tree,
#   3. runs the messaging test suite with SELFTEST_LATEST_STABLE_BINDIR pointing
#      at the stable binaries.
#
# Steps in the suite share one cluster and run in name order, so the suite is
# always run as a whole.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEFAULT_TESTS="samba3.blackbox.cluster_rolling_upgrade"
DEFAULT_CACHE_DIR="${HOME}/.cache/samba-cfl-messaging-stable"

TESTS="${DEFAULT_TESTS}"
STABLE_REF="${SAMBA_LATEST_STABLE_REF:-}"
STABLE_BINDIR=""
CACHE_DIR="${DEFAULT_CACHE_DIR}"
REBUILD_STABLE=0
SKIP_BUILD=0
JOBS="$(nproc)"
VERBOSE=0
TEST_OPTIONS=()

usage() {
	cat <<EOF
Usage: $(basename "$0") [OPTIONS] [TESTS]

Run the cluster rolling upgrade messaging tests (smbcontrol ping, debug,
debuglevel, profile, profilelevel) across a stable -> current upgrade.

Options:
  -t, --tests=NAME          Test suite to run (default: ${DEFAULT_TESTS})
  -s, --stable-ref=REF      Stable git ref/branch (default: auto-detected from VERSION)
  -b, --stable-bindir=DIR   Use existing pre-built stable bin directory (skips clone/build)
  -c, --cache-dir=DIR       Directory to cache the stable build (default: ${DEFAULT_CACHE_DIR})
  -r, --rebuild-stable      Force re-export and rebuild of the stable branch
      --skip-build          Skip building the current tree
  -j, --jobs=N              Parallel make jobs (default: nproc)
  -v, --verbose             Verbose output (shell tracing)
      --valgrind            Pass --valgrind to selftest
      --fail-immediately    Pass --fail-immediately to selftest
      --socket-wrapper-pcap Pass --socket-wrapper-pcap to selftest
      --filter-subunit      Pass --filtered-subunit to selftest
  -h, --help                Show usage information

Environment:
  SAMBA_LATEST_STABLE_REF   Same as --stable-ref
EOF
}

log() {
	echo "[cfl-messaging] $*"
}

die() {
	echo "[cfl-messaging] ERROR: $*" >&2
	exit 1
}

parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
		-t) TESTS="$2"; shift 2 ;;
		--tests=*) TESTS="${1#*=}"; shift ;;
		-s) STABLE_REF="$2"; shift 2 ;;
		--stable-ref=*) STABLE_REF="${1#*=}"; shift ;;
		-b) STABLE_BINDIR="$2"; shift 2 ;;
		--stable-bindir=*) STABLE_BINDIR="${1#*=}"; shift ;;
		-c) CACHE_DIR="$2"; shift 2 ;;
		--cache-dir=*) CACHE_DIR="${1#*=}"; shift ;;
		-r|--rebuild-stable) REBUILD_STABLE=1; shift ;;
		--skip-build) SKIP_BUILD=1; shift ;;
		-j) JOBS="$2"; shift 2 ;;
		--jobs=*) JOBS="${1#*=}"; shift ;;
		-v|--verbose) VERBOSE=1; shift ;;
		--valgrind) TEST_OPTIONS+=("--valgrind"); shift ;;
		--fail-immediately) TEST_OPTIONS+=("--fail-immediately"); shift ;;
		--socket-wrapper-pcap) TEST_OPTIONS+=("--socket-wrapper-pcap"); shift ;;
		--filter-subunit) TEST_OPTIONS+=("--filtered-subunit"); shift ;;
		-h|--help) usage; exit 0 ;;
		--) shift; break ;;
		-*) die "unknown option: $1 (see --help)" ;;
		*) TESTS="$1"; shift ;;
		esac
	done
}

check_prerequisites() {
	local tool
	for tool in git python3 make gcc awk sed tar; do
		command -v "${tool}" >/dev/null 2>&1 || die "missing prerequisite: ${tool}"
	done
}

# Resolve the highest vX-Y-stable branch older than VERSION, matching
# script/autobuild.py:latest_stable_fetch().
detect_stable_ref() {
	local major minor ref

	major=$(sed -n 's/^SAMBA_VERSION_MAJOR=//p' "${SRC_DIR}/VERSION")
	minor=$(sed -n 's/^SAMBA_VERSION_MINOR=//p' "${SRC_DIR}/VERSION")
	[ -n "${major}" ] && [ -n "${minor}" ] || die "cannot read version from VERSION"

	ref=$(git -C "${SRC_DIR}" for-each-ref --format='%(refname)' \
		'refs/remotes/*/v*-*-stable' 'refs/heads/v*-*-stable' |
		sed -n 's|^.*/v\([0-9]*\)-\([0-9]*\)-stable$|\1 \2|p' |
		awk -v M="${major}" -v N="${minor}" \
			'$1 < M || ($1 == M && $2 < N)' |
		sort -n -k1,1 -k2,2 | tail -n 1 |
		awk '{ printf "v%d-%d-stable", $1, $2 }')

	[ -n "${ref}" ] || die "no stable branch older than ${major}.${minor}"
	echo "${ref}"
}

# Map a branch name to a commit, trying the usual remote-tracking names.
resolve_stable_commit() {
	local name="$1" candidate

	for candidate in "${name}" "origin/${name}" "samba-devel/${name}"; do
		if git -C "${SRC_DIR}" rev-parse --verify --quiet "${candidate}^{commit}" >/dev/null; then
			echo "${candidate}"
			return 0
		fi
	done
	die "stable ref not found in this repository: ${name}"
}

build_stable() {
	local stable_src="$1" commit

	if [ -z "${STABLE_REF}" ]; then
		STABLE_REF="$(detect_stable_ref)"
	fi
	commit="$(resolve_stable_commit "${STABLE_REF}")"
	log "stable ref: ${STABLE_REF} (${commit})"

	rm -rf "${stable_src}"
	mkdir -p "${stable_src}"
	git -C "${SRC_DIR}" archive --format=tar "${commit}" | tar -x -C "${stable_src}"

	# cmocka is bundled because the system cmocka (2.x) dropped macros the
	# stable tree's unit tests use.  Matches the current tree's configuration.
	log "configuring stable tree in ${stable_src}"
	(
		cd "${stable_src}"
		./configure.developer "--prefix=${CACHE_DIR}/install" \
			--with-cluster-support \
			--with-profiling-data \
			--with-prometheus-exporter \
			--bundled-libraries=cmocka
		make -j"${JOBS}"
	)
}

verify_bins() {
	local bindir="$1"
	[ -x "${bindir}/smbd" ] || die "missing ${bindir}/smbd"
	[ -x "${bindir}/ctdb" ] || die "missing ${bindir}/ctdb"
}

resolve_stable() {
	local stable_src="${CACHE_DIR}/src"

	if [ -n "${STABLE_BINDIR}" ]; then
		[ -d "${STABLE_BINDIR}" ] || die "stable bindir not found: ${STABLE_BINDIR}"
		STABLE_BINDIR="$(cd "${STABLE_BINDIR}" && pwd)"
		log "using pre-built stable bindir: ${STABLE_BINDIR}"
	else
		if [ "${REBUILD_STABLE}" -eq 1 ] || [ ! -x "${stable_src}/bin/smbd" ]; then
			build_stable "${stable_src}"
		else
			log "reusing cached stable build: ${stable_src}"
		fi
		STABLE_BINDIR="${stable_src}/bin"
	fi
	verify_bins "${STABLE_BINDIR}"
}

build_current() {
	if [ "${SKIP_BUILD}" -eq 1 ]; then
		log "skipping current tree build (--skip-build)"
	else
		log "building current tree"
		(cd "${SRC_DIR}" && make -j"${JOBS}")
	fi
	verify_bins "${SRC_DIR}/bin"
}

run_tests() {
	local opts="${TEST_OPTIONS[*]-}"

	log "running messaging tests: ${TESTS}"
	cd "${SRC_DIR}"
	export SELFTEST_LATEST_STABLE_BINDIR="${STABLE_BINDIR}"
	make test TESTS="${TESTS}" TEST_OPTIONS="${opts}"
}

main() {
	parse_args "$@"
	if [ "${VERBOSE}" -eq 1 ]; then
		set -x
	fi
	check_prerequisites
	resolve_stable
	build_current
	run_tests
}

main "$@"

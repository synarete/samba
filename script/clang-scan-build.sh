#!/bin/bash
# Developer's helper script to run LLVM[1] static-code analyzer. Requires clang
# and scan-build to be installed on local build machine. See scan-build[2] doc
# for more details. For full list of available checkrs, run:
#
#  $ clang -cc1 -analyzer-checker-help
#
# [1] https://llvm.org/
# [2] https://clang.llvm.org/docs/analyzer/user-docs/CommandLineUsage.html#scan-build

# Prerequisites
command -v clang || (echo "can not locate clang" && exit 1)
command -v clang++ || (echo "can not locate clang++" && exit 2)
command -v scan-build || (echo "can not locate scan-build" && exit 3)

# Environment variables
LC_ALL=C
LANG=C
LANGUAGE=C
export LC_ALL LANG LANGUAGE
CC="$(command -v clang)"
CXX="$(command -v clang++)"
CCC_CC="${CC}"
CCC_CXX="${CXX}"
export CC CXX CCC_CC CCC_CXX

# Execute scan-build from project's root dir
set -u
set -e
umask 0022
self="${BASH_SOURCE[0]}"
selfdir=$(dirname "${self}")
root="$(realpath "${selfdir}/../")"
prefix="${root}/bin/scan-build/"
outdir="${prefix}/html/"

cd "${root}"
mkdir -p "${outdir}"
scan-build \
	--use-cc="${CCC_CC}" \
	--use-c++="${CCC_CXX}" \
	./configure \
	--prefix="${prefix}" \

scan-build \
	--use-cc="${CCC_CC}" \
	--use-c++="${CCC_CXX}" \
	-maxloop 10 \
	-k -v -o "${outdir}" \
	-enable-checker core.BitwiseShift \
	-enable-checker core.CallAndMessage \
	-enable-checker core.DivideZero \
	-enable-checker core.NonNullParamChecker \
	-enable-checker core.NullDereference \
	-enable-checker core.StackAddressEscape \
	-enable-checker core.UndefinedBinaryOperatorResult \
	-enable-checker core.VLASize \
	-enable-checker core.uninitialized.ArraySubscript \
	-enable-checker core.uninitialized.Assign \
	-enable-checker core.uninitialized.Branch \
	-enable-checker core.uninitialized.CapturedBlockVariable \
	-enable-checker core.uninitialized.NewArraySize \
	-enable-checker core.uninitialized.UndefReturn \
	-enable-checker deadcode.DeadStores \
	-enable-checker nullability.NullPassedToNonnull \
	-enable-checker nullability.NullReturnedFromNonnull \
	-enable-checker nullability.NullableDereferenced \
	-enable-checker nullability.NullablePassedToNonnull \
	-enable-checker nullability.NullableReturnedFromNonnull \
	-enable-checker security.FloatLoopCounter \
	-enable-checker security.cert.env.InvalidPtr \
	-enable-checker security.insecureAPI.UncheckedReturn \
	-enable-checker security.insecureAPI.bcmp \
	-enable-checker security.insecureAPI.bcopy \
	-enable-checker security.insecureAPI.bzero \
	-enable-checker security.insecureAPI.decodeValueOfObjCType \
	-enable-checker security.insecureAPI.getpw \
	-enable-checker security.insecureAPI.gets \
	-enable-checker security.insecureAPI.mkstemp \
	-enable-checker security.insecureAPI.mktemp \
	-enable-checker security.insecureAPI.rand \
	-enable-checker security.insecureAPI.vfork \
	-enable-checker unix.API \
	-enable-checker unix.Errno \
	-enable-checker unix.Malloc \
	-enable-checker unix.MallocSizeof \
	-enable-checker unix.MismatchedDeallocator \
	-enable-checker unix.StdCLibraryFunctions \
	-enable-checker unix.Vfork \
	-enable-checker unix.cstring.BadSizeArg \
	-enable-checker unix.cstring.NullArg \
	-enable-checker valist.CopyToSelf \
	-enable-checker valist.Uninitialized \
	-enable-checker valist.Unterminated \
	make all

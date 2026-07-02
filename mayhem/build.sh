#!/usr/bin/env bash
#
# cups/mayhem/build.sh — build OpenPrinting/cups's OSS-Fuzz harnesses as sanitized libFuzzer
# targets (+ standalone reproducers), AND cups' own self-contained unit tests for mayhem/test.sh.
#
# This is the FULL CUPS printing system (distinct from the libcups library repo). The fuzzed
# surface is attacker-controlled bytes into CUPS' C parsers:
#   fuzz_ipp               — IPP message wire format via ippReadIO() (cups/ipp.c).
#   fuzz_ipp_gen           — IPP wire format via ippReadIO() into request+response objects.
#   fuzz_raster            — CUPS raster page headers via cupsRasterReadHeader2() (cups/raster.c).
#   fuzz_cups              — PostScript page-setup interpreter _cupsRasterExecPS() (raster-interpret.c).
#   fuzz_ppd_gen_1         — PPD file parser ppdOpenFile() + ppdMarkDefaults/ppdConflicts (cups/ppd*.c).
#   fuzz_ppd_gen_conflicts — PPD parser + cupsParseOptions/cupsGetConflicts/cupsResolveConflicts.
#   fuzz_ppd_gen_cache     — PPD parser + _ppdCacheCreateWithPPD/_ppdCacheWriteFile cache round-trip.
#   fuzz_array             — cups_array_t API (cups/array.c) driven through a FuzzedDataProvider.
#   fuzz_http_core         — HTTP URI/field/base64/addr helpers (cups/http*.c) on a segmented input.
#
# Harnesses come from OpenPrinting/fuzzing (the upstream OSS-Fuzz fuzzer repo); they are vendored
# into mayhem/harnesses/ so the build is self-contained (no network clone at image-build time).
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN/OUT). We build the cups libraries THEMSELVES with $SANITIZER_FLAGS so the
# parsed code (not just the harness) is instrumented.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: explicit DWARF-3 so Mayhem's triage can read symbols (clang-19 defaults to DWARF-5).
# Placed after $SANITIZER_FLAGS in every compile so it is never shadowed.
: "${DEBUG_FLAGS:=-gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${OUT:=/mayhem}"
: "${SRC:=/mayhem}"

# ── Benign-UB relaxation (build.sh only) ───────────────────────────────────────────────────────
# CUPS' IPP/PPD/raster/string parsers deliberately use idioms that trip UBSan on essentially every
# input, drowning out any real bug (same set the sibling libcups repo relaxes):
#   * ipp.c / raster.c: request_id = (buffer[0] << 24) | ...  -> shift / signed-integer-overflow
#   * string.c:         casts an arbitrary input buffer for the string interning pool -> alignment
#   * array.c:          calls a typed comparator through a generic fn pointer          -> function
# Upstream OSS-Fuzz builds CUPS with sanitizers: address, memory (UBSan is NOT in the halting set).
# We keep ASan + the meaningful UBSan checks (null deref, bounds, etc.) HALTING and disable only this
# set of well-known benign checks so the harness reaches real parser code instead of crashing at byte 0.
UBSAN_RELAX="function,alignment,shift,signed-integer-overflow,unsigned-integer-overflow,implicit-integer-sign-change,enum,nonnull-attribute,returns-nonnull-attribute"
case "$SANITIZER_FLAGS" in
  *undefined*) SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=$UBSAN_RELAX" ;;
esac

# -fsanitize=fuzzer-no-link lets the instrumented library collect coverage feedback for libFuzzer.
case "$SANITIZER_FLAGS" in
  *fuzzer-no-link*) : ;;
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" ;;
esac

# CUPS' fuzz harnesses include private headers and use deprecated APIs; mirror the upstream
# OSS-Fuzz build's defines and relax the warnings-as-errors the modern toolchain would raise.
EXTRA_CFLAGS="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fPIE \
-Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=int-conversion"

export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN MAYHEM_JOBS OUT SRC

cd "$SRC"
git config --global --add safe.directory "$SRC" 2>/dev/null || true

# ── 1) Build the CUPS libraries (static, sanitized) ────────────────────────────────────────────
export CFLAGS="${CFLAGS:-} $SANITIZER_FLAGS $DEBUG_FLAGS $EXTRA_CFLAGS"
export CXXFLAGS="${CXXFLAGS:-} $SANITIZER_FLAGS $DEBUG_FLAGS $EXTRA_CFLAGS"
export LDFLAGS="${LDFLAGS:-} $SANITIZER_FLAGS -fPIE"

./configure --enable-static --disable-shared --with-tls=openssl
# Build ONLY the cups/ library subdir (libcups.a + libcupsimage.a — everything the harnesses link
# against). A full top-level `make` also compiles build-time codegen helpers in ppdc/ (genstrings,
# ppdc, …) with our halting sanitizers; those crash on benign UBSan findings (e.g. a NULL passed to
# a __nonnull memcpy in ppdc-array.cxx) and abort the whole build before any library is produced.
make -C cups libs -j"$MAYHEM_JOBS"

LIBCUPS="$SRC/cups/libcups.a"
LIBCUPSIMAGE="$SRC/cups/libcupsimage.a"
[ -f "$LIBCUPS" ]      || { echo "ERROR: $LIBCUPS not built" >&2; exit 1; }
[ -f "$LIBCUPSIMAGE" ] || { echo "ERROR: $LIBCUPSIMAGE not built" >&2; exit 1; }

# ── 2) Build each OSS-Fuzz harness: libFuzzer (-> $OUT/<name>) + standalone reproducer ──────────
# Include paths + link libs mirror OpenPrinting/fuzzing's fuzzer/Makefile.
HDIR="$SRC/mayhem/harnesses"
INC="-I$SRC -I$SRC/cups"
HARNESS_CFLAGS="-D_CUPS_SOURCE -D_REENTRANT -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_THREAD_SAFE \
-Wno-deprecated-declarations -Wno-unused-result $DEBUG_FLAGS $EXTRA_CFLAGS"

AVAHI_LIBS="$(pkg-config --libs avahi-client 2>/dev/null || echo '-lavahi-client -lavahi-common')"
DBUS_LIBS="$(pkg-config --libs dbus-1 2>/dev/null || echo '-ldbus-1')"
LINK_LIBS="-L$SRC/cups -lcups -lcupsimage -lz -lpthread $AVAHI_LIBS $DBUS_LIBS -lssl -lcrypto -lcrypt -lsystemd -lm"

# fuzz_helpers.cpp provides the FuzzedDataProvider glue that fuzz_array links against.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $INC $HARNESS_CFLAGS -c "$HDIR/fuzz_helpers.cpp" -o "$SRC/mayhem/fuzz_helpers.o"

# Standalone driver object (no libFuzzer runtime; reads one input file at a time).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $INC -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/mayhem/standalone_main.o"

HARNESSES="fuzz_ipp fuzz_ipp_gen fuzz_raster fuzz_cups fuzz_ppd_gen_1 fuzz_ppd_gen_conflicts fuzz_ppd_gen_cache fuzz_array fuzz_http_core"
for harness in $HARNESSES; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $INC $HARNESS_CFLAGS -c "$HDIR/$harness.c" -o "$SRC/mayhem/$harness.o"

  # libFuzzer target -> $OUT/<name>  (link with CXX: fuzz_helpers.o is C++)
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$SRC/mayhem/$harness.o" "$SRC/mayhem/fuzz_helpers.o" \
       $LINK_LIBS -o "$OUT/$harness"

  # standalone reproducer (no libFuzzer runtime) -> $OUT/<name>-standalone
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$SRC/mayhem/$harness.o" "$SRC/mayhem/fuzz_helpers.o" "$SRC/mayhem/standalone_main.o" \
       $LINK_LIBS -o "$OUT/$harness-standalone"

  echo "built $harness (+ standalone)"
done

# ── 3) Build cups' OWN unit tests with NORMAL flags in a CLEAN tree so test.sh only RUNS them. ──
# Keep test.sh an honest PATCH oracle: no sanitizers (ASan/LSan would flag benign leaks in the test
# harnesses as failures even though every assertion passes) and no benign-UB noise. A separate copy
# of the source guarantees the sanitized objects from step 1 are NOT reused.
if [ "${SKIP_TESTS:-0}" != "1" ]; then
  TESTTREE="$SRC/mayhem-tests"
  rm -rf "$TESTTREE"
  mkdir -p "$TESTTREE"
  cp -a "$SRC/." "$TESTTREE/" 2>/dev/null || true
  rm -rf "$TESTTREE/mayhem-tests"
  (
    cd "$TESTTREE"
    make distclean >/dev/null 2>&1 || make clean >/dev/null 2>&1 || true
    env -u CFLAGS -u CXXFLAGS -u LDFLAGS -u SANITIZER_FLAGS \
      ./configure --enable-static --disable-shared --enable-unit-tests --with-tls=openssl >/dev/null
    # Build only the cups/ libraries (libcups.a + libcupsimage.a the test programs link against),
    # then ONLY the specific unit-test binaries mayhem/test.sh runs. We deliberately do NOT build the
    # full `unittests` target: it also links testoauth/testcreds/testdest/… which either need network
    # symbols or fail to link against the static lib (e.g. testoauth references cupsOAuth*/cupsJWT*
    # that aren't in libcups.a), and one bad link aborts the whole make before our tests are built.
    env -u CFLAGS -u CXXFLAGS -u LDFLAGS -u SANITIZER_FLAGS make -C cups libs -j"$MAYHEM_JOBS"
    # Build each unit-test binary independently so a single link failure does not abort the rest
    # (`make -C cups <t>` for a list stops at the first error; a per-target loop keeps going).
    for t in testarray testfile testform testi18n testipp testjson testjwt \
             testoptions testppd testpwg testraster; do
      env -u CFLAGS -u CXXFLAGS -u LDFLAGS -u SANITIZER_FLAGS \
        make -C cups -j"$MAYHEM_JOBS" "$t" \
        || echo "WARNING: unit test $t failed to build (test.sh will skip it)" >&2
    done
  ) || echo "WARNING: unittests build failed (test.sh will report)" >&2
fi

echo "build.sh complete:"
for h in $HARNESSES; do ls -la "$OUT/$h" 2>&1 || true; done

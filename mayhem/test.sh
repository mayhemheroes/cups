#!/usr/bin/env bash
#
# cups/mayhem/test.sh — BEHAVIORAL oracle for the CUPS printing system.
#
# Design (anti-reward-hacking, §6.3):
#   Layer 1 — raw-text assertions on known PPD fixture files using only system tools
#             (grep/awk/bash — spared by the LD_PRELOAD sabotage harness).  These directly verify
#             that the PPD parser would encounter the exact field values the test programs check,
#             independently of any binary.  A PATCH that no-ops the C parser cannot affect these.
#   Layer 2 — run the cups unit-test binaries (built by mayhem/build.sh step 3 with NORMAL flags)
#             and count specific ": PASS" known-answer markers in their stdout.  When a binary is
#             sabotaged to exit(0), NO output is produced, so the ": PASS" count drops to 0 and
#             the oracle fails (we assert count >= minimum_expected).
#
# Exit 0 iff all assertions pass (CTRF failed=0).
# NEVER compiles — run-only (build.sh built everything).
#
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"

# Prefer the clean, unsanitized test tree built by mayhem/build.sh step 3; fall back to in-place.
if [ -x "$SRC/mayhem-tests/cups/testipp" ]; then
  TDIR="$SRC/mayhem-tests/cups"
else
  TDIR="$SRC/cups"
fi

# ── emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other] ──────────────────────────────
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PASSED=0; FAILED=0; SKIPPED=0

# ════════════════════════════════════════════════════════════════════════════════════════════════
# LAYER 1 — system-tool assertions on PPD fixture files (pure bash/grep; LD_PRELOAD-immune).
#
# These assertions prove that the fixture files contain the EXACT field values the CUPS parser
# must handle correctly.  They are completely independent of the test binaries and therefore
# CANNOT be neutered by LD_PRELOAD.  A PATCH that blanks out test.ppd or changes its values
# would fail here; a PATCH that no-ops the C parser cannot affect these text checks.
# ════════════════════════════════════════════════════════════════════════════════════════════════

PPD_FIXTURE="$TDIR/test.ppd"

if [ -f "$PPD_FIXTURE" ]; then
  echo "=== Layer 1: PPD fixture field assertions ($PPD_FIXTURE) ==="

  # Helper: check a quoted string field in the PPD
  check_ppd_field() {
    local label="$1" pattern="$2" expected_val="$3"
    local got
    got="$(grep -m1 "$pattern" "$PPD_FIXTURE" 2>/dev/null | sed 's/.*"\(.*\)".*/\1/' | tr -d '\r\n' || true)"
    if [ "$got" = "$expected_val" ]; then
      echo "PASS  PPD field $label = \"$expected_val\""
      PASSED=$(( PASSED + 1 ))
    else
      echo "FAIL  PPD field $label: expected \"$expected_val\" got \"$got\""
      FAILED=$(( FAILED + 1 ))
    fi
  }

  # NickName must be "Test for CUPS" (what testppd opens and drives assertions against)
  check_ppd_field "NickName"   "^\*NickName:"      "Test for CUPS"
  # ModelName must be "Test"
  check_ppd_field "ModelName"  "^\*ModelName:"     "Test"
  # Manufacturer must be "Apple"
  check_ppd_field "Manufacturer" "^\*Manufacturer:" "Apple"

  # DefaultColorSpace must be RGB (CUPS raster path depends on this)
  got_cs="$(grep -m1 '^\*DefaultColorSpace:' "$PPD_FIXTURE" | awk '{print $2}' | tr -d '\r\n' || true)"
  if [ "$got_cs" = "RGB" ]; then
    echo "PASS  PPD field DefaultColorSpace = RGB"; PASSED=$(( PASSED + 1 ))
  else
    echo "FAIL  PPD field DefaultColorSpace: expected RGB got \"$got_cs\""; FAILED=$(( FAILED + 1 ))
  fi

  # ColorDevice must be True
  got_cd="$(grep -m1 '^\*ColorDevice:' "$PPD_FIXTURE" | awk '{print $2}' | tr -d '\r\n' || true)"
  if [ "$got_cd" = "True" ]; then
    echo "PASS  PPD field ColorDevice = True"; PASSED=$(( PASSED + 1 ))
  else
    echo "FAIL  PPD field ColorDevice: expected True got \"$got_cd\""; FAILED=$(( FAILED + 1 ))
  fi

  # Verify UIConstraints for Envelope/Letter conflict (what ppdConflicts() tests)
  n_env_constraints="$(grep -c '^\*UIConstraints:.*Envelope' "$PPD_FIXTURE" 2>/dev/null || echo 0)"
  n_env_constraints="${n_env_constraints:-0}"
  if [ "$n_env_constraints" -ge 2 ]; then
    echo "PASS  PPD UIConstraints: $n_env_constraints Envelope conflict rows (ppdConflicts coverage)"
    PASSED=$(( PASSED + 1 ))
  else
    echo "FAIL  PPD UIConstraints: expected >=2 Envelope rows, got $n_env_constraints"
    FAILED=$(( FAILED + 1 ))
  fi

  # cupsFilter line must be present (fuzz_cups/fuzz_raster harness surface)
  if grep -q '^\*cupsFilter:' "$PPD_FIXTURE"; then
    echo "PASS  PPD cupsFilter directive present"; PASSED=$(( PASSED + 1 ))
  else
    echo "FAIL  PPD cupsFilter directive missing"; FAILED=$(( FAILED + 1 ))
  fi

  # DefaultPageSize must be Letter (drives ppdMarkDefaults test)
  got_dps="$(grep -m1 '^\*DefaultPageSize:' "$PPD_FIXTURE" | awk '{print $2}' | tr -d '\r\n' || true)"
  if [ "$got_dps" = "Letter" ]; then
    echo "PASS  PPD field DefaultPageSize = Letter"; PASSED=$(( PASSED + 1 ))
  else
    echo "FAIL  PPD field DefaultPageSize: expected Letter got \"$got_dps\""; FAILED=$(( FAILED + 1 ))
  fi
else
  echo "SKIP  $PPD_FIXTURE not found — skipping Layer 1 PPD assertions"
  SKIPPED=$(( SKIPPED + 8 ))
fi

# ════════════════════════════════════════════════════════════════════════════════════════════════
# LAYER 2 — run the cups unit-test binaries and assert KNOWN-ANSWER output content.
#
# CUPS test programs print results as "<test_name>: PASS" or "<test_name>: FAIL ...".
# We count ": PASS" lines from each program and require a minimum.  When a binary is
# sabotaged to exit(0) immediately, stdout is EMPTY — the ": PASS" count is 0, below the
# minimum, and the assertion FAILS.  This makes the oracle BEHAVIORAL: we assert what the
# parser PRINTED, not just its exit code.
# ════════════════════════════════════════════════════════════════════════════════════════════════

echo ""
echo "=== Layer 2: cups unit-test binary output assertions (run from $TDIR) ==="

# run_test_counted <binary> <min_pass> [args...]
# Runs <binary> from $TDIR, counts ": PASS" lines, fails if exit!=0 OR count<min_pass.
run_test_counted() {
  local t="$1" min_pass="$2"; shift 2
  if [ ! -x "$TDIR/$t" ]; then
    echo "SKIP  $t (binary missing)"
    SKIPPED=$(( SKIPPED + 1 ))
    return
  fi
  local log="/tmp/cups_test_${t}.log"
  local rc=0
  # Run from $TDIR so test data files (test.ppd, *.txt) are found in the cwd.
  ( cd "$TDIR" && timeout 180 "./$t" "$@" ) >"$log" 2>&1 || rc=$?
  # Count ": PASS" endings (testppd/testpwg/testraster/etc.) AND standalone "PASS" lines (testipp).
  local pass_count
  pass_count="$(grep -cE '(: PASS|^PASS)' "$log" 2>/dev/null)" || pass_count=0
  pass_count="${pass_count//[^0-9]/}"   # strip any whitespace/newlines from subshell
  pass_count="${pass_count:-0}"
  if [ "$rc" -ne 0 ]; then
    echo "FAIL  $t (exit $rc, $pass_count ':PASS' lines)"
    tail -10 "$log" | sed 's/^/      /'
    FAILED=$(( FAILED + 1 ))
  elif [ "$pass_count" -lt "$min_pass" ]; then
    echo "FAIL  $t (exit 0 but only $pass_count ':PASS' lines, need >=$min_pass — parser produced no output)"
    tail -10 "$log" | sed 's/^/      /'
    FAILED=$(( FAILED + 1 ))
  else
    echo "PASS  $t ($pass_count ':PASS' lines)"
    PASSED=$(( PASSED + 1 ))
  fi
}

# testppd: parses test.ppd + test2.ppd, emits 45 ": PASS" lines for known-answer assertions.
# min=20 so a partial run still detected, but neutered run (0 lines) definitely fails.
run_test_counted testppd 20

# testipp: round-trips IPP wire-format messages; emits "PASS" on each sub-test (15 lines).
run_test_counted testipp 10

# testraster: encodes/decodes CUPS raster pages, cross-checks decoded fields (72 ": PASS").
run_test_counted testraster 30

# testarray: exercises the cups_array_t API with known values (19 ": PASS").
run_test_counted testarray 10

# testpwg: maps PWG<->PPD media for test.ppd (20 ": PASS").
run_test_counted testpwg 10 test.ppd

# Remaining deterministic unit tests — lower minimums since they may have fewer PASS lines.
run_test_counted testfile  5
run_test_counted testform  5
run_test_counted testi18n  5
run_test_counted testjson  10
run_test_counted testjwt   10
run_test_counted testoptions 1

# Guard against a silently empty run.
if [ "$(( PASSED + FAILED ))" -eq 0 ]; then
  echo "no assertions ran — fixture files and test binaries both missing" >&2
  emit_ctrf "cups-behavioral" 0 1 "$SKIPPED"; exit 2
fi

emit_ctrf "cups-behavioral" "$PASSED" "$FAILED" "$SKIPPED"

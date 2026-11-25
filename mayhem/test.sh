#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

PD="$SRC/gtests/net/packetdrill"
TD="$SRC/mayhem/testdata"
passed=0; failed=0
ok()   { echo "PASS: $1"; passed=$((passed+1)); }
bad()  { echo "FAIL: $1"; failed=$((failed+1)); }
for b in packetdrill checksum_test packet_parser_test packet_to_string_test; do
  [ -x "$PD/$b" ] || { echo "missing $PD/$b — mayhem/build.sh must build it" >&2; exit 1; }
done

# Upstream unit tests (assert()-based; Makefile.common `tests` target).
for t in checksum_test packet_parser_test; do
  if (cd "$PD" && "./$t"); then ok "$t"; else bad "$t"; fi
done
# packet_to_string_test also prints every dump it checks: diff them against the golden output.
if out=$(cd "$PD" && ./packet_to_string_test) && diff -u "$TD/packet_to_string_test.out" <(printf '%s\n' "$out"); then
  ok "packet_to_string_test (golden dumps)"; else bad "packet_to_string_test (golden dumps)"; fi

# Script parser known answers (packetdrill --dry_run parses without executing).
err=$("$PD/packetdrill" --dry_run "$TD/syntax_error.pkt" 2>&1); rc=$?
if [ $rc -ne 0 ] && [ "$err" = "$TD/syntax_error.pkt:3: parse error at 'here': syntax error" ]; then
  ok "dry_run reports syntax error with line"; else bad "dry_run syntax error (rc=$rc: $err)"; fi
tfo="$SRC/gtests/net/tcp/fastopen/server/basic-zero-payload.pkt"
err=$("$PD/packetdrill" --dry_run "$tfo" 2>&1); rc=$?
if [ $rc -ne 0 ] && [ "$err" = "$tfo:14: semantic error: TCP fast open cookie 'TFO_COOKIE' is not a valid hex string" ]; then
  ok "dry_run reports semantic error"; else bad "dry_run semantic error (rc=$rc: $err)"; fi
# Every upstream script parses, minus: PSP (needs wire mode), the TFO_COOKIE templates, and two
# scripts upstream's own parser rejects (`bad ICMP type packet_too_big`, `bad ICMP code CODE`).
nscripts=0; nbad=0
while IFS= read -r f; do
  grep -q TFO_COOKIE "$f" && continue
  case "$f" in */syn-data-icmp-unreach-frag-needed-with-seq-ipv6.pkt|*/server/icmp-baseline.pkt) continue ;; esac
  nscripts=$((nscripts+1))
  "$PD/packetdrill" --dry_run "$f" >/dev/null 2>&1 || { echo "  parse failed: $f"; nbad=$((nbad+1)); }
done < <(find "$SRC/gtests/net" -name '*.pkt' -not -path '*/psp/*' | sort)
if [ $nbad -eq 0 ] && [ $nscripts -ge 140 ]; then ok "dry_run parses $nscripts upstream scripts"; else bad "dry_run upstream scripts ($nbad/$nscripts failed)"; fi

emit_ctrf "packetdrill-tests" "$passed" "$failed" 0

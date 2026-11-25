#!/usr/bin/env bash
#
# mayhem/test.sh — RUN ChucK's own regression suite (src/test, as upstream's src/test/test.py does)
# with the chuck CLI that mayhem/build.sh built (normal flags) at mayhem/build/test/chuck.
# A test passes iff `chuck --silent --chugin-load:off <file>` exits 0 AND either its output ends with
# the `"success" :(string)` marker the test prints, or it equals the golden <file>.txt exactly —
# the same criterion as test.py (minus its retries/sleeps). Emits CTRF.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

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

CHUCK="$SRC/mayhem/build/test/chuck"
if [ ! -x "$CHUCK" ]; then
  echo "test.sh: $CHUCK missing — run mayhem/build.sh first" >&2
  emit_ctrf "chuck-test" 0 1
  exit 1
fi

cd "$SRC/src/test"
pass=0; fail=0
# test.py walks the tree from src/test, skipping dot-directories (07-Imports/.deps are helpers);
# paths are relative (no ./) because golden files embed them in error messages.
while IFS= read -r f; do
  out=$(timeout 120 "$CHUCK" --silent --chugin-load:off "$f" 2>&1); rc=$?
  ok=0
  if [ "$rc" -eq 0 ]; then
    if printf '%s' "$out" | sed -e 's/[[:space:]]*$//' | grep -v '^$' | tail -n 1 | grep -q '"success" :(string)$'; then
      ok=1
    elif [ -f "${f%.ck}.txt" ] && [ "$out" = "$(tr -d '\r' < "${f%.ck}.txt")" ]; then
      ok=1
    fi
  fi
  if [ "$ok" = 1 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $f (exit $rc)"; fi
done < <(find 0* -name '.*' -prune -o -name '*.ck' -print | LC_ALL=C sort)

echo "chuck test suite: $pass passed, $fail failed"
emit_ctrf "chuck-test" "$pass" "$fail"

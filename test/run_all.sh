#!/usr/bin/env bash
# Run the given validation suites (names under test/, without .sh), keep
# going past failures, and print a summary. Used by `make test`.
#
#   test/run_all.sh run_validation run_validation_mt ...
#
# Each suite's output goes to a log in a per-run directory; the logs of
# failing suites are printed (tail) and the directory is kept.
#
# Each suite is bounded by SUITE_TIMEOUT seconds (default 900; the whole
# native set takes well under a minute). A suite that hits it is reported
# as TIMEOUT and counted as a failure.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOGS=$(mktemp -d -t libcov_tests.XXXXXX)
SUITE_TIMEOUT="${SUITE_TIMEOUT:-900}"
# Importing tools/gen_patchlist.py from a suite must not leave
# tools/__pycache__ behind in the tree.
export PYTHONDONTWRITEBYTECODE=1

pass=() fail=()
for suite in "$@"; do
    printf '%-36s ' "$suite"
    start=$SECONDS
    # -k: a suite that ignores SIGTERM is SIGKILLed 10s later.
    timeout -k 10 "$SUITE_TIMEOUT" "$ROOT/test/$suite.sh" > "$LOGS/$suite.log" 2>&1
    rc=$?
    if [[ $rc -eq 0 ]]; then
        pass+=("$suite"); echo "PASS ($((SECONDS - start))s)"
    elif [[ $rc -eq 124 ]] || [[ $rc -eq 137 && $((SECONDS - start)) -ge $SUITE_TIMEOUT ]]; then
        echo "TIMEOUT: $suite exceeded SUITE_TIMEOUT=${SUITE_TIMEOUT}s" >> "$LOGS/$suite.log"
        fail+=("$suite"); echo "TIMEOUT (>${SUITE_TIMEOUT}s)"
    else
        fail+=("$suite"); echo "FAIL ($((SECONDS - start))s)"
    fi
done

echo
echo "passed ${#pass[@]}/$#"
if (( ${#fail[@]} )); then
    for suite in "${fail[@]}"; do
        echo
        echo "===== $suite (last 20 lines; full log: $LOGS/$suite.log) ====="
        tail -20 "$LOGS/$suite.log"
    done
    exit 1
fi
rm -rf "$LOGS"

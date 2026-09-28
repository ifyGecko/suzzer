#!/usr/bin/env bash
# Run the given validation suites (names under test/, without .sh), keep
# going past failures, and print a summary. Used by `make test`.
#
#   test/run_all.sh run_validation run_validation_mt ...
#
# Each suite's output goes to a log in a per-run directory; the logs of
# failing suites are printed (tail) and the directory is kept.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOGS=$(mktemp -d -t libcov_tests.XXXXXX)
# Importing tools/gen_patchlist.py from a suite must not leave
# tools/__pycache__ behind in the tree.
export PYTHONDONTWRITEBYTECODE=1

pass=() fail=()
for suite in "$@"; do
    printf '%-36s ' "$suite"
    start=$SECONDS
    if "$ROOT/test/$suite.sh" > "$LOGS/$suite.log" 2>&1; then
        pass+=("$suite"); echo "PASS ($((SECONDS - start))s)"
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

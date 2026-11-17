#!/usr/bin/env bash
# Run pmonnt-core's unit tests under Valgrind Memcheck (Linux).
#
# The portable core (snapshot/diff/view model, handle summaries, AlignedBuf, hashing, YARA
# engine, providers) builds on Linux, so Memcheck can check it for invalid reads/writes,
# uninitialised-value use and leaks. Exits non-zero on any Memcheck error.
#
# Usage: tools/valgrind/memcheck-core-tests.sh [extra test-binary args, e.g. a test filter]
set -euo pipefail
cd "$(dirname "$0")/../.."

bin=$(cargo test -p pmonnt-core --lib --no-run --message-format=json 2>/dev/null \
  | python3 -c 'import json,sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["kind"] == ["lib"]:
        print(m["executable"])')

# The differential view-model test runs ~60k cases; it is correct but slow under Memcheck.
exec valgrind --tool=memcheck --error-exitcode=99 \
  --leak-check=full --show-leak-kinds=definite --errors-for-leak-kinds=definite \
  --track-origins=yes --suppressions=tools/valgrind/memcheck.supp \
  "$bin" --test-threads=1 --skip differential "$@"

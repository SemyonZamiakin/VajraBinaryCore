#!/usr/bin/env bash
# Runs the arena, hot-patches it to v2 while it runs, reverts, and checks that
# it kept running with its invariants intact. Works on Linux and on Windows
# (Git Bash / MSYS2 bash; the agent then listens on a named pipe).
#
#   demo/run_demo.sh build/demo/arena build/vajractl build/demo/libarena_patch_v2.so
set -euo pipefail

ARENA=${1:?arena binary}
CTL=${2:?vajractl binary}
PATCH=${3:?patch module}
SECONDS_TOTAL=${DEMO_SECONDS:-12}

dir=$(mktemp -d "${TMPDIR:-/tmp}/vajra-demo-XXXXXX")
trap 'rm -rf "$dir"' EXIT
log="$dir/arena.log"
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) sock='\\.\pipe\vajra-demo-'"$$" ;;
    *) sock="$dir/arena.sock" ;;
esac

"$ARENA" --socket "$sock" --seconds "$SECONDS_TOTAL" >"$log" 2>&1 &
pid=$!

# Wait until the agent answers.
for _ in $(seq 1 100); do
    "$CTL" "$sock" ping >/dev/null 2>&1 && break
    sleep 0.05
done
sleep 3
echo "== t=3s: apply v2 patch"
"$CTL" "$sock" apply "$PATCH"
sleep 4
echo "== t=7s: list"
"$CTL" "$sock" list
sleep 2
echo "== t=9s: revert"
"$CTL" "$sock" revert p1

status=0
wait "$pid" || status=$?
echo "== arena output"
cat "$log"

fail() { echo "demo check failed: $*" >&2; exit 1; }
[ "$status" -eq 0 ] || fail "arena exited with status $status"
grep -q "layout v2" "$log" || fail "no report with layout v2"
grep -q "layouts v1 -> v2 -> v1" "$log" || fail "layout history is not v1 -> v2 -> v1"
if grep -q "INVARIANT FAILED" "$log"; then fail "an invariant failed"; fi
grep -Eq "shield [0-9]+" "$log" || fail "v2 shields never appeared"
echo "demo: OK (patched to v2 and back while running, invariants held)"

#!/usr/bin/env bash
# Builds and tests Vajra in several configurations. Run from the repository root.
#
#   scripts/check.sh            # all configurations
#   scripts/check.sh gcc asan   # selected ones
#
# Configurations:
#   gcc    GCC, RelWithDebInfo, -Werror
#   clang  Clang, Release, -Werror
#   debug  GCC, Debug (-O0: different prologues than optimized code)
#   asan   Clang, AddressSanitizer + UndefinedBehaviorSanitizer
#   tsan   Clang, ThreadSanitizer (only tests that do not stop threads by signal;
#          TSan defers asynchronous signals, see docs/DESIGN.md)
set -euo pipefail

configs=("$@")
[ ${#configs[@]} -eq 0 ] && configs=(gcc clang debug asan tsan)
jobs=$(nproc 2>/dev/null || echo 4)

run() {
    local name=$1; shift
    local dir="build-check/$name"
    echo "=== $name"
    cmake -S . -B "$dir" -DVAJRA_WERROR=ON "$@" >/dev/null
    cmake --build "$dir" -j"$jobs" >/dev/null
    ctest --test-dir "$dir" --output-on-failure -j"$jobs"
}

for c in "${configs[@]}"; do
    case "$c" in
        gcc)   run gcc   -DCMAKE_C_COMPILER=gcc   -DCMAKE_CXX_COMPILER=g++     -DCMAKE_BUILD_TYPE=RelWithDebInfo ;;
        clang) run clang -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release ;;
        debug) run debug -DCMAKE_C_COMPILER=gcc   -DCMAKE_CXX_COMPILER=g++     -DCMAKE_BUILD_TYPE=Debug ;;
        asan)  ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 \
               run asan  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug \
                         -DVAJRA_SANITIZE=address,undefined ;;
        tsan)  TSAN_OPTIONS=halt_on_error=1 \
               run tsan  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=RelWithDebInfo \
                         -DVAJRA_SANITIZE=thread ;;
        *) echo "unknown configuration: $c" >&2; exit 2 ;;
    esac
done
echo "all requested configurations passed"

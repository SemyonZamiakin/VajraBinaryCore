#!/usr/bin/env bash
# Builds and tests Vajra on Windows with MinGW-w64 GCC. Run from the repository
# root in an MSYS2 MINGW64/UCRT64 shell, or in Git Bash with the MinGW bin
# directory on PATH (MINGW_BIN overrides it, default C:/msys64/mingw64/bin).
#
#   scripts/check-windows.sh            # RelWithDebInfo and Debug
#   scripts/check-windows.sh release
set -euo pipefail

bin=${MINGW_BIN:-/c/msys64/mingw64/bin}
[ -d "$bin" ] && export PATH="$bin:$PATH"
gen=()
if command -v ninja >/dev/null 2>&1; then gen=(-G Ninja)
elif command -v mingw32-make >/dev/null 2>&1; then gen=(-G "MinGW Makefiles")
elif [ -x /c/MinGW/bin/mingw32-make.exe ]; then gen=(-G "MinGW Makefiles" -DCMAKE_MAKE_PROGRAM=C:/MinGW/bin/mingw32-make.exe)
else echo "need ninja or mingw32-make" >&2; exit 2; fi

configs=("$@")
[ ${#configs[@]} -eq 0 ] && configs=(release debug)
for c in "${configs[@]}"; do
    case "$c" in
        release) type=RelWithDebInfo ;;
        debug) type=Debug ;;
        *) echo "unknown configuration: $c" >&2; exit 2 ;;
    esac
    dir="build-check-win/$c"
    echo "=== windows $c"
    cmake -S . -B "$dir" "${gen[@]}" -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCMAKE_ASM_COMPILER=gcc \
          -DCMAKE_BUILD_TYPE="$type" -DVAJRA_WERROR=ON >/dev/null
    cmake --build "$dir" -j"$(nproc 2>/dev/null || echo 4)" >/dev/null
    ctest --test-dir "$dir" --output-on-failure -j4
done
echo "all requested configurations passed"

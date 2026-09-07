#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-$ROOT/build/lint}"

if [[ ! -f "$BUILD_DIR/compile_commands.json" ]]; then
    echo "Missing $BUILD_DIR/compile_commands.json — run 'make lint-build' first." >&2
    exit 1
fi

mapfile -t files < <(
    find "$ROOT/include/rqp/security" "$ROOT/src" "$ROOT/tests" \
        -type f \( -name '*.cpp' -o -name '*.h' \) \
        ! -path '*/build/*' ! -path '*/_deps/*' \
        | sort
)

if [[ ${#files[@]} -eq 0 ]]; then
    echo "No source files found for clang-tidy." >&2
    exit 1
fi

# Match project headers under include/, src/, and tests/ regardless of checkout path.
HEADER_FILTER='.*/(include/rqp/security/|src/|tests/).*'

if command -v run-clang-tidy >/dev/null 2>&1; then
    echo "Running run-clang-tidy on ${#files[@]} files..."
    run-clang-tidy -p "$BUILD_DIR" \
        -header-filter="$HEADER_FILTER" \
        -quiet \
        "${files[@]}"
    echo "clang-tidy passed."
    exit 0
fi

if ! command -v clang-tidy >/dev/null 2>&1; then
    echo "Neither run-clang-tidy nor clang-tidy found in PATH" >&2
    exit 127
fi

echo "Running clang-tidy on ${#files[@]} files..."
clang-tidy -p "$BUILD_DIR" "${files[@]}" --quiet
echo "clang-tidy passed."

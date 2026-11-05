#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v clang-format >/dev/null 2>&1; then
    echo "clang-format not found in PATH" >&2
    exit 127
fi

mapfile -t filtered < <("$ROOT/scripts/collect_format_sources.sh")

if ((${#filtered[@]} == 0)); then
    echo "No source files selected for clang-format check" >&2
    exit 1
fi

echo "Checking clang-format on ${#filtered[@]} files..."
clang-format --dry-run --Werror "${filtered[@]}"
echo "clang-format check passed."

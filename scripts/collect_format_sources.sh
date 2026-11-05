#!/usr/bin/env bash
# Shared file list for clang-format check/format. Sources one path per line on stdout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mapfile -t files < <(
    find include src tests -type f \( -name '*.cpp' -o -name '*.h' \) \
        ! -path '*/build/*' ! -path '*/_deps/*' \
        | sort
)

for file in "${files[@]}"; do
    case "$file" in
        src/validator/*)
            continue
            ;;
    esac
    printf '%s\n' "$file"
done

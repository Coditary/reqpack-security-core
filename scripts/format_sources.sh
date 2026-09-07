#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v clang-format >/dev/null 2>&1; then
    echo "clang-format not found in PATH" >&2
    exit 127
fi

mapfile -t files < <(
    git ls-files 'include/*.h' 'src/*.cpp' 'src/*.h' 'tests/**/*.cpp' 'tests/**/*.h' 2>/dev/null \
        | sort
)

if ((${#files[@]} == 0)); then
    mapfile -t files < <(
        find include src tests -type f \( -name '*.cpp' -o -name '*.h' \) \
            ! -path '*/build/*' ! -path '*/_deps/*' \
            | sort
    )
fi

declare -a filtered=()
for file in "${files[@]}"; do
    [[ -f "$file" ]] || continue
    case "$file" in
        src/validator.cpp|src/validator_prepare.cpp|src/validator_prompt.cpp|src/validator_internal.h)
            continue
            ;;
    esac
    filtered+=("$file")
done

if ((${#filtered[@]} == 0)); then
    echo "No source files selected for clang-format" >&2
    exit 1
fi

clang-format -i "${filtered[@]}"
echo "Formatted ${#filtered[@]} files."

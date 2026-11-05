#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-$ROOT/build/fuzz}"
RUNS="${FUZZ_RUNS:-4096}"
MAX_TIME="${FUZZ_MAX_TIME:-20}"
RSS_LIMIT="${FUZZ_RSS_LIMIT_MB:-512}"

if [[ ! -d "$BUILD_DIR" ]]; then
    echo "Missing fuzz build directory: $BUILD_DIR — run 'make fuzz-build' first." >&2
    exit 1
fi

declare -a fuzzers=(
    osv_parse_fuzzer
    osv_json_fuzzer
    cyclonedx_emit_fuzzer
    snyk_csv_fuzzer
    trivy_helper_fuzzer
    version_compare_fuzzer
)

for fuzzer in "${fuzzers[@]}"; do
    bin="$BUILD_DIR/$fuzzer"
    if [[ ! -x "$bin" ]]; then
        echo "Missing fuzzer binary: $bin" >&2
        exit 1
    fi

    corpus_name="${fuzzer%_fuzzer}"
    corpus="$ROOT/tests/fuzz/corpus/${corpus_name}"

    args=(-runs="$RUNS" -max_total_time="$MAX_TIME" -timeout=5 -rss_limit_mb="$RSS_LIMIT")
    if [[ -d "$corpus" ]]; then
        args+=("$corpus")
    fi

    echo "Running $fuzzer (${RUNS} runs, max ${MAX_TIME}s)..."
    "$bin" "${args[@]}"
done

echo "All fuzzers completed."

#!/usr/bin/env bash
# Shared Rust bootstrap for security-core CI / act (Cargo.lock v4 needs recent rustc).
set -euo pipefail

if command -v rustc >/dev/null 2>&1; then
    rustc --version
    exit 0
fi

export CARGO_HOME="${CARGO_HOME:-${HOME}/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME}/.rustup}"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
# shellcheck disable=SC1091
source "${CARGO_HOME}/env"
rustc --version

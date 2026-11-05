[![Quality](https://github.com/Coditary/reqpack-security-core/actions/workflows/quality.yml/badge.svg)](https://github.com/Coditary/reqpack-security-core/actions/workflows/quality.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Coditary/reqpack-security-core/main/.github/badges/coverage.json)](https://github.com/Coditary/reqpack-security-core/actions/workflows/coverage.yml)

# ReqPack Security Core

Standalone C++ library for vulnerability scanning, OSV database sync, security gateways, and install-plan validation. Extracted from [ReqPack](https://github.com/Coditary/ReqPack) so security logic can be developed, tested, and reused independently of the main CLI.

## What It Provides

- **OSV matching** — parse advisories, match packages, compare version ranges
- **Vulnerability databases** — LMDB-backed storage with indexed lookup paths
- **Sync backends** — pluggable registry (`sync_backend_registry.h`); OSV plus optional GitHub Advisory, Snyk, Trivy
- **Plan validation** — gate installs/updates against configured severity thresholds
- **Security gateway** — orchestrate sync, validation, and host callbacks
- **Host hooks** — archive extraction, logging, and stdout redirection for embedding

Public headers live under `include/rqp/security/` (~27 integration-facing headers). Backend-specific sync and infra headers live under `src/` (see `ARCHITECTURE-CHANGELOG.md`). The static library target is `reqpack_security_core`.

## Requirements

| Dependency | Notes |
| --- | --- |
| CMake 3.15+ | C++20 project |
| C++20 compiler | GCC or Clang |
| libcurl, OpenSSL, Boost, zstd | Required at configure time |
| LMDB, Catch2 | Fetched automatically via CMake |
| `gcovr` | Optional — coverage reports |
| Clang + libFuzzer | Optional — fuzz targets (`make fuzz`) |
| `clang-format`, `clang-tidy` | Optional — formatting and lint |

## Quick Start

```bash
git clone https://github.com/Coditary/reqpack-security-core.git
cd reqpack-security-core

make build
make test          # 110 unit tests
make qa            # format-check + lint + test + fuzz
```

### Optional sync backends (CMake)

Default build includes all built-in backends. Minimal OSV-only library:

```bash
cmake -S . -B build \
  -DRQP_SECURITY_BACKEND_GH_ADVISORY=OFF \
  -DRQP_SECURITY_BACKEND_SNYK=OFF \
  -DRQP_SECURITY_BACKEND_TRIVY=OFF
```

Backend IDs for config/gateway: `rqp::sync_backend::kOsv`, `kGhAdvisory`, `kSnyk`, `kTrivy` in `sync_backend_registry.h`.

CMake equivalent:

```bash
cmake -S . -B build -DRQP_SECURITY_CORE_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Run only security unit tests:

```bash
ctest --test-dir build --output-on-failure -R '^security::'
```

## Makefile Targets

| Target | Description |
| --- | --- |
| `make build` | Configure and build library + tests |
| `make test` | Run full CTest suite |
| `make test-unit` | Run tests matching `^security::` |
| `make test-coverage` | Debug build with gcovr summary + badge update |
| `make format-check` | Verify `clang-format` (dry run) |
| `make format` | Apply `clang-format` in place |
| `make lint` | Run `clang-tidy` via `build/lint/compile_commands.json` |
| `make fuzz` | libFuzzer smoke run (Clang required) |
| `make qa` | `format-check` + `lint` + `test` + `fuzz` |
| `make clean` | Remove build directories and coverage artifacts |

Coverage instrumentation excludes subprocess/pipe glue and network sync backends from the headline metric; those paths are still exercised by unit and gateway tests.

## Quality Tooling

Formatting uses `.clang-format` (LLVM style, 120 columns). Tab-indented validator sources are listed in `.clang-format-ignore` until normalized.

Lint builds into `build/lint/` with Clang and `CMAKE_EXPORT_COMPILE_COMMANDS`. Fuzzers build with `-fsanitize=fuzzer,address,undefined` into `build/fuzz/`:

| Fuzzer | Input focus |
| --- | --- |
| `osv_parse_fuzzer` | OSV JSON advisory parsing |
| `snyk_csv_fuzzer` | Snyk CSV rows |
| `trivy_helper_fuzzer` | Trivy DB helper output |
| `version_compare_fuzzer` | Version range comparison |
| `osv_json_fuzzer` | OSV JSON advisory parsing (libFuzzer) |
| `cyclonedx_emit_fuzzer` | CycloneDX emit FFI boundary |

Seed corpora: `tests/fuzz/corpus/`.

## Integration with ReqPack

When built inside the ReqPack tree, the parent project adds this directory via `add_subdirectory(../reqpack-security-core)` and disables the security test suite by default — tests run from this repository instead.

Link against `reqpack_security_core` and map host settings into `SecuritySettings`:

```cpp
#include <rqp/security/security_settings.h>
#include <rqp/security/validator.h>

SecuritySettings settings = default_security_settings();
settings.security.enabled = true;

Validator validator(metadataProvider, settings);
```

Optional host callbacks:

| Callback | Purpose |
| --- | --- |
| `archive.extractToTemp` | Materialize GH advisory DB tarballs |
| `set_security_log_callback` | Route security logs through the host |
| `set_security_stdout_callback` | Redirect structured stdout output |

ReqPack keeps `security_bridge_tests.cpp` for config-mapping integration; all other security unit tests live here.

## Project Layout

```
include/rqp/security/     Public API (~27 headers; see ARCHITECTURE-CHANGELOG.md)
src/domain/               Matching, OSV, policy, version (I/O-free)
src/adapters/             LMDB, sync backends, HTTP, infra (internal headers under src/)
src/app/                  scan_service, sync gateway runner, policy console
src/gateway/              SecurityGatewayService
src/validator/            Validator
src/exchange/             Document pipeline + transforms
tests/unit/               Standalone unit tests (Catch2)
tests/cpp/                Shared test main and helpers
tests/fuzz/               libFuzzer targets + seed corpora
tests/coverage_summary.py gcovr summary and badge helper
scripts/                  format, lint, and fuzz runner scripts
.github/workflows/        quality.yml, coverage.yml
```

## Related

- [ReqPack](https://github.com/Coditary/ReqPack) — universal package-manager orchestrator (`rqp` CLI)

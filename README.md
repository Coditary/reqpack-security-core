# ReqPack Security Core

Standalone C++ library extracted from ReqPack. It provides vulnerability scanning,
OSV database sync, security gateways, and plan validation.

## Build

When built as part of ReqPack, the parent project adds this directory via
`add_subdirectory(../reqpack-security-core)`. ReqPack disables the security test
suite by default so tests run only from this project.

Standalone:

```bash
cmake -S . -B build
cmake --build build
```

Or with Makefile shortcuts:

```bash
make build
make test
make test-unit
make test-coverage
make format-check
make lint
make fuzz
make qa
```

Coverage uses `gcovr` over `src/` (excluding subprocess/pipe glue). Results are written to
`coverage-summary.txt` and `.github/badges/coverage.json`.

## Quality tooling

Formatting uses `clang-format` (`.clang-format`). Tab-indented validator sources are excluded via
`.clang-format-ignore` until they are normalized.

```bash
make format-check   # verify formatting
make format         # apply clang-format in-place
make lint           # clang-tidy via compile_commands.json
make fuzz           # libFuzzer smoke run (requires Clang)
make qa             # format-check + lint + unit tests + fuzz
```

Lint builds into `build/lint/`; fuzzers build with `-fsanitize=fuzzer,address,undefined` into
`build/fuzz/`. Seed corpora live under `tests/fuzz/corpus/`.

```bash
make test-coverage
# or
cmake -S . -B build/coverage \
  -DCMAKE_BUILD_TYPE=Debug \
  -DRQP_SECURITY_CORE_BUILD_TESTS=ON \
  -DRQP_SECURITY_CORE_ENABLE_COVERAGE=ON
cmake --build build/coverage
ctest --test-dir build/coverage --output-on-failure
python3 tests/coverage_summary.py build/coverage . --badge-json .github/badges/coverage.json
```

## Tests

Unit tests live in `tests/unit/` and run independently of ReqPack:

```bash
cmake -S . -B build -DRQP_SECURITY_CORE_BUILD_TESTS=ON
cmake --build build --target security_core_unit_tests
ctest --test-dir build --output-on-failure -R '^security::'
```

ReqPack keeps only `security_bridge_tests.cpp` for config mapping integration.

## Integration

Link against `reqpack_security_core` and include headers from `include/rqp/security/`.

Map host application settings into `SecuritySettings` and wire optional callbacks:

- `archive.extractToTemp` for archive materialization (GH advisory DB tarballs)
- `set_security_log_callback` / `set_security_stdout_callback` for host logging

```cpp
#include <rqp/security/security_settings.h>
#include <rqp/security/validator.h>

SecuritySettings settings = default_security_settings();
settings.security.enabled = true;
Validator validator(metadataProvider, settings);
```

## Layout

```
include/rqp/security/   Public headers
src/                    Library implementation
tests/cpp/              Catch2 main + shared helpers
tests/unit/             Unit tests (standalone runner)
tests/coverage_summary.py  gcovr summary + badge helper
```

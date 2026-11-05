# Architecture refactor changelog (reqpack-security-core)

Tracks the hexagonal layering refactor. **ReqPack-Core / `rqp`:** existing public includes remain valid for integration headers listed below.

## CMake layers

| Target | Role |
|--------|------|
| `rqp_sec_domain` | Version, OSV, policy, matcher, `json_util` — **no LMDB/cURL/sync adapters** |
| `rqp_sec_adapters` | LMDB, sync backends, HTTP, archive, CycloneDX, exchange codecs, ecosystem resolver |
| `rqp_sec_app` | Gateway, validator, `scan_service`, sync gateway runner |

Private include roots: `src/`, `src/adapters/`, `src/validator/`.

## Public headers (`include/rqp/security/`, 27 files)

**Integration / CLI / Core-facing**

| Header | Purpose |
|--------|---------|
| `validator.h` | Graph validate/audit (ReqPack-Core) |
| `validator_core.h` | Findings, policy helpers |
| `security_settings.h` / `security_config.h` | Configuration |
| `security_types.h` | `Package`, `Graph`, … |
| `security_gateway_service.h` | Multi-backend sync orchestration |
| `vulnerability_database.h` | LMDB store (pimpl; implements advisory ports) |
| `vulnerability_sync_service.h` | OSV per-ecosystem sync (Validator, `rqps` DB) |
| `vulnerability_matcher.h` | Matching API (`IEcosystemAdvisoryResolver` injection) |
| `plugin_metadata_provider.h` | Plugin OSV ecosystem metadata |
| `security_paths.h` / `security_log.h` / `security_status.h` | Paths, logging, status |
| `security_archive.h` | Host archive callback type in settings |
| `osv_core.h` / `version_compare.h` / `json_util.h` | Domain types exposed for tools/tests |
| `cyclonedx.h` | CycloneDX emit (ReqPack-Core reporting) |
| `exchange.h` / `exchange_view.h` / `sbom_inventory.h` | Document pipeline |
| `sync_backend_registry.h` | Backend IDs, `find_sync_backend`, defaults |
| `ports.h` | `IAdvisoryReader`/`Writer`, `IEcosystemAdvisoryResolver`, policy port |
| `error.h` | `Result<T>`, `SecurityError` |
| `engine.h` | **`scan_packages` / `scan_graph`** (shared Validator + exchange scan) |
| `graph_adapter.h` | `packages_from_graph` helper |
| `types.h` | Re-export of `security_types` + findings (optional alias) |

## Internal headers (under `src/`, not installed)

| Former public path | New location |
|--------------------|--------------|
| `pipe_helpers.h` | `src/adapters/infra/pipe_helpers.h` |
| `security_network.h` | `src/adapters/infra/security_network.h` |
| `security_process.h` | `src/adapters/infra/security_process.h` |
| `gh_advisory_vulnerability_sync_service.h` | `src/adapters/sync/` |
| `snyk_vulnerability_sync_service.h` | `src/adapters/sync/snyk/` |
| `trivy_vulnerability_sync_service.h` | `src/adapters/sync/trivy/` |
| `sync_gateway_backend_run.h` | `src/app/` |
| `policy_decision_console.h` | `src/app/` |

Include from library code via private roots, e.g. `#include "sync/snyk/snyk_vulnerability_sync_service.h"`, `#include "app/sync_gateway_backend_run.h"`, `#include "infra/security_network.h"`.

## Sync architecture (remediation complete)

- **`ISyncBackend`**: native implementations for OSV / GH / Snyk / Trivy (no `SyncBackendRunner` / `RegisteredSyncBackend` wrapper).
- **`SecurityIoPorts`**: `IHttpClient` + `IArchiveExtractor` passed into `ISyncBackend::sync` and sync services (mockable HTTP in tests via `TestSyncIo` in unit test helpers).
- **`http_download_to_file(IHttpClient&, …)`** / **`http_fetch_text`**: shared transport; OSV/Snyk/Trivy/GH use injected client where sync runs.
- **`run_registered_sync_backend`**: builds default `CurlHttpClient` + `SettingsArchiveExtractor`, calls `find_sync_backend` → `sync(…, io)`.

## Domain / matching (remediation complete)

- **`VulnerabilityMatcher`**: no `VulnerabilityDatabase` or filesystem I/O in `rqp_sec_domain`; uses **`IEcosystemAdvisoryResolver`** only.
- **`LmdbEcosystemAdvisoryResolver`** (adapters): per-ecosystem LMDB paths and cache.
- **`scan_service`**: wires resolver + matcher; **`scan_graph`** uses **`matchGraph`** (dependency waves, same as Validator graph audit).

## Storage

- **`VulnerabilityDatabase`**: no `<lmdb.h>` in public header; LMDB in private `Impl`.

## Tests

- `tests/unit/http_client_sync_port_tests.cpp` — HTTP `Result` mapping, mock client, OSV `ISyncBackend` registration.
- `tests/unit/matcher_in_memory_tests.cpp` — overlay + `matchPackages`.
- `tests/cpp/test_helpers.h` — **`TestSyncIo`** for sync tests needing `SecurityIoPorts`.
- `tests/cpp/in_memory_advisory_store.h` — advisory port double.

## Verification

```bash
make build && make test-unit   # 134 tests, prefix security::
```

## Optional follow-ups

- Move `vulnerability_sync_service.h` behind a slimmer public sync API (Validator/`rqps` still include it today).
- Relocate `src/exchange/codec_sbom.cpp` + `envelope.cpp` under `src/adapters/exchange/`.
- End-to-end unit test: mock `IHttpClient` driving OSV delta sync failure paths (429/5xx).

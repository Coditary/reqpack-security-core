#include "rqp/security/snyk_vulnerability_sync_service.h"
#include "rqp/security/sync_backend_registry.h"

namespace {

std::vector<ValidationFinding> run_snyk(const SyncBackendContext& ctx) {
    SnykVulnerabilitySyncService syncService(ctx.database, ctx.ecosystems, ctx.config);
    return syncService.ensureReady(ctx.forceRefresh);
}

void apply_snyk_defaults(SecurityConfig& security) {
    if (security.backends.contains(rqp::sync_backend::kSnyk)) {
        return;
    }
    SecurityBackendConfig snykBackend;
    snykBackend.apiBaseUrl = "https://api.snyk.io/rest";
    snykBackend.apiVersion = "2024-10-15";
    snykBackend.tokenEnv = "SNYK_TOKEN";
    snykBackend.dataset = "issues";
    security.backends[rqp::sync_backend::kSnyk] = std::move(snykBackend);
}

void register_snyk_backend() {
    register_sync_backend(SyncBackendRegistration{
        .id = rqp::sync_backend::kSnyk,
        .scope = SyncBackendScope::PerEcosystem,
        .applyDefaultConfig = apply_snyk_defaults,
        .run = run_snyk,
    });
}

} // namespace

void rqp_security_register_snyk_sync_backend() {
    register_snyk_backend();
}

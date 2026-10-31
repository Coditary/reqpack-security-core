#include "rqp/security/sync_backend_registry.h"
#include "rqp/security/trivy_vulnerability_sync_service.h"

namespace {

std::vector<ValidationFinding> run_trivy(const SyncBackendContext& ctx) {
    TrivyVulnerabilitySyncService syncService(ctx.database, ctx.ecosystems, ctx.config);
    return syncService.ensureReady(ctx.forceRefresh);
}

void apply_trivy_defaults(SecurityConfig& security) {
    if (security.backends.contains(rqp::sync_backend::kTrivy)) {
        return;
    }
    SecurityBackendConfig trivyBackend;
    trivyBackend.dbRepositories = {
        "mirror.gcr.io/aquasec/trivy-db:2",
        "ghcr.io/aquasecurity/trivy-db:2",
    };
    security.backends[rqp::sync_backend::kTrivy] = std::move(trivyBackend);
}

void register_trivy_backend() {
    register_sync_backend(SyncBackendRegistration{
        .id = rqp::sync_backend::kTrivy,
        .scope = SyncBackendScope::PerEcosystem,
        .applyDefaultConfig = apply_trivy_defaults,
        .run = run_trivy,
    });
}

} // namespace

void rqp_security_register_trivy_sync_backend() {
    register_trivy_backend();
}

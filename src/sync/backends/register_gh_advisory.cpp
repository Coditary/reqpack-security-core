#include "rqp/security/gh_advisory_vulnerability_sync_service.h"
#include "rqp/security/sync_backend_registry.h"

#include "sync/sync_backend_support.h"

namespace {

std::vector<ValidationFinding> run_gh_advisory(const SyncBackendContext& ctx) {
    GhAdvisoryVulnerabilitySyncService syncService(ctx.ecosystems, ctx.config);
    return syncService.ensureReady(ctx.forceRefresh);
}

void apply_gh_defaults(SecurityConfig& security) {
    if (security.backends.contains(rqp::sync_backend::kGhAdvisory)) {
        return;
    }
    SecurityBackendConfig ghAdvisoryBackend;
    ghAdvisoryBackend.feedUrl = "https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main";
    security.backends[rqp::sync_backend::kGhAdvisory] = std::move(ghAdvisoryBackend);
}

void register_gh_advisory_backend() {
    register_sync_backend(SyncBackendRegistration{
        .id = rqp::sync_backend::kGhAdvisory,
        .scope = SyncBackendScope::MultiEcosystem,
        .allowsRawPackageNamesAsEcosystem = true,
        .applyDefaultConfig = apply_gh_defaults,
        .mergeGatewayBackendConfig = rqp::sync_backend_internal::merge_gh_advisory_gateway_backend,
        .applyForceRefresh = rqp::sync_backend_internal::apply_gh_advisory_force_refresh,
        .run = run_gh_advisory,
    });
}

} // namespace

void rqp_security_register_gh_advisory_sync_backend() {
    register_gh_advisory_backend();
}

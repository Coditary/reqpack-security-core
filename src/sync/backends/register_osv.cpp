#include "rqp/security/sync_backend_registry.h"
#include "rqp/security/vulnerability_database.h"
#include "rqp/security/vulnerability_sync_service.h"

#include "sync/sync_backend_support.h"

namespace {

std::vector<ValidationFinding> run_osv(const SyncBackendContext& ctx) {
    VulnerabilitySyncService syncService(ctx.database, ctx.metadataProvider, ctx.config,
                                         {*ctx.ecosystems.begin()});
    return syncService.ensureReady();
}

void apply_osv_defaults(SecurityConfig& security) {
    if (security.backends.contains(rqp::sync_backend::kOsv)) {
        return;
    }
    SecurityBackendConfig osvBackend;
    osvBackend.feedUrl = security.osvFeedUrl;
    osvBackend.refreshMode = security.osvRefreshMode;
    osvBackend.refreshIntervalSeconds = security.osvRefreshIntervalSeconds;
    osvBackend.overlayPath = security.osvOverlayPath;
    security.backends[rqp::sync_backend::kOsv] = std::move(osvBackend);
}

void register_osv_backend() {
    register_sync_backend(SyncBackendRegistration{
        .id = rqp::sync_backend::kOsv,
        .scope = SyncBackendScope::PerEcosystem,
        .applyDefaultConfig = apply_osv_defaults,
        .mergeGatewayBackendConfig = rqp::sync_backend_internal::merge_osv_gateway_backend,
        .applyForceRefresh = rqp::sync_backend_internal::apply_osv_force_refresh,
        .run = run_osv,
    });
}

} // namespace

void rqp_security_register_osv_sync_backend() {
    register_osv_backend();
}

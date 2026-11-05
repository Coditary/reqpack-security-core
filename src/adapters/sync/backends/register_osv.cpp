#include "rqp/security/sync_backend_registry.h"
#include "rqp/security/vulnerability_database.h"
#include "rqp/security/vulnerability_sync_service.h"

#include "ports/internal_ports.h"
#include "sync/sync_backend_support.h"

namespace {

class OsvSyncBackend final : public ISyncBackend {
  public:
    [[nodiscard]] std::string id() const override {
        return rqp::sync_backend::kOsv;
    }

    [[nodiscard]] SyncBackendScope scope() const override {
        return SyncBackendScope::PerEcosystem;
    }

    [[nodiscard]] bool allowsRawPackageNamesAsEcosystem() const override {
        return false;
    }

    [[nodiscard]] bool supportsEcosystem(const std::string& ecosystem) const override {
        return !ecosystem.empty();
    }

    void applyDefaultConfig(SecurityConfig& security) const override {
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

    void mergeGatewayBackendConfig(SecuritySettings& out, const SecuritySettings& in) const override {
        rqp::sync_backend_internal::merge_osv_gateway_backend(out, in, this->id());
    }

    void applyForceRefresh(SecuritySettings& out) const override {
        rqp::sync_backend_internal::apply_osv_force_refresh(out, this->id());
    }

    [[nodiscard]] rqp::security::Result<std::vector<ValidationFinding>>
    sync(IAdvisoryWriter& store, const SyncOptions& options, SecurityIoPorts& io) const override {
        auto* database = dynamic_cast<VulnerabilityDatabase*>(&store);
        if (database == nullptr) {
            return rqp::security::Result<std::vector<ValidationFinding>>(
                rqp::security::make_error(rqp::security::ErrorCode::InvalidInput,
                                          "advisory store must be VulnerabilityDatabase for per-ecosystem backends"));
        }
        if (options.ecosystems.empty()) {
            return rqp::security::Result<std::vector<ValidationFinding>>(
                rqp::security::make_error(rqp::security::ErrorCode::InvalidInput,
                                          "ecosystem scope required for per-ecosystem backend", this->id()));
        }

        SecuritySettings runConfig = options.settings;
        this->mergeGatewayBackendConfig(runConfig, options.settings);
        if (options.forceRefresh) {
            this->applyForceRefresh(runConfig);
        }

        VulnerabilitySyncService syncService(database, options.metadataProvider, runConfig, options.ecosystems, &io);
        return rqp::security::Result<std::vector<ValidationFinding>>(syncService.ensureReady());
    }
};

void register_osv_backend() {
    register_sync_backend(std::make_unique<OsvSyncBackend>());
}

} // namespace

void rqp_security_register_osv_sync_backend() {
    register_osv_backend();
}

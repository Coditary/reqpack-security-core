#include "rqp/security/sync_backend_registry.h"
#include "rqp/security/vulnerability_database.h"
#include "sync/snyk/snyk_vulnerability_sync_service.h"

#include "ports/internal_ports.h"

namespace {

class SnykSyncBackend final : public ISyncBackend {
  public:
    [[nodiscard]] std::string id() const override {
        return rqp::sync_backend::kSnyk;
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

    void mergeGatewayBackendConfig(SecuritySettings& /*out*/, const SecuritySettings& /*in*/) const override {}

    void applyForceRefresh(SecuritySettings& /*out*/) const override {}

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

        SnykVulnerabilitySyncService syncService(database, options.ecosystems, options.settings, &io);
        return rqp::security::Result<std::vector<ValidationFinding>>(syncService.ensureReady(options.forceRefresh));
    }
};

void register_snyk_backend() {
    register_sync_backend(std::make_unique<SnykSyncBackend>());
}

} // namespace

void rqp_security_register_snyk_sync_backend() {
    register_snyk_backend();
}

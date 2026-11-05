#include "rqp/security/sync_backend_registry.h"
#include "rqp/security/vulnerability_database.h"
#include "sync/trivy/trivy_vulnerability_sync_service.h"

#include "ports/internal_ports.h"

namespace {

class TrivySyncBackend final : public ISyncBackend {
  public:
    [[nodiscard]] std::string id() const override {
        return rqp::sync_backend::kTrivy;
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

        TrivyVulnerabilitySyncService syncService(database, options.ecosystems, options.settings, &io);
        return rqp::security::Result<std::vector<ValidationFinding>>(syncService.ensureReady(options.forceRefresh));
    }
};

void register_trivy_backend() {
    register_sync_backend(std::make_unique<TrivySyncBackend>());
}

} // namespace

void rqp_security_register_trivy_sync_backend() {
    register_trivy_backend();
}

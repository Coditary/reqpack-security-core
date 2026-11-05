#include "rqp/security/sync_backend_registry.h"
#include "sync/gh_advisory_vulnerability_sync_service.h"

#include "ports/internal_ports.h"
#include "sync/sync_backend_support.h"

namespace {

class GhAdvisorySyncBackend final : public ISyncBackend {
  public:
    [[nodiscard]] std::string id() const override {
        return rqp::sync_backend::kGhAdvisory;
    }

    [[nodiscard]] SyncBackendScope scope() const override {
        return SyncBackendScope::MultiEcosystem;
    }

    [[nodiscard]] bool allowsRawPackageNamesAsEcosystem() const override {
        return true;
    }

    [[nodiscard]] bool supportsEcosystem(const std::string& ecosystem) const override {
        return !ecosystem.empty();
    }

    void applyDefaultConfig(SecurityConfig& security) const override {
        if (security.backends.contains(rqp::sync_backend::kGhAdvisory)) {
            return;
        }
        SecurityBackendConfig ghAdvisoryBackend;
        ghAdvisoryBackend.feedUrl = "https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main";
        security.backends[rqp::sync_backend::kGhAdvisory] = std::move(ghAdvisoryBackend);
    }

    void mergeGatewayBackendConfig(SecuritySettings& out, const SecuritySettings& in) const override {
        rqp::sync_backend_internal::merge_gh_advisory_gateway_backend(out, in, this->id());
    }

    void applyForceRefresh(SecuritySettings& out) const override {
        rqp::sync_backend_internal::apply_gh_advisory_force_refresh(out, this->id());
    }

    [[nodiscard]] rqp::security::Result<std::vector<ValidationFinding>>
    sync(IAdvisoryWriter& /*store*/, const SyncOptions& options, SecurityIoPorts& io) const override {
        SecuritySettings runConfig = options.settings;
        this->mergeGatewayBackendConfig(runConfig, options.settings);
        if (options.forceRefresh) {
            this->applyForceRefresh(runConfig);
        }

        GhAdvisoryVulnerabilitySyncService syncService(options.ecosystems, runConfig);
        return rqp::security::Result<std::vector<ValidationFinding>>(syncService.ensureReady(io, options.forceRefresh));
    }
};

void register_gh_advisory_backend() {
    register_sync_backend(std::make_unique<GhAdvisorySyncBackend>());
}

} // namespace

void rqp_security_register_gh_advisory_sync_backend() {
    register_gh_advisory_backend();
}

#pragma once

#include "rqp/security/plugin_metadata_provider.h"
#include "rqp/security/security_settings.h"
#include "rqp/security/validator_core.h"

#include <set>
#include <string>
#include <vector>

class SecurityGatewayService {
    PluginMetadataProvider* metadataProvider;
    SecuritySettings config;

    std::string normalizeGatewayName(const std::string& gateway) const;
    std::set<std::string> discoverSecurityProviders() const;
    std::set<std::string> resolveGatewayBackends(const std::string& gateway) const;
    std::optional<std::string> resolveCanonicalEcosystem(const std::string& target) const;

  public:
    SecurityGatewayService(PluginMetadataProvider* metadataProvider = nullptr,
                           const SecuritySettings& config = default_security_settings());

    bool isGatewaySystem(const std::string& system) const;
    std::set<std::string> configuredGatewayNames() const;
    std::set<std::string> resolvePackageEcosystems(const std::vector<Package>& packages) const;
    std::vector<ValidationFinding> ensureEcosystemsReady(const std::set<std::string>& ecosystems,
                                                         const std::string& gateway = {},
                                                         bool forceRefresh = false) const;
    std::vector<ValidationFinding> executeGatewayRequest(ActionType action, const std::string& gateway,
                                                         const std::vector<Package>& packages) const;
};

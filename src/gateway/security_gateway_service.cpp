#include "rqp/security/security_gateway_service.h"

#include "rqp/security/security_log.h"
#include "rqp/security/security_paths.h"
#include "rqp/security/sync_backend_registry.h"
#include "rqp/security/vulnerability_database.h"

#include <algorithm>
#include <cctype>

namespace {

std::string to_lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string package_index_path_for_ecosystem(const SecuritySettings& config, const std::string& ecosystem) {
    std::filesystem::path root = config.security.indexPath;
    const std::filesystem::path defaultIndexPath = default_security_index_path();
    const std::filesystem::path defaultOsvDatabasePath = default_osv_database_path();
    if (root == defaultIndexPath && std::filesystem::path(config.security.osvDatabasePath) != defaultOsvDatabasePath) {
        root = config.security.osvDatabasePath;
    }
    return (root / ecosystem).string();
}

bool findings_contain_sync_error(const std::vector<ValidationFinding>& findings) {
    return std::any_of(findings.begin(), findings.end(),
                       [](const ValidationFinding& finding) { return finding.kind == "sync_error"; });
}

} // namespace

SecurityGatewayService::SecurityGatewayService(PluginMetadataProvider* metadataProvider, const SecuritySettings& config)
    : metadataProvider(metadataProvider), config(config) {}

std::string SecurityGatewayService::normalizeGatewayName(const std::string& gateway) const {
    return to_lower_copy(gateway);
}

std::set<std::string> SecurityGatewayService::discoverSecurityProviders() const {
    std::set<std::string> providers;
    if (!this->config.security.enabled || this->metadataProvider == nullptr) {
        return providers;
    }

    for (const std::string& name : this->metadataProvider->getKnownPluginNames()) {
        const auto metadata = this->metadataProvider->getPluginSecurityMetadata(name);
        if (!metadata.has_value()) {
            continue;
        }
        if (this->normalizeGatewayName(metadata->role) != "security-provider") {
            continue;
        }
        providers.insert(this->normalizeGatewayName(name));
    }

    return providers;
}

std::set<std::string> SecurityGatewayService::configuredGatewayNames() const {
    std::set<std::string> names;
    if (!this->config.security.enabled) {
        return names;
    }
    if (this->config.security.gateways.empty()) {
        names.insert(this->normalizeGatewayName(this->config.security.defaultGateway));
        const std::set<std::string> discoveredProviders = this->discoverSecurityProviders();
        names.insert(discoveredProviders.begin(), discoveredProviders.end());
        return names;
    }
    for (const auto& [name, gateway] : this->config.security.gateways) {
        if (gateway.enabled) {
            names.insert(name);
        }
    }
    const std::set<std::string> discoveredProviders = this->discoverSecurityProviders();
    names.insert(discoveredProviders.begin(), discoveredProviders.end());
    return names;
}

bool SecurityGatewayService::isGatewaySystem(const std::string& system) const {
    return this->configuredGatewayNames().contains(this->normalizeGatewayName(system));
}

std::set<std::string> SecurityGatewayService::resolveGatewayBackends(const std::string& gateway) const {
    const std::string normalizedGateway = this->normalizeGatewayName(gateway);
    std::set<std::string> discoveredProviders = this->discoverSecurityProviders();
    if (discoveredProviders.contains(normalizedGateway)) {
        return {normalizedGateway};
    }
    if (this->config.security.gateways.empty()) {
        if (discoveredProviders.empty()) {
            return {rqp::sync_backend::kOsv};
        }
        return discoveredProviders;
    }
    const auto it = this->config.security.gateways.find(normalizedGateway);
    if (it == this->config.security.gateways.end()) {
        if (normalizedGateway == this->normalizeGatewayName(this->config.security.defaultGateway)) {
            if (discoveredProviders.empty()) {
                return {rqp::sync_backend::kOsv};
            }
            return discoveredProviders;
        }
        return {};
    }
    if (!it->second.enabled) {
        return {};
    }

    std::set<std::string> backends;
    for (const std::string& backend : it->second.backends) {
        if (!backend.empty()) {
            backends.insert(backend);
        }
    }
    return backends;
}

std::optional<std::string> SecurityGatewayService::resolveCanonicalEcosystem(const std::string& target) const {
    if (!this->config.security.enabled || target.empty()) {
        return std::nullopt;
    }

    const std::string normalizedTarget = to_lower_copy(target);
    if (const auto it = this->config.security.ecosystemMap.find(normalizedTarget);
        it != this->config.security.ecosystemMap.end()) {
        return it->second;
    }
    if (const auto it = this->config.security.osvEcosystemMap.find(normalizedTarget);
        it != this->config.security.osvEcosystemMap.end()) {
        return it->second;
    }
    if (this->metadataProvider != nullptr) {
        if (const auto metadata = this->metadataProvider->getPluginSecurityMetadata(normalizedTarget);
            metadata.has_value() && !metadata->osvEcosystem.empty()) {
            return metadata->osvEcosystem;
        }
    }

    return std::nullopt;
}

std::set<std::string> SecurityGatewayService::resolvePackageEcosystems(const std::vector<Package>& packages) const {
    std::set<std::string> ecosystems;
    if (!this->config.security.enabled) {
        return ecosystems;
    }
    for (const Package& package : packages) {
        std::string ecosystem;
        if (this->metadataProvider != nullptr) {
            if (const auto metadata = this->metadataProvider->getPluginSecurityMetadata(package.system);
                metadata.has_value()) {
                ecosystem = metadata->osvEcosystem;
            }
        }
        if (ecosystem.empty()) {
            if (const auto resolved = this->resolveCanonicalEcosystem(package.system); resolved.has_value()) {
                ecosystem = resolved.value();
            }
        }
        if (!ecosystem.empty()) {
            ecosystems.insert(ecosystem);
        }
    }
    return ecosystems;
}

std::vector<ValidationFinding> SecurityGatewayService::ensureEcosystemsReady(const std::set<std::string>& ecosystems,
                                                                             const std::string& gateway,
                                                                             bool forceRefresh) const {
    if (!this->config.security.enabled || ecosystems.empty()) {
        return {};
    }

    const std::string gatewayName = gateway.empty() ? this->config.security.defaultGateway : gateway;
    const std::set<std::string> backends = this->resolveGatewayBackends(gatewayName);
    if (backends.empty()) {
        return {ValidationFinding{
            .kind = "sync_error",
            .source = gatewayName.empty() ? "security" : gatewayName,
            .severity = "high",
            .message = "no configured security backends for gateway '" + gatewayName + "'",
        }};
    }

    std::vector<ValidationFinding> findings;
    bool anySuccess = false;

    for (const std::string& backendId : backends) {
        const SyncBackendRegistration* backend = find_sync_backend(backendId);
        if (backend == nullptr) {
            findings.push_back(ValidationFinding{
                .kind = "sync_warning",
                .source = backendId,
                .severity = "low",
                .message = "security backend is not available in this build",
            });
            anySuccess = true;
            continue;
        }

        SecuritySettings backendConfig = this->config;
        if (backend->mergeGatewayBackendConfig) {
            backend->mergeGatewayBackendConfig(backendConfig, this->config, backendId);
        }
        if (forceRefresh && backend->applyForceRefresh) {
            backend->applyForceRefresh(backendConfig, backendId);
        }

        if (backend->scope == SyncBackendScope::MultiEcosystem) {
            SyncBackendContext ctx{
                .database = nullptr,
                .metadataProvider = this->metadataProvider,
                .config = backendConfig,
                .ecosystems = ecosystems,
                .forceRefresh = forceRefresh,
            };
            const std::vector<ValidationFinding> backendFindings = backend->run(ctx);
            if (!findings_contain_sync_error(backendFindings)) {
                anySuccess = true;
            }
            findings.insert(findings.end(), backendFindings.begin(), backendFindings.end());
            continue;
        }

        for (const std::string& ecosystem : ecosystems) {
            security_log_stdout("security sync: backend=" + backendId + " ecosystem=" + ecosystem);
            SecuritySettings ecosystemConfig = backendConfig;
            ecosystemConfig.security.osvDatabasePath = package_index_path_for_ecosystem(backendConfig, ecosystem);
            VulnerabilityDatabase database(ecosystemConfig);

            SyncBackendContext ctx{
                .database = &database,
                .metadataProvider = this->metadataProvider,
                .config = ecosystemConfig,
                .ecosystems = {ecosystem},
                .forceRefresh = forceRefresh,
            };
            const std::vector<ValidationFinding> syncFindings = backend->run(ctx);
            if (!findings_contain_sync_error(syncFindings)) {
                anySuccess = true;
            }
            findings.insert(findings.end(), syncFindings.begin(), syncFindings.end());
        }
    }

    if (!anySuccess && !ecosystems.empty()) {
        findings.push_back(ValidationFinding{
            .kind = "sync_error",
            .source = gatewayName,
            .severity = "high",
            .message = "failed to populate requested security ecosystems",
        });
    }

    return findings;
}

std::vector<ValidationFinding>
SecurityGatewayService::executeGatewayRequest(ActionType action, const std::string& gateway,
                                              const std::vector<Package>& packages) const {
    if (!this->config.security.enabled) {
        return {};
    }

    if (action != ActionType::INSTALL && action != ActionType::UPDATE && action != ActionType::ENSURE) {
        return {ValidationFinding{
            .kind = "sync_error",
            .source = gateway,
            .severity = "high",
            .message = "unsupported security gateway action",
        }};
    }

    const std::string gatewayName = gateway.empty() ? this->config.security.defaultGateway : gateway;
    const std::set<std::string> backends = this->resolveGatewayBackends(gatewayName);
    bool allowRawGatewayEcosystems = backends.size() == 1;
    if (allowRawGatewayEcosystems) {
        const SyncBackendRegistration* backend = find_sync_backend(*backends.begin());
        allowRawGatewayEcosystems =
            backend != nullptr && backend->allowsRawPackageNamesAsEcosystem;
    } else {
        allowRawGatewayEcosystems = false;
    }

    std::set<std::string> ecosystems;
    for (const Package& package : packages) {
        if (const auto resolved = this->resolveCanonicalEcosystem(package.name); resolved.has_value()) {
            ecosystems.insert(resolved.value());
        } else if (allowRawGatewayEcosystems && !package.name.empty()) {
            ecosystems.insert(package.name);
        }
    }
    return this->ensureEcosystemsReady(ecosystems, gateway, action == ActionType::UPDATE);
}

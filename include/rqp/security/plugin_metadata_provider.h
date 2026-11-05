#pragma once

#include "rqp/security/version_compare.h"

#include <optional>
#include <string>
#include <vector>

struct PluginWriteScope {
    std::string kind;
    std::string value;

    bool operator==(const PluginWriteScope& other) const = default;
};

struct PluginNetworkScope {
    std::string host;
    std::string scheme;
    std::string pathPrefix;

    bool operator==(const PluginNetworkScope& other) const = default;
};

struct PluginSecurityMetadata {
    std::string role{"package-manager"};
    std::vector<std::string> capabilities;
    std::vector<std::string> ecosystemScopes;
    std::vector<PluginWriteScope> writeScopes;
    std::vector<PluginNetworkScope> networkScopes;
    std::string privilegeLevel{"none"};
    std::string osvEcosystem;
    std::string purlType;
    VersionComparatorSpec versionComparator{};
};

class PluginMetadataProvider {
  public:
    virtual ~PluginMetadataProvider() = default;
    virtual std::optional<PluginSecurityMetadata> getPluginSecurityMetadata(const std::string& name) = 0;
    virtual std::vector<std::string> getKnownPluginNames() {
        return {};
    }
};

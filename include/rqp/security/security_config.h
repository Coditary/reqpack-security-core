#pragma once

#include <map>
#include <string>
#include <vector>

enum class SeverityLevel { UNASSIGNED, LOW, MEDIUM, HIGH, CRITICAL };

enum class UnsafeAction { CONTINUE, PROMPT, ABORT };

enum class OsvRefreshMode { MANUAL, PERIODIC, ALWAYS };

struct SecurityGatewayConfig {
    bool enabled{true};
    std::vector<std::string> backends{};
};

struct SecurityBackendConfig {
    bool enabled{true};
    std::string feedUrl{};
    OsvRefreshMode refreshMode{OsvRefreshMode::MANUAL};
    long refreshIntervalSeconds{24L * 60L * 60L};
    std::string overlayPath{};
    std::string apiBaseUrl{};
    std::string apiVersion{};
    std::string tokenEnv{};
    std::string orgId{};
    std::string groupId{};
    std::string dataset{};
    std::vector<std::string> dbRepositories{};
    std::string helperPath{};
};

struct SecurityConfig {
    bool enabled{false};
    bool autoFetch{true};
    bool requireThinLayer{false};
    SeverityLevel severityThreshold{SeverityLevel::CRITICAL};
    double scoreThreshold{0.0};
    UnsafeAction onUnsafe{UnsafeAction::CONTINUE};
    bool promptOnUnsafe{false};
    bool allowUnassigned{true};
    std::string defaultGateway{"security"};
    std::string cachePath{};
    std::string indexPath{};
    std::string osvDatabasePath{};
    std::string osvFeedUrl{"https://storage.googleapis.com/osv-vulnerabilities"};
    OsvRefreshMode osvRefreshMode{OsvRefreshMode::MANUAL};
    long osvRefreshIntervalSeconds{24L * 60L * 60L};
    std::string osvOverlayPath{};
    std::vector<std::string> ignoreVulnerabilityIds{};
    std::vector<std::string> allowVulnerabilityIds{};
    std::map<std::string, std::string> ecosystemMap{};
    std::map<std::string, std::string> osvEcosystemMap{};
    std::map<std::string, SecurityGatewayConfig> gateways{};
    std::map<std::string, SecurityBackendConfig> backends{};
    UnsafeAction onUnresolvedVersion{UnsafeAction::CONTINUE};
    bool strictEcosystemMapping{false};
    bool includeWithdrawnInReport{false};
};

inline std::string to_string(SeverityLevel severity) {
    switch (severity) {
    case SeverityLevel::CRITICAL:
        return "critical";
    case SeverityLevel::HIGH:
        return "high";
    case SeverityLevel::MEDIUM:
        return "medium";
    case SeverityLevel::LOW:
        return "low";
    case SeverityLevel::UNASSIGNED:
    default:
        return "unassigned";
    }
}

inline std::string to_string(UnsafeAction action) {
    switch (action) {
    case UnsafeAction::PROMPT:
        return "prompt";
    case UnsafeAction::ABORT:
        return "abort";
    case UnsafeAction::CONTINUE:
    default:
        return "continue";
    }
}

inline std::string to_string(OsvRefreshMode mode) {
    switch (mode) {
    case OsvRefreshMode::PERIODIC:
        return "periodic";
    case OsvRefreshMode::ALWAYS:
        return "always";
    case OsvRefreshMode::MANUAL:
    default:
        return "manual";
    }
}

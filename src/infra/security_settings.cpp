#include "rqp/security/security_settings.h"

#include "rqp/security/security_paths.h"
#include "rqp/security/sync_backend_registry.h"

#include <algorithm>
#include <cctype>
#include <filesystem>

namespace {

std::filesystem::path security_index_root(const SecuritySettings& settings) {
    std::filesystem::path root = settings.security.indexPath;
    const std::filesystem::path defaultIndexPath = default_security_index_path();
    const std::filesystem::path defaultOsvDatabasePath = default_osv_database_path();
    if (root == defaultIndexPath &&
        std::filesystem::path(settings.security.osvDatabasePath) != defaultOsvDatabasePath) {
        root = settings.security.osvDatabasePath;
    }
    return root;
}

void populate_default_backends(SecurityConfig& security) {
    sync_backend_apply_registered_defaults(security);
}

} // namespace

SecuritySettings default_security_settings() {
    SecuritySettings settings;
    settings.security.cachePath = default_security_cache_path().string();
    settings.security.indexPath = default_security_index_path().string();
    settings.security.osvDatabasePath = default_osv_database_path().string();
    populate_default_backends(settings.security);
    return settings;
}

SecuritySettings ecosystem_db_settings(const SecuritySettings& settings, const std::string& ecosystem) {
    SecuritySettings dbSettings = settings;
    dbSettings.security.osvDatabasePath = (security_index_root(settings) / ecosystem).string();
    return dbSettings;
}

bool apply_security_preset(SecurityConfig& security, const std::string& preset) {
    std::string normalized = preset;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (normalized.empty() || normalized == "custom") {
        return true;
    }
    if (normalized == "dev") {
        security.enabled = true;
        security.onUnsafe = UnsafeAction::CONTINUE;
        security.strictEcosystemMapping = false;
        security.osvRefreshMode = OsvRefreshMode::MANUAL;
        security.auditFailOnFindings = false;
        security.autoFetch = true;
        return true;
    }
    if (normalized == "ci") {
        security.enabled = true;
        security.onUnsafe = UnsafeAction::ABORT;
        security.strictEcosystemMapping = true;
        security.autoFetch = true;
        security.osvRefreshMode = OsvRefreshMode::PERIODIC;
        security.auditFailOnFindings = true;
        security.severityThreshold = SeverityLevel::HIGH;
        return true;
    }
    if (normalized == "strict") {
        security.enabled = true;
        security.onUnsafe = UnsafeAction::ABORT;
        security.onUnresolvedVersion = UnsafeAction::ABORT;
        security.strictEcosystemMapping = true;
        security.auditFailOnFindings = true;
        security.severityThreshold = SeverityLevel::CRITICAL;
        security.autoFetch = true;
        return true;
    }
    return false;
}

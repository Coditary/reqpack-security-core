#include "rqp/security/security_settings.h"

#include "rqp/security/security_paths.h"

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
    if (!security.backends.contains("osv")) {
        SecurityBackendConfig osvBackend;
        osvBackend.feedUrl = security.osvFeedUrl;
        osvBackend.refreshMode = security.osvRefreshMode;
        osvBackend.refreshIntervalSeconds = security.osvRefreshIntervalSeconds;
        osvBackend.overlayPath = security.osvOverlayPath;
        security.backends["osv"] = std::move(osvBackend);
    }
    if (!security.backends.contains("snyk")) {
        SecurityBackendConfig snykBackend;
        snykBackend.apiBaseUrl = "https://api.snyk.io/rest";
        snykBackend.apiVersion = "2024-10-15";
        snykBackend.tokenEnv = "SNYK_TOKEN";
        snykBackend.dataset = "issues";
        security.backends["snyk"] = std::move(snykBackend);
    }
    if (!security.backends.contains("trivy")) {
        SecurityBackendConfig trivyBackend;
        trivyBackend.dbRepositories = {
            "mirror.gcr.io/aquasec/trivy-db:2",
            "ghcr.io/aquasecurity/trivy-db:2",
        };
        security.backends["trivy"] = std::move(trivyBackend);
    }
    if (!security.backends.contains("gh-advisory")) {
        SecurityBackendConfig ghAdvisoryBackend;
        ghAdvisoryBackend.feedUrl = "https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main";
        security.backends["gh-advisory"] = std::move(ghAdvisoryBackend);
    }
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

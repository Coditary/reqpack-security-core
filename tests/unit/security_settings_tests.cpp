#include <catch2/catch.hpp>

#include "rqp/security/security_paths.h"
#include "rqp/security/security_settings.h"
#include "test_helpers.h"

TEST_CASE("default security paths resolve under expected XDG directories", "[unit][security_paths]") {
    const std::filesystem::path dataDir = default_security_data_directory();
    const std::filesystem::path cacheDir = default_security_cache_directory();
    CHECK(default_security_index_path().string().find(dataDir.string()) == 0);
    CHECK(default_osv_database_path().string().find(dataDir.string()) == 0);
    CHECK(default_security_cache_directory().string().find(cacheDir.string()) == 0);
    CHECK(default_security_cache_path().string().find(cacheDir.string()) == 0);
}

TEST_CASE("default security settings populate backend defaults", "[unit][security_settings]") {
    const SecuritySettings settings = default_security_settings();

    CHECK(settings.security.backends.contains("osv"));
    CHECK(settings.security.backends.contains("snyk"));
    CHECK(settings.security.backends.contains("trivy"));
    CHECK(settings.security.backends.contains("gh-advisory"));
    CHECK_FALSE(settings.security.backends.at("snyk").tokenEnv.empty());
}

TEST_CASE("ecosystem db settings point at per-ecosystem index path", "[unit][security_settings]") {
    TempDir tempDir{"security-settings"};
    SecuritySettings settings = test_security_settings();
    settings.security.indexPath = (tempDir.path() / "index").string();
    settings.security.osvDatabasePath = (tempDir.path() / "db").string();

    const SecuritySettings debian = ecosystem_db_settings(settings, "Debian");
    CHECK(debian.security.osvDatabasePath == (tempDir.path() / "index" / "Debian").string());
}

#include <catch2/catch.hpp>

#include "rqp/security/security_paths.h"
#include "rqp/security/security_settings.h"
#include "rqp/security/sync_backend_registry.h"
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

    CHECK(settings.security.backends.contains(rqp::sync_backend::kOsv));
    if (sync_backend_is_registered(rqp::sync_backend::kSnyk)) {
        CHECK(settings.security.backends.contains(rqp::sync_backend::kSnyk));
        CHECK_FALSE(settings.security.backends.at(rqp::sync_backend::kSnyk).tokenEnv.empty());
    }
    if (sync_backend_is_registered(rqp::sync_backend::kTrivy)) {
        CHECK(settings.security.backends.contains(rqp::sync_backend::kTrivy));
    }
    if (sync_backend_is_registered(rqp::sync_backend::kGhAdvisory)) {
        CHECK(settings.security.backends.contains(rqp::sync_backend::kGhAdvisory));
    }
}

TEST_CASE("security presets apply expected policy defaults", "[unit][security_settings]") {
    SecurityConfig security = default_security_settings().security;
    REQUIRE(apply_security_preset(security, "ci"));
    CHECK(security.onUnsafe == UnsafeAction::ABORT);
    CHECK(security.strictEcosystemMapping);
    CHECK(security.auditFailOnFindings);
    CHECK(security.severityThreshold == SeverityLevel::HIGH);

    security = default_security_settings().security;
    REQUIRE(apply_security_preset(security, "dev"));
    CHECK(security.onUnsafe == UnsafeAction::CONTINUE);
    CHECK_FALSE(security.auditFailOnFindings);
}

TEST_CASE("ecosystem db settings point at per-ecosystem index path", "[unit][security_settings]") {
    TempDir tempDir{"security-settings"};
    SecuritySettings settings = test_security_settings();
    settings.security.indexPath = (tempDir.path() / "index").string();
    settings.security.osvDatabasePath = (tempDir.path() / "db").string();

    const SecuritySettings debian = ecosystem_db_settings(settings, "Debian");
    CHECK(debian.security.osvDatabasePath == (tempDir.path() / "index" / "Debian").string());
}

#include <catch2/catch.hpp>

#include "rqp/security/vulnerability_database.h"
#include "sync/snyk/snyk_vulnerability_sync_service.h"
#include "sync/trivy/trivy_vulnerability_sync_service.h"
#include "test_helpers.h"

TEST_CASE("snyk sync service reports missing backend configuration", "[unit][snyk][sync]") {
    TempDir tempDir{"snyk-sync-config"};
    SecuritySettings config = test_security_settings();
    config.security.backends.erase("snyk");
    config.security.indexPath = (tempDir.path() / "index").string();
    config.security.osvDatabasePath = (tempDir.path() / "db").string();

    VulnerabilityDatabase database(config);
    SnykVulnerabilitySyncService syncService(&database, {"Maven"}, config);
    const std::vector<ValidationFinding> findings = syncService.ensureReady(true);
    REQUIRE_FALSE(findings.empty());
    CHECK(findings.front().source == "snyk");
}

TEST_CASE("trivy sync service reports missing helper binary", "[unit][trivy][sync]") {
    TempDir tempDir{"trivy-sync-helper"};
    const std::filesystem::path trivyRoot = tempDir.path() / "trivy-db";
    write_file(trivyRoot / "metadata.json", R"({"Version":2})");
    write_file(trivyRoot / "trivy.db", "fixture");

    SecuritySettings config = test_security_settings();
    config.security.indexPath = (tempDir.path() / "index").string();
    config.security.osvDatabasePath = (tempDir.path() / "db").string();
    config.security.cachePath = (tempDir.path() / "cache").string();
    config.security.backends["trivy"].dbRepositories = {"file://" + trivyRoot.string()};
    config.security.backends["trivy"].helperPath = (tempDir.path() / "missing-helper").string();
    config.security.backends["trivy"].refreshMode = OsvRefreshMode::ALWAYS;

    VulnerabilityDatabase database(config);
    TrivyVulnerabilitySyncService syncService(&database, {"Maven"}, config);
    const std::vector<ValidationFinding> findings = syncService.ensureReady(true);
    REQUIRE_FALSE(findings.empty());
    CHECK(findings.front().message.find("helper") != std::string::npos);
}

TEST_CASE("trivy sync service imports helper output into database", "[unit][trivy][sync]") {
    TempDir tempDir{"trivy-sync-success"};
    const std::filesystem::path trivyRoot = tempDir.path() / "trivy-db";
    const std::filesystem::path helperPath = tempDir.path() / "trivy-helper.sh";
    write_file(trivyRoot / "metadata.json", R"({"Version":2})");
    write_file(trivyRoot / "trivy.db", "fixture");
    write_file(helperPath,
               "#!/bin/sh\n"
               "printf '%s\\n' "
               "'{\"ecosystem\":\"Maven\",\"packageName\":\"org.example:demo\",\"advisoryId\":\"CVE-TRIVY-1\","
               "\"aliases\":[],\"summary\":\"demo\",\"description\":\"desc\",\"severity\":\"HIGH\",\"score\":8.5,"
               "\"references\":[],\"modified\":\"2026-01-01T00:00:00Z\",\"published\":\"2026-01-01T00:00:00Z\","
               "\"versions\":[],\"ranges\":[{\"introduced\":\"1.0\",\"fixed\":\"2.0\"}]}'\n");
    REQUIRE(std::system((std::string{"chmod +x "} + helperPath.string()).c_str()) == 0);

    SecuritySettings config = test_security_settings();
    config.security.indexPath = (tempDir.path() / "index").string();
    config.security.osvDatabasePath = (tempDir.path() / "db").string();
    config.security.cachePath = (tempDir.path() / "cache").string();
    config.security.backends["trivy"].dbRepositories = {"file://" + trivyRoot.string()};
    config.security.backends["trivy"].helperPath = helperPath.string();
    config.security.backends["trivy"].refreshMode = OsvRefreshMode::ALWAYS;

    VulnerabilityDatabase database(config);
    TrivyVulnerabilitySyncService syncService(&database, {"Maven"}, config);
    CHECK(syncService.ensureReady(true).empty());

    VulnerabilityDatabase mavenDatabase(config);
    REQUIRE(mavenDatabase.ensureReady());
    CHECK(mavenDatabase.advisoryIdsForPackage("Maven", "org.example:demo").size() == 1);
}

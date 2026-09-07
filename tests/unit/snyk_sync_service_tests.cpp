#include <catch2/catch.hpp>

#include "rqp/security/snyk_vulnerability_sync_service.h"
#include "rqp/security/vulnerability_database.h"
#include "test_helpers.h"

TEST_CASE("snyk sync service imports maven advisories from file-backed api fixtures", "[unit][snyk][sync]") {
    TempDir tempDir{"snyk-sync-success"};
    const std::filesystem::path apiRoot = tempDir.path() / "snyk-api" / "orgs" / "org-1";
    const std::filesystem::path exportFile = tempDir.path() / "export.csv";
    write_file(apiRoot / "export.json", R"({"export_id":"exp-1"})");
    write_file(apiRoot / "jobs" / "export" / "exp-1.json", R"({"status":"FINISHED"})");
    write_file(apiRoot / "export" / "exp-1.json",
               std::string{"{"} + "\"download_url\":\"file://" + exportFile.string() + "\"}");
    write_file(exportFile,
               "PROBLEM_ID,PROBLEM_TITLE,CVE,PACKAGE_NAME_AND_VERSION,SEMVER_VULNERABLE_RANGE,ISSUE_SEVERITY,NVD_SCORE,"
               "SNYK_CVSS_SCORE,UPDATED_AT,FIXED_IN_VERSION,PRODUCT_NAME\n"
               "SNYK-JAVA-LOG4J-1,Remote code "
               "execution,CVE-2026-1,pkg:maven/org.apache.logging.log4j/"
               "log4j-core@2.14.1,\"[,2.15.0)\",critical,9.8,9.8,2026-01-01T00:00:00Z,2.15.0,Snyk Open Source\n");

    SecuritySettings config = test_security_settings();
    config.security.osvDatabasePath = (tempDir.path() / "db").string();
    config.security.cachePath = (tempDir.path() / "cache").string();
    config.security.backends["snyk"].apiBaseUrl = "file://" + (tempDir.path() / "snyk-api").string();
    config.security.backends["snyk"].apiVersion = "2024-10-15";
    config.security.backends["snyk"].tokenEnv = "REQPACK_TEST_SNYK_TOKEN";
    config.security.backends["snyk"].orgId = "org-1";
    config.security.backends["snyk"].dataset = "issues";
    config.security.backends["snyk"].refreshMode = OsvRefreshMode::ALWAYS;
    ScopedEnvVar token{"REQPACK_TEST_SNYK_TOKEN", "token-1"};

    VulnerabilityDatabase database(config);
    SnykVulnerabilitySyncService syncService(&database, {"Maven"}, config);
    CHECK(syncService.ensureReady(true).empty());
    CHECK(database.advisoryIdsForPackage("Maven", "org.apache.logging.log4j:log4j-core").size() == 1);
}

TEST_CASE("snyk sync service reports invalid org and group configuration", "[unit][snyk][sync]") {
    TempDir tempDir{"snyk-sync-org-group"};
    SecuritySettings config = test_security_settings();
    config.security.osvDatabasePath = (tempDir.path() / "db").string();
    config.security.backends["snyk"].tokenEnv = "REQPACK_TEST_SNYK_TOKEN";
    config.security.backends["snyk"].orgId = "org-1";
    config.security.backends["snyk"].groupId = "group-1";
    ScopedEnvVar token{"REQPACK_TEST_SNYK_TOKEN", "token-1"};

    VulnerabilityDatabase database(config);
    SnykVulnerabilitySyncService syncService(&database, {"Maven"}, config);
    const std::vector<ValidationFinding> findings = syncService.ensureReady(true);
    REQUIRE_FALSE(findings.empty());
    CHECK(findings.front().message.find("orgId or groupId") != std::string::npos);
}

TEST_CASE("snyk sync service reports missing api token", "[unit][snyk][sync]") {
    TempDir tempDir{"snyk-sync-token"};
    SecuritySettings config = test_security_settings();
    config.security.osvDatabasePath = (tempDir.path() / "db").string();
    config.security.backends["snyk"].tokenEnv = "REQPACK_MISSING_SNYK_TOKEN";
    config.security.backends["snyk"].orgId = "org-1";
    ScopedEnvVar unsetToken{"REQPACK_MISSING_SNYK_TOKEN", nullptr};

    VulnerabilityDatabase database(config);
    SnykVulnerabilitySyncService syncService(&database, {"Maven"}, config);
    const std::vector<ValidationFinding> findings = syncService.ensureReady(true);
    REQUIRE_FALSE(findings.empty());
    CHECK(findings.front().message.find("missing Snyk API token") != std::string::npos);
}

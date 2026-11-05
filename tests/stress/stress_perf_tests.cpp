#include <catch2/catch.hpp>

#include "adapters/matching/lmdb_ecosystem_advisory_resolver.h"
#include "rqp/security/exchange.h"
#include "rqp/security/osv_core.h"
#include "rqp/security/version_compare.h"
#include "rqp/security/vulnerability_database.h"
#include "rqp/security/vulnerability_matcher.h"
#include "stress_helpers.h"
#include "test_helpers.h"

#include <string>

namespace {

constexpr std::size_t kDefaultParseOps = 5000;
constexpr std::size_t kDefaultAdvisories = 750;
constexpr std::size_t kDefaultPackages = 750;
constexpr std::size_t kDefaultAliasLookups = 20000;
constexpr std::size_t kDefaultVersionCompareOps = 50000;
constexpr std::size_t kDefaultSbomPackages = 2000;

} // namespace

TEST_CASE("stress osv_parse_advisory throughput", "[stress][osv]") {
    const std::size_t operations = stress_env_size("RQP_STRESS_PARSE_OPS", kDefaultParseOps);
    const std::string sample = stress_advisory_json(0);

    StressStopwatch watch;
    std::size_t parsed = 0;
    for (std::size_t index = 0; index < operations; ++index) {
        const std::optional<OsvAdvisory> advisory = osv_parse_advisory(sample);
        REQUIRE(advisory.has_value());
        ++parsed;
    }

    stress_log_line("osv_parse_advisory", watch.elapsed_ms(), parsed);
    CHECK(parsed == operations);
}

TEST_CASE("stress version_compare throughput", "[stress][version]") {
    const std::size_t operations = stress_env_size("RQP_STRESS_VERSION_COMPARE_OPS", kDefaultVersionCompareOps);

    StressStopwatch watch;
    for (std::size_t index = 0; index < operations; ++index) {
        const bool left = version_compare_values("1.2." + std::to_string(index % 10), "1.2.9") < 0;
        const bool right = version_compare_values("2.0." + std::to_string(index % 7), "1.99.0") > 0;
        REQUIRE((left || right));
    }

    stress_log_line("version_compare", watch.elapsed_ms(), operations);
}

TEST_CASE("stress vulnerability database bulk upsert and package load", "[stress][database]") {
    const std::size_t advisoryCount = stress_env_size("RQP_STRESS_ADVISORIES", kDefaultAdvisories);

    TempDir tempDir{"reqpack-stress-db"};
    SecuritySettings config = test_security_settings();
    stress_apply_ecosystem_map(config);
    config.security.osvDatabasePath = (tempDir.path() / "db").string();

    VulnerabilityDatabase database(config);
    REQUIRE(database.ensureReady());

    std::vector<OsvAdvisory> advisories;
    advisories.reserve(advisoryCount);
    for (std::size_t index = 0; index < advisoryCount; ++index) {
        advisories.push_back(stress_advisory(index));
    }

    StressStopwatch upsertWatch;
    REQUIRE(database.upsertAdvisories(advisories, 256));
    const double upsertMs = upsertWatch.elapsed_ms();
    stress_log_line("db_upsert_advisories", upsertMs, advisoryCount);

    StressStopwatch loadWatch;
    std::size_t loadedRows = 0;
    for (std::size_t index = 0; index < advisoryCount; ++index) {
        const std::vector<OsvAdvisory> rows =
            database.loadAdvisoriesForPackage(stress_osv_ecosystem(), stress_package_name(index));
        REQUIRE(rows.size() == 1);
        CHECK(rows.front().id == stress_advisory_id(index));
        ++loadedRows;
    }
    stress_log_line("db_load_by_package", loadWatch.elapsed_ms(), loadedRows);

    const std::size_t aliasLookups = stress_env_size("RQP_STRESS_ALIAS_LOOKUPS", kDefaultAliasLookups);
    StressStopwatch aliasWatch;
    for (std::size_t index = 0; index < aliasLookups; ++index) {
        const std::size_t advisoryIndex = index % advisoryCount;
        const auto resolved = database.resolveAlias(stress_advisory_id(advisoryIndex));
        REQUIRE(resolved.has_value());
        CHECK(resolved.value() == stress_advisory_id(advisoryIndex));
    }
    stress_log_line("db_resolve_alias", aliasWatch.elapsed_ms(), aliasLookups);
}

TEST_CASE("stress vulnerability matcher graph scan", "[stress][matcher]") {
    const std::size_t advisoryCount = stress_env_size("RQP_STRESS_ADVISORIES", kDefaultAdvisories);
    const std::size_t packageCount = stress_env_size("RQP_STRESS_PACKAGES", kDefaultPackages);
    REQUIRE(packageCount <= advisoryCount);

    TempDir tempDir{"reqpack-stress-matcher"};
    SecuritySettings config = test_security_settings();
    stress_apply_ecosystem_map(config);
    config.security.osvDatabasePath = (tempDir.path() / "db").string();
    config.security.indexPath = (tempDir.path() / "index").string();

    VulnerabilityDatabase database(config);
    REQUIRE(database.ensureReady());

    std::vector<OsvAdvisory> advisories;
    advisories.reserve(advisoryCount);
    for (std::size_t index = 0; index < advisoryCount; ++index) {
        advisories.push_back(stress_advisory(index));
    }
    REQUIRE(database.upsertAdvisories(advisories, 256));

    LmdbEcosystemAdvisoryResolver advisoryResolver(config, static_cast<const IAdvisoryReader*>(&database));
    VulnerabilityMatcher matcher(nullptr, config);
    matcher.setEcosystemAdvisoryResolver(&advisoryResolver);

    const Graph graph = stress_package_graph(packageCount);

    StressStopwatch watch;
    const std::vector<ValidationFinding> findings = matcher.matchGraph(graph);
    const double elapsedMs = watch.elapsed_ms();

    std::size_t vulnerabilityFindings = 0;
    for (const ValidationFinding& finding : findings) {
        if (finding.kind == "vulnerability") {
            ++vulnerabilityFindings;
            CHECK(finding.severity != "");
        }
    }
    REQUIRE(vulnerabilityFindings == packageCount);

    std::ostringstream detail;
    detail << packageCount << " packages, " << vulnerabilityFindings << " vuln findings, " << findings.size()
           << " total";
    stress_log_line("matcher_match_graph", elapsedMs, packageCount, detail.str());
}

TEST_CASE("stress exchange pipeline decode large reqpack sbom", "[stress][exchange]") {
    const std::size_t packageCount = stress_env_size("RQP_STRESS_SBOM_PACKAGES", kDefaultSbomPackages);
    const std::string input = stress_reqpack_sbom_json(packageCount);

    const auto codec = create_codec(ExchangeKind::INVENTORY);
    REQUIRE(codec != nullptr);
    IdentityTransform identity;

    StressStopwatch watch;
    const PipelineResult result =
        run_pipeline(input, WireFormat::REQPACK_SBOM_JSON, *codec, identity, WireFormat::REQPACK_SBOM_JSON, {});
    const double elapsedMs = watch.elapsed_ms();

    REQUIRE_FALSE(result.error.has_value());
    CHECK(result.payload.find(stress_package_name(0)) != std::string::npos);
    CHECK(result.payload.find(stress_package_name(packageCount - 1)) != std::string::npos);

    stress_log_line("exchange_sbom_roundtrip", elapsedMs, packageCount);
}

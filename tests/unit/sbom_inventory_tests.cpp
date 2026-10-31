#include <catch2/catch.hpp>

#include <boost/graph/graph_traits.hpp>

#include "rqp/security/osv_core.h"
#include "rqp/security/sbom_inventory.h"
#include "rqp/security/vulnerability_matcher.h"
#include "test_helpers.h"

namespace {

Package first_package(const Graph& graph) {
    auto [vertex, end] = boost::vertices(graph);
    REQUIRE(vertex != end);
    return graph[*vertex];
}

} // namespace

TEST_CASE("sbom inventory imports cyclonedx components with purl and reqpack system property",
          "[unit][sbom_inventory]") {
    const std::string json = R"({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "react",
                "version": "18.3.1",
                "purl": "pkg:npm/react@18.3.1",
                "properties": [
                    {"name": "reqpack:system", "value": "npm"}
                ]
            }
        ]
    })";

    const SbomImportResult imported = import_sbom_from_json(json);
    REQUIRE_FALSE(imported.error.has_value());
    CHECK(imported.detectedFormat == "cyclonedx");
    REQUIRE(boost::num_vertices(imported.graph) == 1);

    const Package package = first_package(imported.graph);
    CHECK(package.system == "npm");
    CHECK(package.name == "react");
    CHECK(package.version == "18.3.1");
    CHECK(package.action == ActionType::AUDIT);
}

TEST_CASE("sbom inventory imports spdx packages via purl", "[unit][sbom_inventory]") {
    const std::string json = R"({
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "ignored",
                "versionInfo": "ignored",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/requests@2.31.0"
                    }
                ]
            }
        ]
    })";

    const SbomImportResult imported = import_sbom_from_json(json);
    REQUIRE_FALSE(imported.error.has_value());
    CHECK(imported.detectedFormat == "spdx");
    REQUIRE(boost::num_vertices(imported.graph) == 1);

    const Package package = first_package(imported.graph);
    CHECK(package.system == "pip");
    CHECK(package.name == "requests");
    CHECK(package.version == "2.31.0");
}

TEST_CASE("sbom inventory imports reqpack sbom json and feeds validator audit", "[unit][sbom_inventory]") {
    const std::string json = R"({
        "packages": [
            {"system": "dnf", "name": "ripgrep", "version": "14.1"}
        ]
    })";

    SecuritySettings config = test_security_settings();
    config.security.osvEcosystemMap["dnf"] = "Debian";

    OsvAdvisory advisory;
    advisory.id = "CVE-sbom-audit";
    advisory.affected.push_back(OsvAffectedPackage{
        .ecosystem = "Debian",
        .name = "ripgrep",
        .versions = {"14.1"},
    });

    const SbomImportResult imported = import_sbom_from_json(json, config);
    REQUIRE_FALSE(imported.error.has_value());
    CHECK(imported.detectedFormat == "reqpack-json");

    VulnerabilityMatcher matcher(nullptr, config);
    matcher.setAdvisories({advisory});
    const std::vector<ValidationFinding> findings = matcher.matchGraph(imported.graph);
    REQUIRE(findings.size() == 1);
    CHECK(findings.front().id == "CVE-sbom-audit");
}

TEST_CASE("sbom inventory imports cyclonedx components from name version and type without purl",
          "[unit][sbom_inventory]") {
    const std::string json = R"({
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "npm",
                "name": "lodash",
                "version": "4.17.21"
            }
        ]
    })";

    const SbomImportResult imported = import_sbom_from_json(json);
    REQUIRE_FALSE(imported.error.has_value());
    const Package package = first_package(imported.graph);
    CHECK(package.system == "npm");
    CHECK(package.name == "lodash");
    CHECK(package.version == "4.17.21");
}

TEST_CASE("sbom inventory imports spdx packages from name and version when purl is absent", "[unit][sbom_inventory]") {
    const std::string json = R"({
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "curl",
                "versionInfo": "8.5.0"
            }
        ]
    })";

    const SbomImportResult imported = import_sbom_from_json(json);
    REQUIRE_FALSE(imported.error.has_value());
    const Package package = first_package(imported.graph);
    CHECK(package.system == "unknown");
    CHECK(package.name == "curl");
    CHECK(package.version == "8.5.0");
}

TEST_CASE("sbom inventory imports cyclonedx json from filesystem path", "[unit][sbom_inventory]") {
    TempDir tempDir{"sbom-inventory-path"};
    const std::filesystem::path sbomPath = tempDir.path() / "sbom.cdx.json";
    write_file(sbomPath, R"({
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0"}
        ]
    })");

    const SbomImportResult imported = import_sbom_from_path(sbomPath);
    REQUIRE_FALSE(imported.error.has_value());
    CHECK(imported.detectedFormat == "cyclonedx");
    const Package package = first_package(imported.graph);
    CHECK(package.system == "npm");
    CHECK(package.name == "left-pad");
}

TEST_CASE("sbom inventory deduplicates identical components", "[unit][sbom_inventory]") {
    const std::string json = R"({
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "dup", "version": "1.0.0", "purl": "pkg:npm/dup@1.0.0"},
            {"name": "dup", "version": "1.0.0", "purl": "pkg:npm/dup@1.0.0"}
        ]
    })";

    const SbomImportResult imported = import_sbom_from_json(json);
    REQUIRE_FALSE(imported.error.has_value());
    CHECK(boost::num_vertices(imported.graph) == 1);
}

TEST_CASE("sbom inventory reports undetectable and empty payloads", "[unit][sbom_inventory]") {
    const SbomImportResult empty = import_sbom_from_json("");
    REQUIRE(empty.error.has_value());

    const SbomImportResult unknown = import_sbom_from_json(R"({"metadata": {"timestamp": "now"}})");
    REQUIRE(unknown.error.has_value());

    TempDir tempDir{"sbom-inventory-missing"};
    const SbomImportResult missing = import_sbom_from_path(tempDir.path() / "missing.json");
    REQUIRE(missing.error.has_value());
}

TEST_CASE("sbom inventory honors explicit format override", "[unit][sbom_inventory]") {
    const std::string reqpackJson = R"({
        "packages": [
            {"system": "npm", "name": "pkg", "version": "1.0.0"}
        ]
    })";

    const SbomImportResult imported =
        import_sbom_from_json(reqpackJson, default_security_settings(), SbomInventoryFormat::REQPACK_JSON);
    REQUIRE_FALSE(imported.error.has_value());
    CHECK(imported.detectedFormat == "reqpack-json");
    CHECK(first_package(imported.graph).system == "npm");
}

TEST_CASE("sbom inventory parses maven purls", "[unit][sbom_inventory]") {
    const std::string json = R"({
        "bomFormat": "CycloneDX",
        "components": [
            {
                "name": "jackson-databind",
                "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.1"
            }
        ]
    })";

    const SbomImportResult imported = import_sbom_from_json(json);
    REQUIRE_FALSE(imported.error.has_value());
    const Package package = first_package(imported.graph);
    CHECK(package.system == "maven");
    CHECK(package.name == "com.fasterxml.jackson.core:jackson-databind");
    CHECK(package.version == "2.14.1");
}

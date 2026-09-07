#include <catch2/catch.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <system_error>

#include "rqp/security/osv_core.h"

namespace {

class TempDir {
  public:
    explicit TempDir(const std::string& prefix)
        : path_(std::filesystem::temp_directory_path() /
                (prefix + "-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))) {
        std::filesystem::create_directories(path_);
    }

    ~TempDir() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& path() const {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

void write_file(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    REQUIRE(output.is_open());
    output << content;
}

} // namespace

TEST_CASE("osv parser reads advisory fields and matches package versions", "[unit][osv][core]") {
    const std::string json = R"({
        "id": "GHSA-1234",
        "modified": "2026-01-01T00:00:00Z",
        "published": "2025-12-31T00:00:00Z",
        "aliases": ["CVE-2026-1"],
        "summary": "demo summary",
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        "affected": [{
            "package": {
                "ecosystem": "npm",
                "name": "react"
            },
            "versions": ["18.3.1"],
            "ranges": [{
                "type": "SEMVER",
                "events": [
                    {"introduced": "0"},
                    {"fixed": "19.0.0"}
                ]
            }]
        }]
    })";

    const auto advisory = osv_parse_advisory(json);
    REQUIRE(advisory.has_value());
    CHECK(advisory->id == "GHSA-1234");
    CHECK(advisory->aliases == std::vector<std::string>{"CVE-2026-1"});
    CHECK(advisory->severity == "critical");
    REQUIRE(advisory->affected.size() == 1);
    CHECK(advisory->affected[0].ecosystem == "npm");
    CHECK(advisory->affected[0].name == "react");

    const auto exactMatch = osv_match_package(advisory.value(), "npm", "react", "18.3.1");
    REQUIRE(exactMatch.has_value());
    CHECK(exactMatch->severity == "critical");
    CHECK(exactMatch->score == Approx(9.8));

    const auto miss = osv_match_package(advisory.value(), "npm", "react", "19.1.0");
    CHECK_FALSE(miss.has_value());
}

TEST_CASE("osv parser derives critical severity from CVSS vector string", "[unit][osv][core]") {
    const std::string json = R"({
        "id": "GHSA-jfh8-c2jp-5v3q",
        "modified": "2025-10-22T19:37:02Z",
        "summary": "Remote code injection in Log4j",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H"}],
        "affected": [{
            "package": {
                "ecosystem": "Maven",
                "name": "org.apache.logging.log4j:log4j-core"
            },
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "2.13.0"},
                    {"fixed": "2.15.0"}
                ]
            }]
        }]
    })";

    const auto advisory = osv_parse_advisory(json);
    REQUIRE(advisory.has_value());
    CHECK(advisory->severity == "critical");
    CHECK(advisory->score == Approx(10.0));

    const auto match = osv_match_package(advisory.value(), "Maven", "org.apache.logging.log4j:log4j-core", "2.14.1",
                                         VersionComparatorSpec{.profile = "maven-comparable"});
    REQUIRE(match.has_value());
    CHECK(match->severity == "critical");
    CHECK(match->score == Approx(10.0));
}

TEST_CASE("osv parser falls back to database severity when score is non-numeric", "[unit][osv][core]") {
    const std::string json = R"({
        "id": "GHSA-3pxv-7cmr-fjr4",
        "modified": "2026-04-16T11:29:10Z",
        "summary": "Silent log event loss",
        "database_specific": {
            "severity": "MODERATE"
        },
        "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N"}],
        "affected": [{
            "package": {
                "ecosystem": "Maven",
                "name": "org.apache.logging.log4j:log4j-core"
            },
            "versions": ["2.14.1"]
        }]
    })";

    const auto advisory = osv_parse_advisory(json);
    REQUIRE(advisory.has_value());
    CHECK(advisory->severity == "medium");
    CHECK(advisory->score == Approx(4.0));
    REQUIRE(advisory->affected.size() == 1);
    CHECK(advisory->affected[0].severity == "medium");
    CHECK(advisory->affected[0].score == Approx(4.0));
}

TEST_CASE("osv loader accepts top-level array files", "[unit][osv][core]") {
    TempDir tempDir{"reqpack-osv"};
    const std::filesystem::path path = tempDir.path() / "overlay.json";
    write_file(path, R"([
        {
            "id": "CVE-2026-1",
            "modified": "2026-01-01T00:00:00Z",
            "affected": [{"package": {"ecosystem": "npm", "name": "react"}}]
        },
        {
            "id": "CVE-2026-2",
            "modified": "2026-01-02T00:00:00Z",
            "affected": [{"package": {"ecosystem": "Maven", "name": "org.demo:lib"}}]
        }
    ])");

    const std::vector<OsvAdvisory> advisories = osv_load_advisories_from_path(path);
    REQUIRE(advisories.size() == 2);
    CHECK(advisories[0].id == "CVE-2026-1");
    CHECK(advisories[1].id == "CVE-2026-2");
}

TEST_CASE("osv helpers normalize names and collect package keys", "[unit][osv][core]") {
    CHECK(osv_to_lower_copy("Debian") == "debian");
    CHECK(osv_normalize_package_name("Foo/Bar") == "foo/bar");

    OsvAdvisory advisory;
    advisory.id = "GHSA-keys";
    advisory.affected.push_back(OsvAffectedPackage{.ecosystem = "npm", .name = "react", .versions = {"18.0"}});
    advisory.affected.push_back(OsvAffectedPackage{.ecosystem = "npm", .name = "React", .versions = {"19.0"}});

    const auto keys = osv_collect_package_keys(advisory);
    REQUIRE(keys.size() == 2);
    CHECK(keys[0].first == "npm");
    CHECK(keys[1].first == "npm");
    CHECK(keys[0].second == "react");
    CHECK(keys[1].second == "react");
    CHECK(osv_package_index_key("npm", "react") == "npm\nreact");
}

TEST_CASE("osv match still evaluates withdrawn advisory payloads", "[unit][osv][core]") {
    OsvAdvisory advisory;
    advisory.id = "GHSA-withdrawn";
    advisory.withdrawn = true;
    advisory.affected.push_back(OsvAffectedPackage{
        .ecosystem = "npm",
        .name = "react",
        .versions = {"18.0"},
    });

    CHECK(osv_match_package(advisory, "npm", "react", "18.0").has_value());
}

TEST_CASE("osv match honors ecosystem version ranges", "[unit][osv][core]") {
    OsvAdvisory advisory;
    advisory.id = "GHSA-range";
    advisory.affected.push_back(OsvAffectedPackage{
        .ecosystem = "Maven",
        .name = "org.demo:lib",
        .events =
            {
                OsvRangeEvent{.introduced = "1.0", .fixed = "2.0"},
            },
    });

    const VersionComparatorSpec spec{.profile = "maven-comparable"};
    CHECK(osv_match_package(advisory, "Maven", "org.demo:lib", "1.5", spec).has_value());
    CHECK_FALSE(osv_match_package(advisory, "Maven", "org.demo:lib", "2.0", spec).has_value());
    CHECK_FALSE(osv_match_package(advisory, "Maven", "org.other:lib", "1.5", spec).has_value());
}

TEST_CASE("osv parser rejects invalid json and missing ids", "[unit][osv][core]") {
    CHECK_FALSE(osv_parse_advisory("{").has_value());
    CHECK_FALSE(osv_parse_advisory(R"({"modified":"2026-01-01T00:00:00Z"})").has_value());
}

TEST_CASE("osv parser marks withdrawn advisories from json field", "[unit][osv][core]") {
    const auto advisory = osv_parse_advisory(R"({
        "id": "GHSA-withdrawn-json",
        "modified": "2026-01-01T00:00:00Z",
        "withdrawn": "2026-01-02T00:00:00Z",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "react"},
            "versions": ["18.0"]
        }]
    })");
    REQUIRE(advisory.has_value());
    CHECK(advisory->withdrawn);
    CHECK(osv_match_package(advisory.value(), "npm", "react", "18.0").has_value());
}

TEST_CASE("osv match honors last affected and limit events", "[unit][osv][core]") {
    OsvAdvisory advisory;
    advisory.id = "GHSA-limit";
    advisory.affected.push_back(OsvAffectedPackage{
        .ecosystem = "npm",
        .name = "pkg",
        .events =
            {
                OsvRangeEvent{.introduced = "1.0", .lastAffected = "1.9", .limit = "2.0"},
            },
    });

    const VersionComparatorSpec spec{.profile = "semver"};
    CHECK(osv_match_package(advisory, "npm", "pkg", "1.5", spec).has_value());
    CHECK(osv_match_package(advisory, "npm", "pkg", "1.9", spec).has_value());
    CHECK_FALSE(osv_match_package(advisory, "npm", "pkg", "2.1", spec).has_value());
}

TEST_CASE("osv loader reads top-level advisory arrays from file paths", "[unit][osv][core]") {
    TempDir tempDir{"reqpack-osv-array-file"};
    const std::filesystem::path path = tempDir.path() / "feed.json";
    write_file(path, R"([
        {"id":"CVE-array-1","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"a"}}]},
        {"id":"CVE-array-2","modified":"2026-01-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"b"}}]}
    ])");

    const std::vector<OsvAdvisory> advisories = osv_load_advisories_from_path(path);
    REQUIRE(advisories.size() == 2);
}

TEST_CASE("osv match without version accepts unrestricted affected entries", "[unit][osv][core]") {
    OsvAdvisory advisory;
    advisory.id = "GHSA-unrestricted";
    advisory.affected.push_back(OsvAffectedPackage{
        .ecosystem = "npm",
        .name = "pkg",
    });

    CHECK(osv_match_package(advisory, "npm", "pkg", "", VersionComparatorSpec{}).has_value());
    CHECK_FALSE(osv_match_package(advisory, "pypi", "pkg", "", VersionComparatorSpec{}).has_value());
}

TEST_CASE("osv match rejects empty version when affected data requires version", "[unit][osv][core]") {
    OsvAdvisory advisory;
    advisory.id = "GHSA-open-range";
    advisory.affected.push_back(OsvAffectedPackage{
        .ecosystem = "npm",
        .name = "pkg",
        .events = {OsvRangeEvent{.introduced = "1.0"}},
    });

    CHECK_FALSE(osv_match_package(advisory, "npm", "pkg", "", VersionComparatorSpec{}).has_value());
}

TEST_CASE("osv match rejects empty version when only explicit versions exist", "[unit][osv][core]") {
    OsvAdvisory advisory;
    advisory.id = "GHSA-explicit-version";
    advisory.affected.push_back(OsvAffectedPackage{
        .ecosystem = "npm",
        .name = "pkg",
        .versions = {"1.0"},
    });

    CHECK_FALSE(osv_match_package(advisory, "npm", "pkg", "", VersionComparatorSpec{}).has_value());
}

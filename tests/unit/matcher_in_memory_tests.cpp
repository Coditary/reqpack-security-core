#include <catch2/catch.hpp>

#include "in_memory_advisory_store.h"
#include "rqp/security/vulnerability_matcher.h"
#include "test_helpers.h"

TEST_CASE("vulnerability matcher matches advisories from in-memory store without LMDB",
          "[unit][vulnerability_matcher][in_memory]") {
    InMemoryAdvisoryStore store;
    OsvAdvisory advisory;
    advisory.id = "GHSA-memory";
    advisory.summary = "demo issue";
    advisory.rawJson = R"({
        "id": "GHSA-memory",
        "summary": "demo issue",
        "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.18.0"}]}]}]
    })";
    advisory.affected = {OsvAffectedPackage{.ecosystem = "npm", .name = "lodash", .versions = {"4.17.21"}}};
    REQUIRE(store.upsert(advisory));

    SecuritySettings config = test_security_settings();
    config.security.ecosystemMap["npm"] = "npm";

    VulnerabilityMatcher matcher(nullptr, config);
    matcher.setAdvisories({advisory});

    Package pkg;
    pkg.system = "npm";
    pkg.name = "lodash";
    pkg.version = "4.17.21";

    const std::vector<ValidationFinding> findings = matcher.matchPackages(std::span<const Package>(&pkg, 1));
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].id == "GHSA-memory");
    CHECK(findings[0].kind == "vulnerability");
}

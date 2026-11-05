#include <catch2/catch.hpp>

#include "rqp/security/exchange.h"
#include "rqp/security/exchange_view.h"
#include "test_helpers.h"

TEST_CASE("security document pipeline round-trips reqpack sbom json", "[unit][security_document]") {
    const std::string input = R"({
        "packages": [
            {"system": "apt", "name": "curl", "version": "8.5.0-1"}
        ]
    })";

    const auto codec = create_codec(ExchangeKind::INVENTORY);
    REQUIRE(codec != nullptr);

    IdentityTransform identity;
    const PipelineResult result =
        run_pipeline(input, WireFormat::REQPACK_SBOM_JSON, *codec, identity, WireFormat::REQPACK_SBOM_JSON, {});

    REQUIRE_FALSE(result.error.has_value());
    CHECK(result.payload.find("\"system\": \"apt\"") != std::string::npos);
    CHECK(result.payload.find("\"name\": \"curl\"") != std::string::npos);
}

TEST_CASE("security document pipeline converts cyclonedx to reqpack sbom json", "[unit][security_document]") {
    const std::string input = R"({
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "demo",
                "version": "1.0.0",
                "properties": [{"name": "reqpack:system", "value": "npm"}]
            }
        ]
    })";

    const auto codec = create_codec(ExchangeKind::INVENTORY);
    IdentityTransform identity;

    const PipelineResult result =
        run_pipeline(input, WireFormat::AUTO, *codec, identity, WireFormat::REQPACK_SBOM_JSON, {});

    REQUIRE_FALSE(result.error.has_value());
    CHECK(result.payload.find("\"system\": \"npm\"") != std::string::npos);
    CHECK(result.payload.find("\"name\": \"demo\"") != std::string::npos);
}

TEST_CASE("decode inventory to envelope exposes structured packages", "[unit][security_document]") {
    const std::string input = R"({
        "packages": [
            {"system": "npm", "name": "left-pad", "version": "1.0.0"}
        ]
    })";

    const DecodeResult decoded = decode_to_view(input, WireFormat::REQPACK_SBOM_JSON);
    REQUIRE_FALSE(decoded.error.has_value());
    REQUIRE(decoded.view.packages.size() == 1);
    CHECK(decoded.view.packages.front().ref == "npm:left-pad@1.0.0");
    CHECK(decoded.view.packages.front().name == "left-pad");
    CHECK(decoded.view.kind == PayloadKind::INVENTORY);

    const std::string json = view_to_json(decoded.view);
    CHECK(json.find("\"kind\": \"inventory\"") != std::string::npos);
    CHECK(json.find("\"ref\": \"npm:left-pad@1.0.0\"") != std::string::npos);
}

TEST_CASE("security document pipeline emits audit json after vulnerability scan transform",
          "[unit][security_document]") {
    TempDir tempDir{"security-document-audit"};
    SecuritySettings config = test_security_settings();
    config.security.indexPath = (tempDir.path() / "index").string();
    config.security.osvDatabasePath = (tempDir.path() / "db").string();

    const std::string input = R"({
        "packages": [
            {"system": "Maven", "name": "com.example:demo", "version": "1.0.0"}
        ]
    })";

    ExchangeCtx context{.settings = config};
    const auto inputAdapter = create_in(ExchangeKind::INVENTORY);
    const auto outputAdapter = create_out(ExchangeKind::AUDIT_REPORT);
    VulnScanTransform scanTransform(context);

    const PipelineResult result = run_pipeline(input, WireFormat::REQPACK_SBOM_JSON, *inputAdapter, scanTransform,
                                               *outputAdapter, WireFormat::REQPACK_AUDIT_JSON, context);

    REQUIRE_FALSE(result.error.has_value());
    CHECK(result.payload.find("\"findings\"") != std::string::npos);
    CHECK(result.payload.find("\"packageCount\"") != std::string::npos);
}

#include <catch2/catch.hpp>

#include "adapters/infra/http_util.h"
#include "ports/internal_ports.h"
#include "rqp/security/sync_backend_registry.h"

TEST_CASE("http_response_body maps transport and HTTP status codes", "[unit][http_client][core]") {
    SECTION("429 is rate limited") {
        HttpResponse response{.statusCode = 429, .body = "slow down"};
        const rqp::security::Result<std::string> result = rqp::security::http_response_body(response);
        REQUIRE_FALSE(result);
        CHECK(result.error().code == rqp::security::ErrorCode::RateLimited);
    }

    SECTION("500 is network failure") {
        HttpResponse response{.statusCode = 503, .body = "upstream"};
        const rqp::security::Result<std::string> result = rqp::security::http_response_body(response);
        REQUIRE_FALSE(result);
        CHECK(result.error().code == rqp::security::ErrorCode::NetworkFailed);
    }

    SECTION("corrupt empty 200 body is parse failure") {
        HttpResponse response{.statusCode = 200, .body = ""};
        const rqp::security::Result<std::string> result = rqp::security::http_response_body(response);
        REQUIRE_FALSE(result);
        CHECK(result.error().code == rqp::security::ErrorCode::ParseFailed);
    }

    SECTION("200 with payload succeeds") {
        HttpResponse response{.statusCode = 200, .body = R"({"ok":true})"};
        const rqp::security::Result<std::string> result = rqp::security::http_response_body(response);
        REQUIRE(result);
        CHECK(result.value() == R"({"ok":true})");
    }
}

class MockHttpClient final : public IHttpClient {
  public:
    mutable std::vector<HttpRequest> requests;
    HttpResponse nextResponse{.statusCode = 200, .body = "{}"};

    HttpResponse perform(const HttpRequest& request) const override {
        this->requests.push_back(request);
        return this->nextResponse;
    }
};

TEST_CASE("mock http client supports deterministic sync error injection", "[unit][http_client][core]") {
    MockHttpClient mock;
    mock.nextResponse = HttpResponse{.statusCode = 500, .body = "internal error"};
    const HttpResponse response = mock.perform(HttpRequest{.url = "https://example.test/vulns"});
    const rqp::security::Result<std::string> body = rqp::security::http_response_body(response);
    REQUIRE_FALSE(body);
    CHECK(body.error().code == rqp::security::ErrorCode::NetworkFailed);
    REQUIRE(mock.requests.size() == 1);
    CHECK(mock.requests[0].url == "https://example.test/vulns");
}

TEST_CASE("builtin osv sync backend is registered as ISyncBackend", "[unit][sync_backend][core]") {
    const ISyncBackend* backend = find_sync_backend(rqp::sync_backend::kOsv);
    REQUIRE(backend != nullptr);
    CHECK(backend->id() == rqp::sync_backend::kOsv);
    CHECK(backend->supportsEcosystem("npm"));
}

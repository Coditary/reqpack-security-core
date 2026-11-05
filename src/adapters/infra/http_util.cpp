#include "adapters/infra/http_util.h"

#include <optional>

namespace rqp::security {

ErrorCode http_status_error_code(const long statusCode) {
    if (statusCode == 429) {
        return ErrorCode::RateLimited;
    }
    if (statusCode >= 500) {
        return ErrorCode::NetworkFailed;
    }
    if (statusCode >= 400) {
        return ErrorCode::InvalidInput;
    }
    return ErrorCode::Ok;
}

Result<std::string> http_response_body(const HttpResponse& response) {
    if (!response.error.empty()) {
        return make_error(ErrorCode::NetworkFailed, response.error, "transport");
    }
    const ErrorCode statusCode = http_status_error_code(response.statusCode);
    if (statusCode != ErrorCode::Ok) {
        std::string detail = response.body.empty() ? "empty response body" : response.body.substr(0, 256);
        return make_error(statusCode, "HTTP " + std::to_string(response.statusCode), detail);
    }
    if (response.body.empty()) {
        return make_error(ErrorCode::ParseFailed, "empty HTTP response body", std::to_string(response.statusCode));
    }
    return response.body;
}

std::optional<std::string> http_fetch_text(const IHttpClient& client, const std::string& url) {
    const Result<std::string> body = http_response_body(client.perform(HttpRequest{.url = url}));
    if (!body) {
        return std::nullopt;
    }
    return body.value();
}

} // namespace rqp::security

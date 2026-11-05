#pragma once

#include "ports/internal_ports.h"
#include "rqp/security/error.h"

namespace rqp::security {

[[nodiscard]] ErrorCode http_status_error_code(long statusCode);

[[nodiscard]] Result<std::string> http_response_body(const HttpResponse& response);

[[nodiscard]] std::optional<std::string> http_fetch_text(const IHttpClient& client, const std::string& url);

} // namespace rqp::security

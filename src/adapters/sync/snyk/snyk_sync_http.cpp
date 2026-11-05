#include "sync/snyk/snyk_sync_internal.h"

#include "adapters/infra/curl_http_client.h"
#include "adapters/infra/http_download.h"
#include "adapters/infra/http_util.h"

#include <sstream>
#include <utility>

namespace snyk_sync_internal {

std::optional<std::string> http_request(const IHttpClient& http, const SecuritySettings& config,
                                        const std::string& method, const std::string& url,
                                        const std::vector<std::string>& headers,
                                        const std::optional<std::string>& body) {
    std::vector<std::pair<std::string, std::string>> headerPairs;
    headerPairs.reserve(headers.size());
    for (const std::string& header : headers) {
        const std::size_t separator = header.find(':');
        if (separator == std::string::npos) {
            continue;
        }
        headerPairs.emplace_back(trim_copy(header.substr(0, separator)), trim_copy(header.substr(separator + 1)));
    }

    HttpRequest request{
        .url = url,
        .method = method,
        .headers = headerPairs,
        .body = body.value_or(std::string{}),
    };
    const HttpResponse response = http.perform(request);
    const rqp::security::Result<std::string> parsed = rqp::security::http_response_body(response);
    if (!parsed) {
        return std::nullopt;
    }
    return parsed.value();
}

bool fetch_file(const IHttpClient& http, const SecuritySettings& config, const std::string& url,
                const std::filesystem::path& path) {
    return http_download_to_file(http, config, url, path);
}

} // namespace snyk_sync_internal

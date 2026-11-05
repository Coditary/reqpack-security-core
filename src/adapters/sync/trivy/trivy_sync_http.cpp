#include "sync/trivy/trivy_sync_internal.h"

#include "adapters/infra/http_download.h"

#include <utility>

namespace trivy_sync_internal {

HttpResponse http_request(const IHttpClient& http, const SecuritySettings& config, const std::string& method,
                          const std::string& url, const std::vector<std::string>& headers,
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
    return http.perform(request);
}

bool http_download_to_path(const IHttpClient& http, const SecuritySettings& config, const std::string& url,
                           const std::vector<std::string>& headers, const std::filesystem::path& path,
                           long& statusCode) {
    std::vector<std::pair<std::string, std::string>> headerPairs;
    headerPairs.reserve(headers.size());
    for (const std::string& header : headers) {
        const std::size_t separator = header.find(':');
        if (separator == std::string::npos) {
            continue;
        }
        headerPairs.emplace_back(trim_copy(header.substr(0, separator)), trim_copy(header.substr(separator + 1)));
    }

    const bool ok = http_download_to_file(http, config, url, path, headerPairs);
    statusCode = ok ? 200L : 500L;
    return ok;
}

} // namespace trivy_sync_internal

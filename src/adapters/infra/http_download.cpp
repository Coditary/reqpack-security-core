#include "adapters/infra/http_download.h"

#include "adapters/infra/curl_http_client.h"
#include "adapters/infra/http_util.h"
#include "infra/security_network.h"

#include <curl/curl.h>

#include <fstream>

namespace {

bool starts_with(const std::string& value, std::string_view prefix) {
    return value.rfind(prefix, 0) == 0;
}

bool copy_file_url_to_path(const std::string& url, const std::filesystem::path& path) {
    if (!starts_with(url, "file://")) {
        return false;
    }
    std::ifstream input(url.substr(std::string{"file://"}.size()), std::ios::binary);
    if (!input.is_open()) {
        return false;
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        return false;
    }
    output << input.rdbuf();
    return output.good();
}

} // namespace

bool http_download_to_file(const IHttpClient& client, const SecuritySettings& /*config*/, const std::string& url,
                           const std::filesystem::path& path,
                           const std::vector<std::pair<std::string, std::string>>& headers) {
    if (copy_file_url_to_path(url, path)) {
        return true;
    }

    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        return false;
    }

    HttpRequest request{.url = url};
    if (!headers.empty()) {
        request.headers = std::span<const std::pair<std::string, std::string>>(headers.data(), headers.size());
    }
    const HttpResponse response = client.perform(request);
    const rqp::security::Result<std::string> body = rqp::security::http_response_body(response);
    if (!body) {
        std::error_code cleanupError;
        std::filesystem::remove(path, cleanupError);
        return false;
    }
    output.write(body.value().data(), static_cast<std::streamsize>(body.value().size()));
    output.flush();
    const bool ok = output.good();
    output.close();
    if (!ok) {
        std::error_code cleanupError;
        std::filesystem::remove(path, cleanupError);
    }
    return ok;
}

bool curl_download_to_file(const SecuritySettings& config, const std::string& url, const std::filesystem::path& path,
                           const std::vector<std::pair<std::string, std::string>>& headers) {
    const CurlHttpClient client(config);
    return http_download_to_file(client, config, url, path, headers);
}

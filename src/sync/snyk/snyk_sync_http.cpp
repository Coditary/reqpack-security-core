#include "sync/snyk/snyk_sync_internal.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <thread>
#include <utility>

namespace snyk_sync_internal {

std::optional<std::filesystem::path> resolve_file_fixture_path(const std::string& url) {
    if (!starts_with(url, "file://")) {
        return std::nullopt;
    }

    const std::filesystem::path rawPath(url.substr(std::string{"file://"}.size()));
    std::error_code error;
    if (std::filesystem::is_regular_file(rawPath, error) && !error) {
        return rawPath;
    }
    error.clear();
    const std::filesystem::path indexPath = rawPath / "index.json";
    if (std::filesystem::is_regular_file(indexPath, error) && !error) {
        return indexPath;
    }
    error.clear();
    const std::filesystem::path jsonPath = rawPath.string() + ".json";
    if (std::filesystem::is_regular_file(jsonPath, error) && !error) {
        return jsonPath;
    }
    return std::nullopt;
}

std::size_t write_to_string(void* contents, std::size_t size, std::size_t nmemb, void* userp) {
    const std::size_t bytes = size * nmemb;
    auto* buffer = static_cast<std::string*>(userp);
    buffer->append(static_cast<const char*>(contents), bytes);
    return bytes;
}

std::size_t write_to_file(void* contents, std::size_t size, std::size_t nmemb, void* userp) {
    const std::size_t bytes = size * nmemb;
    auto* output = static_cast<std::ofstream*>(userp);
    output->write(static_cast<const char*>(contents), static_cast<std::streamsize>(bytes));
    return output->good() ? bytes : 0;
}

bool configure_curl(CURL* curl, const SecuritySettings& config, const std::string& url) {
    if (curl == nullptr) {
        return false;
    }

    rqp_security_apply_curl_ca_bundle(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, config.network.followRedirects ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, config.network.connectTimeoutSeconds);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, config.network.requestTimeoutSeconds);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, config.network.userAgent.c_str());
    return true;
}

std::optional<std::string> http_request(const SecuritySettings& config, const std::string& method,
                                        const std::string& url, const std::vector<std::string>& headers,
                                        const std::optional<std::string>& body) {
    if (starts_with(url, "file://")) {
        const auto resolved = resolve_file_fixture_path(url);
        if (!resolved.has_value()) {
            return std::nullopt;
        }
        const std::filesystem::path& path = resolved.value();
        std::ifstream input(path, std::ios::binary);
        if (!input.is_open()) {
            return std::nullopt;
        }
        std::ostringstream buffer;
        buffer << input.rdbuf();
        return buffer.str();
    }

    std::string buffer;
    CURL* curl = curl_easy_init();
    if (!configure_curl(curl, config, url)) {
        return std::nullopt;
    }

    struct curl_slist* headerList = nullptr;
    for (const std::string& header : headers) {
        headerList = curl_slist_append(headerList, header.c_str());
    }
    if (headerList != nullptr) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
    }
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_to_string);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    if (body.has_value()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body->c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body->size()));
    }

    long statusCode = 0;
    const CURLcode result = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);
    if (headerList != nullptr) {
        curl_slist_free_all(headerList);
    }
    curl_easy_cleanup(curl);

    if (result != CURLE_OK || statusCode >= 400) {
        return std::nullopt;
    }
    return buffer;
}

bool fetch_file(const SecuritySettings& config, const std::string& url, const std::filesystem::path& path) {
    if (starts_with(url, "file://")) {
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

    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        return false;
    }

    CURL* curl = curl_easy_init();
    if (!configure_curl(curl, config, url)) {
        return false;
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_to_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output);

    long statusCode = 0;
    const CURLcode result = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);
    curl_easy_cleanup(curl);
    output.flush();
    const bool ok = result == CURLE_OK && statusCode < 400 && output.good();
    output.close();
    if (!ok) {
        std::error_code cleanupError;
        std::filesystem::remove(path, cleanupError);
    }
    return ok;
}


} // namespace snyk_sync_internal

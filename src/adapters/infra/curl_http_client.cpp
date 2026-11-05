#include "adapters/infra/curl_http_client.h"

#include "infra/security_network.h"

#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace {

bool starts_with(const std::string& value, std::string_view prefix) {
    return value.rfind(prefix, 0) == 0;
}

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

std::size_t capture_response_headers(void* contents, std::size_t size, std::size_t nmemb, void* userp) {
    const std::size_t bytes = size * nmemb;
    std::string line(static_cast<const char*>(contents), bytes);
    auto* headers = static_cast<std::map<std::string, std::string>*>(userp);
    const std::size_t separator = line.find(':');
    if (separator != std::string::npos) {
        std::string key = line.substr(0, separator);
        std::string value = line.substr(separator + 1);
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t' || key.back() == '\r' || key.back() == '\n')) {
            key.pop_back();
        }
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
            value.erase(value.begin());
        }
        while (!value.empty() && (value.back() == '\r' || value.back() == '\n')) {
            value.pop_back();
        }
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (!key.empty() && !value.empty()) {
            (*headers)[key] = value;
        }
    }
    return bytes;
}

std::size_t write_to_file_stream(void* contents, std::size_t size, std::size_t nmemb, void* userp) {
    const std::size_t bytes = size * nmemb;
    auto* output = static_cast<std::ofstream*>(userp);
    output->write(static_cast<const char*>(contents), static_cast<std::streamsize>(bytes));
    return output->good() ? bytes : 0;
}

} // namespace

CurlHttpClient::CurlHttpClient(SecuritySettings settings) : settings(std::move(settings)) {}

HttpResponse CurlHttpClient::perform(const HttpRequest& request) const {
    HttpResponse response;
    if (request.url.empty()) {
        response.error = "missing url";
        return response;
    }

    if (starts_with(request.url, "file://")) {
        const auto resolved = resolve_file_fixture_path(request.url);
        if (!resolved.has_value()) {
            response.statusCode = 404;
            response.error = "file fixture not found";
            return response;
        }
        std::ifstream input(*resolved, std::ios::binary);
        if (!input.is_open()) {
            response.statusCode = 500;
            response.error = "failed to open file fixture";
            return response;
        }
        std::ostringstream buffer;
        buffer << input.rdbuf();
        response.statusCode = 200;
        response.body = buffer.str();
        return response;
    }

    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        response.error = "curl_easy_init failed";
        return response;
    }

    rqp_security_apply_curl_ca_bundle(curl);
    curl_easy_setopt(curl, CURLOPT_URL, request.url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, this->settings.network.followRedirects ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, this->settings.network.connectTimeoutSeconds);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, this->settings.network.requestTimeoutSeconds);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, this->settings.network.userAgent.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_to_string);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &capture_response_headers);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);

    const std::string method = request.method.empty() ? "GET" : request.method;
    if (method != "GET") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
    }
    if (!request.body.empty()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.body.size()));
    }

    struct curl_slist* headerList = nullptr;
    for (const auto& [name, value] : request.headers) {
        headerList = curl_slist_append(headerList, (name + ": " + value).c_str());
    }
    if (headerList != nullptr) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
    }

    const CURLcode result = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.statusCode);
    if (result != CURLE_OK) {
        response.error = curl_easy_strerror(result);
    }

    if (headerList != nullptr) {
        curl_slist_free_all(headerList);
    }
    curl_easy_cleanup(curl);
    return response;
}

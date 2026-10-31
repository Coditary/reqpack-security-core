#include "sync/trivy/trivy_sync_internal.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <regex>
#include <sstream>
#include <system_error>
#include <utility>

namespace trivy_sync_internal {

std::string canonicalize_header_name(std::string name) {
    name = trim_copy(name);
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return name;
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

std::size_t capture_headers(void* contents, std::size_t size, std::size_t nmemb, void* userp) {
    const std::size_t bytes = size * nmemb;
    std::string line(static_cast<const char*>(contents), bytes);
    auto* headers = static_cast<std::map<std::string, std::string>*>(userp);
    const std::size_t separator = line.find(':');
    if (separator != std::string::npos) {
        const std::string key = canonicalize_header_name(line.substr(0, separator));
        const std::string value = trim_copy(line.substr(separator + 1));
        if (!key.empty() && !value.empty()) {
            (*headers)[key] = value;
        }
    }
    return bytes;
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
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &capture_headers);
    return true;
}

HttpResponse http_request(const SecuritySettings& config, const std::string& method, const std::string& url,
                          const std::vector<std::string>& headers, const std::optional<std::string>& body) {
    HttpResponse response;
    CURL* curl = curl_easy_init();
    if (!configure_curl(curl, config, url)) {
        return response;
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
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);
    if (body.has_value()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body->c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body->size()));
    }

    const CURLcode result = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.statusCode);
    if (headerList != nullptr) {
        curl_slist_free_all(headerList);
    }
    curl_easy_cleanup(curl);
    if (result != CURLE_OK) {
        response.statusCode = 0;
    }
    return response;
}

bool http_download_to_path(const SecuritySettings& config, const std::string& url,
                           const std::vector<std::string>& headers, const std::filesystem::path& path,
                           long& statusCode) {
    statusCode = 0;
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        return false;
    }

    CURL* curl = curl_easy_init();
    if (!configure_curl(curl, config, url)) {
        return false;
    }

    struct curl_slist* headerList = nullptr;
    for (const std::string& header : headers) {
        headerList = curl_slist_append(headerList, header.c_str());
    }
    if (headerList != nullptr) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_to_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output);
    std::map<std::string, std::string> responseHeaders;
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseHeaders);

    const CURLcode result = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);
    if (headerList != nullptr) {
        curl_slist_free_all(headerList);
    }
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


} // namespace trivy_sync_internal

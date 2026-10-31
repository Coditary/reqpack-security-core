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

std::string build_export_body(const std::string& dataset) {
    return std::string{"{\"data\":{\"attributes\":{\"dataset\":\""} + json_escape(dataset) +
           "\",\"filters\":{\"updated\":{\"from\":\"1970-01-01T00:00:00Z\",\"to\":\"9999-12-31T23:59:59Z\"}},"
           "\"columns\":[\"PROBLEM_ID\",\"PROBLEM_TITLE\",\"CVE\",\"PACKAGE_NAME_AND_VERSION\",\"SEMVER_VULNERABLE_"
           "RANGE\",\"ISSUE_SEVERITY\",\"NVD_SCORE\",\"SNYK_CVSS_SCORE\",\"UPDATED_AT\",\"FIXED_IN_VERSION\",\"PRODUCT_"
           "NAME\"],"
           "\"url_expiration_seconds\":3600}}}";
}

std::vector<std::string> build_headers(const SecurityBackendConfig& backend, const std::string& token) {
    return {
        "Authorization: token " + token,
        "Version: " + backend.apiVersion,
        "Content-Type: application/vnd.api+json",
        "Accept: application/vnd.api+json",
    };
}

std::string endpoint_for(const SecurityBackendConfig& backend, const std::string& path) {
    const std::string base = backend.apiBaseUrl.empty() ? std::string{"https://api.snyk.io/rest"} : backend.apiBaseUrl;
    if (base.back() == '/' && !path.empty() && path.front() == '/') {
        return base.substr(0, base.size() - 1) + path;
    }
    if (base.back() != '/' && !path.empty() && path.front() != '/') {
        return base + "/" + path;
    }
    return base + path;
}

std::optional<std::string> read_env_value(const std::string& name) {
    if (name.empty()) {
        return std::nullopt;
    }
    const char* value = std::getenv(name.c_str());
    if (value == nullptr || value[0] == '\0') {
        return std::nullopt;
    }
    return std::string(value);
}

std::optional<std::string> create_export_job(const SecuritySettings& config, const SecurityBackendConfig& backend,
                                             const std::string& token) {
    const std::vector<std::string> headers = build_headers(backend, token);
    const std::string scopePath =
        !backend.orgId.empty() ? "/orgs/" + backend.orgId + "/export" : "/groups/" + backend.groupId + "/export";
    const auto payload =
        http_request(config, "POST", endpoint_for(backend, scopePath), headers, build_export_body(backend.dataset));
    if (!payload.has_value()) {
        return std::nullopt;
    }
    ptree tree;
    if (!parse_json_tree(payload.value(), tree)) {
        return std::nullopt;
    }
    const std::string exportId = trim_copy(tree.get<std::string>("export_id", {}));
    return exportId.empty() ? std::nullopt : std::optional<std::string>(exportId);
}

std::optional<std::string> export_status(const SecuritySettings& config, const SecurityBackendConfig& backend,
                                         const std::string& token, const std::string& exportId) {
    const std::vector<std::string> headers = build_headers(backend, token);
    const std::string scopePath = !backend.orgId.empty() ? "/orgs/" + backend.orgId + "/jobs/export/" + exportId
                                                         : "/groups/" + backend.groupId + "/jobs/export/" + exportId;
    const auto payload = http_request(config, "GET", endpoint_for(backend, scopePath), headers);
    if (!payload.has_value()) {
        return std::nullopt;
    }
    ptree tree;
    if (!parse_json_tree(payload.value(), tree)) {
        return std::nullopt;
    }
    const std::string status = trim_copy(tree.get<std::string>("status", {}));
    return status.empty() ? std::nullopt : std::optional<std::string>(status);
}

std::optional<std::string> export_download_url(const SecuritySettings& config, const SecurityBackendConfig& backend,
                                               const std::string& token, const std::string& exportId) {
    const std::vector<std::string> headers = build_headers(backend, token);
    const std::string scopePath = !backend.orgId.empty() ? "/orgs/" + backend.orgId + "/export/" + exportId
                                                         : "/groups/" + backend.groupId + "/export/" + exportId;
    const auto payload = http_request(config, "GET", endpoint_for(backend, scopePath), headers);
    if (!payload.has_value()) {
        return std::nullopt;
    }
    ptree tree;
    if (!parse_json_tree(payload.value(), tree)) {
        return std::nullopt;
    }
    const std::string url = trim_copy(tree.get<std::string>("download_url", {}));
    return url.empty() ? std::nullopt : std::optional<std::string>(url);
}

std::optional<std::filesystem::path>
download_export_csv(const SecuritySettings& config, const std::filesystem::path& root, const std::string& downloadUrl) {
    std::error_code error;
    std::filesystem::create_directories(root, error);
    if (error) {
        return std::nullopt;
    }
    const std::filesystem::path path = root / "snyk-export.csv";
    if (!fetch_file(config, downloadUrl, path)) {
        return std::nullopt;
    }
    return path;
}

std::optional<std::vector<SnykExportRow>> load_export_rows(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        return std::nullopt;
    }

    std::string line;
    if (!std::getline(input, line)) {
        return std::nullopt;
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    const std::vector<std::string> header = parse_csv_line_impl(line);
    std::vector<SnykExportRow> rows;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (trim_copy(line).empty()) {
            continue;
        }
        const auto parsed = parse_export_row_impl(header, parse_csv_line_impl(line));
        if (parsed.has_value()) {
            rows.push_back(parsed.value());
        }
    }
    return rows;
}


} // namespace snyk_sync_internal

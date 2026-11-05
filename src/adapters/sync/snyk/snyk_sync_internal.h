#pragma once

#include "detail/sync_common.h"
#include "detail/sync_refresh.h"
#include "infra/security_network.h"
#include "ports/internal_ports.h"
#include "rqp/security/osv_core.h"
#include "rqp/security/security_config.h"
#include "rqp/security/vulnerability_database.h"
#include "sync/snyk/snyk_vulnerability_sync_service.h"

#include <boost/property_tree/ptree.hpp>

#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace snyk_sync_internal {

using boost::property_tree::ptree;
using rqp_security_detail::join_scope_key;
using rqp_security_detail::json_escape;
using rqp_security_detail::now_epoch_seconds;
using rqp_security_detail::parse_json_tree;
using rqp_security_detail::severity_rank;
using rqp_security_detail::starts_with;
using rqp_security_detail::to_lower_copy;
using rqp_security_detail::trim_copy;

constexpr std::size_t SNYK_IMPORT_BATCH_SIZE = 256;

constexpr const char* SNYK_SYNC_KEY_LAST_SUCCESS = "snyk:last_successful_sync_at";
constexpr const char* SNYK_SYNC_KEY_SCOPE = "snyk:scope";
constexpr const char* SNYK_SYNC_KEY_LAST_UPDATED = "snyk:last_export_updated_at";

struct SnykGroupedAdvisory {
    std::string id;
    std::string title;
    std::string cve;
    std::string severity;
    double score{0.0};
    std::string updatedAt;
    std::string fixedInVersion;
    std::string semverVulnerableRange;
    std::string productName;
    std::map<std::string, std::set<std::string>> versionsByPackage;
};

struct ParsedSnykPackageLocal {
    std::string name;
    std::string version;
};

std::optional<std::string> read_env_value(const std::string& name);

bool is_maven_purl(const std::string& value);

std::optional<std::string> http_request(const IHttpClient& http, const SecuritySettings& config,
                                        const std::string& method, const std::string& url,
                                        const std::vector<std::string>& headers,
                                        const std::optional<std::string>& body = std::nullopt);

bool fetch_file(const IHttpClient& http, const SecuritySettings& config, const std::string& url,
                const std::filesystem::path& path);

std::vector<std::string> parse_csv_line_impl(std::string_view line);
std::optional<SnykExportRow> parse_export_row_impl(const std::vector<std::string>& header,
                                                   const std::vector<std::string>& values);
std::optional<ParsedSnykPackageLocal> parse_maven_package_name_and_version(const std::string& value);

std::optional<std::string> create_export_job(const IHttpClient& http, const SecuritySettings& config,
                                             const SecurityBackendConfig& backend, const std::string& token);
std::optional<std::string> export_status(const IHttpClient& http, const SecuritySettings& config,
                                         const SecurityBackendConfig& backend, const std::string& token,
                                         const std::string& exportId);
std::optional<std::string> export_download_url(const IHttpClient& http, const SecuritySettings& config,
                                               const SecurityBackendConfig& backend, const std::string& token,
                                               const std::string& exportId);
std::optional<std::filesystem::path> download_export_csv(const IHttpClient& http, const SecuritySettings& config,
                                                         const std::filesystem::path& root,
                                                         const std::string& downloadUrl);
std::optional<std::vector<SnykExportRow>> load_export_rows(const std::filesystem::path& path);

std::vector<ValidationFinding> import_rows(VulnerabilityDatabase* database, const std::set<std::string>& ecosystems,
                                           const std::vector<SnykExportRow>& rows);

bool scope_matches(const VulnerabilityDatabase* database, const std::set<std::string>& ecosystems);
bool should_refresh(const VulnerabilityDatabase* database, const SecurityBackendConfig& backend, bool forceRefresh);

std::string severity_from_row(const std::string& value, double score);

} // namespace snyk_sync_internal

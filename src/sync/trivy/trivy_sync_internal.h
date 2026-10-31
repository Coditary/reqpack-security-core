#pragma once

#include "detail/sync_common.h"
#include "detail/sync_refresh.h"
#include "rqp/security/osv_core.h"
#include "rqp/security/security_archive.h"
#include "rqp/security/security_config.h"
#include "rqp/security/security_network.h"
#include "rqp/security/security_process.h"
#include "rqp/security/trivy_vulnerability_sync_service.h"
#include "rqp/security/vulnerability_database.h"

#include <boost/property_tree/ptree.hpp>
#include <curl/curl.h>

#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace trivy_sync_internal {

using boost::property_tree::ptree;
using rqp_security_detail::join_scope_key;
using rqp_security_detail::json_escape;
using rqp_security_detail::now_epoch_seconds;
using rqp_security_detail::parse_json_tree;
using rqp_security_detail::severity_rank;
using rqp_security_detail::starts_with;
using rqp_security_detail::to_lower_copy;
using rqp_security_detail::trim_copy;

constexpr std::size_t TRIVY_IMPORT_BATCH_SIZE = 256;

constexpr const char* TRIVY_SYNC_KEY_LAST_SUCCESS = "trivy:last_successful_sync_at";
constexpr const char* TRIVY_SYNC_KEY_SOURCE_REPOSITORY = "trivy:source_repository";
constexpr const char* TRIVY_SYNC_KEY_METADATA_VERSION = "trivy:db_metadata_version";
constexpr const char* TRIVY_SYNC_KEY_SCOPE = "trivy:scope";

constexpr const char* TRIVY_DB_LAYER_MEDIA_TYPE = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip";

#ifndef REQPACK_TRIVY_HELPER_DEFAULT_PATH
#define REQPACK_TRIVY_HELPER_DEFAULT_PATH ""
#endif

struct HttpResponse {
    long statusCode{0};
    std::string body{};
    std::map<std::string, std::string> headers{};
};

struct ProcessResult {
    int exitCode{1};
    std::string stdoutText{};
    std::string stderrText{};
};

struct OciReference {
    std::string original;
    std::string registry;
    std::string repository;
    std::string reference;
};

struct BearerChallenge {
    std::string realm;
    std::string service;
    std::string scope;
};

struct TrivyDbMetadata {
    std::string version;
};

struct TrivyGroupedPackage {
    std::set<std::string> versions;
    std::vector<TrivyHelperRange> ranges;
};

struct TrivyGroupedAdvisory {
    std::string ecosystem;
    std::string id;
    std::set<std::string> aliases;
    std::string modified;
    std::string published;
    std::string summary;
    std::string description;
    std::string severity{"unassigned"};
    double score{0.0};
    std::set<std::string> references;
    std::map<std::string, TrivyGroupedPackage> packages;
};

std::string normalize_trivy_severity(const std::string& value, double score);

std::optional<std::filesystem::path> prepare_local_fixture_database(const SecuritySettings& config,
                                                                    const std::string& repository,
                                                                    const std::filesystem::path& cacheRoot);
std::optional<std::filesystem::path> download_trivy_database_from_oci(const SecuritySettings& config,
                                                                      const std::string& repository,
                                                                      const std::filesystem::path& cacheRoot);

HttpResponse http_request(const SecuritySettings& config, const std::string& method, const std::string& url,
                          const std::vector<std::string>& headers, const std::optional<std::string>& body = std::nullopt);

bool http_download_to_path(const SecuritySettings& config, const std::string& url, const std::vector<std::string>& headers,
                           const std::filesystem::path& path, long& statusCode);

std::optional<std::filesystem::path> prepare_trivy_database(const SecuritySettings& config,
                                                            const SecurityBackendConfig& backend,
                                                            std::string& selectedRepository);

std::optional<TrivyDbMetadata> load_trivy_metadata(const std::filesystem::path& path);

ProcessResult run_process_capture(const std::vector<std::string>& arguments);

std::filesystem::path resolve_helper_path(const SecurityBackendConfig& backend);

bool scope_matches(const VulnerabilityDatabase* database, const std::set<std::string>& ecosystems);

bool should_refresh(const VulnerabilityDatabase* database, const SecurityBackendConfig& backend, bool forceRefresh);

std::optional<std::vector<TrivyHelperRecord>> load_helper_records(const std::string& output);

std::vector<ValidationFinding> import_records(VulnerabilityDatabase* database, const std::set<std::string>& ecosystems,
                                              const std::vector<TrivyHelperRecord>& records,
                                              const std::string& sourceRepository, const TrivyDbMetadata& metadata);

} // namespace trivy_sync_internal

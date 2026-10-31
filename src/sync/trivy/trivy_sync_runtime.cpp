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

std::optional<std::filesystem::path> prepare_trivy_database(const SecuritySettings& config,
                                                            const SecurityBackendConfig& backend,
                                                            std::string& selectedRepository) {
    const std::filesystem::path cacheRoot = std::filesystem::path(config.security.cachePath) / "trivy";
    for (const std::string& repository : backend.dbRepositories) {
        std::optional<std::filesystem::path> prepared;
        if (starts_with(repository, "file://")) {
            prepared = prepare_local_fixture_database(config, repository, cacheRoot);
        } else {
            prepared = download_trivy_database_from_oci(config, repository, cacheRoot);
        }
        if (prepared.has_value()) {
            selectedRepository = repository;
            return prepared;
        }
    }
    return std::nullopt;
}

std::optional<TrivyDbMetadata> load_trivy_metadata(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        return std::nullopt;
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    ptree tree;
    if (!parse_json_tree(buffer.str(), tree)) {
        return std::nullopt;
    }
    const long version = tree.get<long>("Version", 0L);
    return TrivyDbMetadata{.version = version > 0 ? std::to_string(version) : std::string{}};
}

ProcessResult run_process_capture(const std::vector<std::string>& arguments) {
    const RqpSecurityProcessResult captured = rqp_security_run_process_capture(arguments);
    return ProcessResult{
        .exitCode = captured.exitCode,
        .stdoutText = captured.stdoutText,
        .stderrText = captured.stderrText,
    };
}

std::filesystem::path resolve_helper_path(const SecurityBackendConfig& backend) {
    if (!backend.helperPath.empty()) {
        return backend.helperPath;
    }
    if (const char* overridePath = std::getenv("REQPACK_TRIVY_HELPER");
        overridePath != nullptr && overridePath[0] != '\0') {
        return std::filesystem::path(overridePath);
    }
    if (std::string_view(REQPACK_TRIVY_HELPER_DEFAULT_PATH).empty()) {
        return {};
    }
    return std::filesystem::path(REQPACK_TRIVY_HELPER_DEFAULT_PATH);
}


} // namespace trivy_sync_internal

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

std::optional<OciReference> parse_oci_reference(const std::string& value) {
    const std::size_t firstSlash = value.find('/');
    if (firstSlash == std::string::npos || firstSlash == 0 || firstSlash == value.size() - 1) {
        return std::nullopt;
    }

    const std::size_t lastColon = value.rfind(':');
    if (lastColon == std::string::npos || lastColon < firstSlash || lastColon == value.size() - 1) {
        return std::nullopt;
    }

    return OciReference{
        .original = value,
        .registry = value.substr(0, firstSlash),
        .repository = value.substr(firstSlash + 1, lastColon - firstSlash - 1),
        .reference = value.substr(lastColon + 1),
    };
}

std::string manifest_url(const OciReference& reference) {
    return "https://" + reference.registry + "/v2/" + reference.repository + "/manifests/" + reference.reference;
}

std::string blob_url(const OciReference& reference, const std::string& digest) {
    return "https://" + reference.registry + "/v2/" + reference.repository + "/blobs/" + digest;
}

std::string manifest_digest_url(const OciReference& reference, const std::string& digest) {
    return "https://" + reference.registry + "/v2/" + reference.repository + "/manifests/" + digest;
}

std::optional<BearerChallenge> parse_bearer_challenge(const std::string& header) {
    if (header.empty()) {
        return std::nullopt;
    }
    const std::string normalized = to_lower_copy(header);
    if (!starts_with(normalized, "bearer ")) {
        return std::nullopt;
    }

    BearerChallenge challenge;
    const std::regex fieldRegex(R"field(([A-Za-z]+)="([^"]*)")field");
    auto begin = std::sregex_iterator(header.begin(), header.end(), fieldRegex);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        const std::string key = to_lower_copy((*it)[1].str());
        const std::string value = (*it)[2].str();
        if (key == "realm") {
            challenge.realm = value;
        } else if (key == "service") {
            challenge.service = value;
        } else if (key == "scope") {
            challenge.scope = value;
        }
    }

    if (challenge.realm.empty()) {
        return std::nullopt;
    }
    return challenge;
}

std::string url_encode(const std::string& value) {
    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        return value;
    }
    char* escaped = curl_easy_escape(curl, value.c_str(), static_cast<int>(value.size()));
    std::string result = escaped == nullptr ? value : std::string(escaped);
    if (escaped != nullptr) {
        curl_free(escaped);
    }
    curl_easy_cleanup(curl);
    return result;
}

std::optional<std::string> request_bearer_token(const SecuritySettings& config, const BearerChallenge& challenge) {
    std::string url = challenge.realm;
    const char separator = challenge.realm.find('?') == std::string::npos ? '?' : '&';
    url.push_back(separator);
    url += "service=" + url_encode(challenge.service);
    if (!challenge.scope.empty()) {
        url += "&scope=" + url_encode(challenge.scope);
    }
    const HttpResponse response = http_request(config, "GET", url, {});
    if (response.statusCode >= 400 || response.body.empty()) {
        return std::nullopt;
    }
    ptree tree;
    if (!parse_json_tree(response.body, tree)) {
        return std::nullopt;
    }
    const std::string token = trim_copy(tree.get<std::string>("token", tree.get<std::string>("access_token", {})));
    return token.empty() ? std::nullopt : std::optional<std::string>(token);
}

std::vector<std::string> manifest_headers(const std::optional<std::string>& token) {
    std::vector<std::string> headers{
        "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, "
        "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json",
    };
    if (token.has_value()) {
        headers.push_back("Authorization: Bearer " + token.value());
    }
    return headers;
}

std::vector<std::string> blob_headers(const std::optional<std::string>& token) {
    if (!token.has_value()) {
        return {};
    }
    return {"Authorization: Bearer " + token.value()};
}

std::optional<std::string> select_db_layer_digest(const std::string& manifestJson) {
    ptree tree;
    if (!parse_json_tree(manifestJson, tree)) {
        return std::nullopt;
    }

    if (const auto layers = tree.get_child_optional("layers")) {
        for (const auto& [_, layer] : layers.value()) {
            const std::string mediaType = trim_copy(layer.get<std::string>("mediaType", {}));
            std::string title;
            if (const auto annotations = layer.get_child_optional("annotations")) {
                for (const auto& [annotationKey, annotationValue] : annotations.value()) {
                    if (annotationKey == "org.opencontainers.image.title") {
                        title = trim_copy(annotationValue.get_value<std::string>());
                        break;
                    }
                }
            }
            if (mediaType == TRIVY_DB_LAYER_MEDIA_TYPE || title == "db.tar.gz") {
                const std::string digest = trim_copy(layer.get<std::string>("digest", {}));
                if (!digest.empty()) {
                    return digest;
                }
            }
        }
        for (const auto& [_, layer] : layers.value()) {
            const std::string digest = trim_copy(layer.get<std::string>("digest", {}));
            if (!digest.empty()) {
                return digest;
            }
        }
    }
    return std::nullopt;
}

std::optional<std::string> load_manifest_with_auth(const SecuritySettings& config, const OciReference& reference,
                                                   std::optional<std::string>& token) {
    HttpResponse response = http_request(config, "GET", manifest_url(reference), manifest_headers(token));
    if (response.statusCode == 401 && !token.has_value()) {
        const auto challenge = parse_bearer_challenge(response.headers["www-authenticate"]);
        if (!challenge.has_value()) {
            return std::nullopt;
        }
        token = request_bearer_token(config, challenge.value());
        if (!token.has_value()) {
            return std::nullopt;
        }
        response = http_request(config, "GET", manifest_url(reference), manifest_headers(token));
    }
    if (response.statusCode >= 400 || response.body.empty()) {
        return std::nullopt;
    }

    ptree tree;
    if (!parse_json_tree(response.body, tree)) {
        return std::nullopt;
    }
    if (!tree.get_child_optional("layers").has_value()) {
        std::string nestedDigest;
        if (const auto manifests = tree.get_child_optional("manifests")) {
            for (const auto& [_, manifestNode] : manifests.value()) {
                nestedDigest = trim_copy(manifestNode.get<std::string>("digest", {}));
                if (!nestedDigest.empty()) {
                    break;
                }
            }
        }
        if (nestedDigest.empty()) {
            return std::nullopt;
        }
        const HttpResponse nested =
            http_request(config, "GET", manifest_digest_url(reference, nestedDigest), manifest_headers(token));
        if (nested.statusCode >= 400 || nested.body.empty()) {
            return std::nullopt;
        }
        return nested.body;
    }
    return response.body;
}

bool ensure_directory(const std::filesystem::path& path) {
    if (path.empty()) {
        return true;
    }
    std::error_code error;
    std::filesystem::create_directories(path, error);
    return !error;
}

bool copy_file_replace(const std::filesystem::path& source, const std::filesystem::path& target) {
    if (!ensure_directory(target.parent_path())) {
        return false;
    }
    std::error_code error;
    std::filesystem::copy_file(source, target, std::filesystem::copy_options::overwrite_existing, error);
    return !error;
}

void remove_cleanup_paths_quietly(const std::vector<std::filesystem::path>& cleanupPaths) {
    for (const std::filesystem::path& cleanupPath : cleanupPaths) {
        std::error_code cleanupError;
        std::filesystem::remove_all(cleanupPath, cleanupError);
    }
}

std::optional<std::filesystem::path> materialize_extracted_database(const std::filesystem::path& sourceDirectory,
                                                                    const std::filesystem::path& destinationDirectory) {
    const std::filesystem::path metadataPath = sourceDirectory / "metadata.json";
    const std::filesystem::path dbPath = sourceDirectory / "trivy.db";
    std::error_code error;
    if (!std::filesystem::is_regular_file(metadataPath, error) || error) {
        return std::nullopt;
    }
    error.clear();
    if (!std::filesystem::is_regular_file(dbPath, error) || error) {
        return std::nullopt;
    }

    std::filesystem::remove_all(destinationDirectory, error);
    error.clear();
    if (!ensure_directory(destinationDirectory)) {
        return std::nullopt;
    }
    if (!copy_file_replace(metadataPath, destinationDirectory / "metadata.json")) {
        return std::nullopt;
    }
    if (!copy_file_replace(dbPath, destinationDirectory / "trivy.db")) {
        return std::nullopt;
    }
    return destinationDirectory;
}

std::optional<std::filesystem::path> materialize_extracted_archive(const SecuritySettings& config,
                                                                   const std::filesystem::path& archivePath,
                                                                   const std::filesystem::path& destinationDirectory) {
    if (!config.archive.extractToTemp) {
        return std::nullopt;
    }

    try {
        const SecurityArchiveResolution extracted = config.archive.extractToTemp(archivePath);
        const auto materialized = materialize_extracted_database(extracted.installPath, destinationDirectory);
        remove_cleanup_paths_quietly(extracted.cleanupPaths);
        return materialized;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::filesystem::path> prepare_local_fixture_database(const SecuritySettings& config,
                                                                    const std::string& repository,
                                                                    const std::filesystem::path& cacheRoot) {
    const std::filesystem::path localPath(repository.substr(std::string{"file://"}.size()));
    const std::filesystem::path destinationDirectory = cacheRoot / "input";
    std::error_code error;
    error.clear();
    if (std::filesystem::is_directory(localPath, error) && !error) {
        if (const auto extracted = materialize_extracted_database(localPath, destinationDirectory);
            extracted.has_value()) {
            return extracted;
        }
        error.clear();
        const std::filesystem::path archivePath = localPath / "db.tar.gz";
        if (std::filesystem::is_regular_file(archivePath, error) && !error) {
            return materialize_extracted_archive(config, archivePath, destinationDirectory);
        }
        return std::nullopt;
    }

    error.clear();
    if (std::filesystem::is_regular_file(localPath, error) && !error) {
        return materialize_extracted_archive(config, localPath, destinationDirectory);
    }
    return std::nullopt;
}

std::optional<std::filesystem::path> download_trivy_database_from_oci(const SecuritySettings& config,
                                                                      const std::string& repository,
                                                                      const std::filesystem::path& cacheRoot) {
    const auto reference = parse_oci_reference(repository);
    if (!reference.has_value()) {
        return std::nullopt;
    }

    std::optional<std::string> token;
    const auto manifest = load_manifest_with_auth(config, reference.value(), token);
    if (!manifest.has_value()) {
        return std::nullopt;
    }
    const auto digest = select_db_layer_digest(manifest.value());
    if (!digest.has_value()) {
        return std::nullopt;
    }

    if (!ensure_directory(cacheRoot)) {
        return std::nullopt;
    }
    const std::filesystem::path archivePath = cacheRoot / "db.tar.gz";
    long statusCode = 0;
    if (!http_download_to_path(config, blob_url(reference.value(), digest.value()), blob_headers(token), archivePath,
                               statusCode)) {
        return std::nullopt;
    }
    return materialize_extracted_archive(config, archivePath, cacheRoot / "input");
}


} // namespace trivy_sync_internal

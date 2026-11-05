#pragma once

#include "ports/internal_ports.h"
#include "rqp/security/security_settings.h"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

/// Download `url` to `path` (supports `file://` fixtures). Returns false on transport or HTTP errors.
[[nodiscard]] bool http_download_to_file(const IHttpClient& client, const SecuritySettings& config,
                                         const std::string& url, const std::filesystem::path& path,
                                         const std::vector<std::pair<std::string, std::string>>& headers = {});

[[nodiscard]] bool curl_download_to_file(const SecuritySettings& config, const std::string& url,
                                         const std::filesystem::path& path,
                                         const std::vector<std::pair<std::string, std::string>>& headers = {});

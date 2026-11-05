#pragma once

#include "rqp/security/security_settings.h"
#include "rqp/security/security_types.h"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

enum class SbomInventoryFormat { AUTO, CYCLONEDX, SPDX, REQPACK_JSON };

struct SbomImportWarning {
    std::string message;
};

struct SbomImportResult {
    Graph graph;
    std::vector<SbomImportWarning> warnings;
    std::optional<std::string> error;
    std::string detectedFormat;
};

SbomImportResult import_sbom_from_json(const std::string& json,
                                       const SecuritySettings& config = default_security_settings(),
                                       SbomInventoryFormat format = SbomInventoryFormat::AUTO);

SbomImportResult import_sbom_from_path(const std::filesystem::path& path,
                                       const SecuritySettings& config = default_security_settings(),
                                       SbomInventoryFormat format = SbomInventoryFormat::AUTO);

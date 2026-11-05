#include "adapters/infra/settings_archive_extractor.h"

#include "rqp/security/security_archive.h"

#include <filesystem>

SettingsArchiveExtractor::SettingsArchiveExtractor(SecuritySettings settings) : settings(std::move(settings)) {}

rqp::security::Result<std::string>
SettingsArchiveExtractor::extractToDirectory(const std::string& archivePath, const std::string& destinationDir) const {
    (void)destinationDir;
    if (!this->settings.archive.extractToTemp) {
        return rqp::security::make_error(rqp::security::ErrorCode::BackendUnavailable,
                                         "archive.extractToTemp callback is not configured");
    }

    const std::filesystem::path path(archivePath);
    if (path.empty()) {
        return rqp::security::make_error(rqp::security::ErrorCode::InvalidInput, "archive path is empty");
    }

    try {
        const SecurityArchiveResolution resolution = this->settings.archive.extractToTemp(path);
        if (resolution.installPath.empty()) {
            return rqp::security::make_error(rqp::security::ErrorCode::StorageFailed,
                                             "archive extraction returned empty install path");
        }
        return resolution.installPath.string();
    } catch (const std::exception& ex) {
        return rqp::security::make_error(rqp::security::ErrorCode::StorageFailed, ex.what());
    }
}

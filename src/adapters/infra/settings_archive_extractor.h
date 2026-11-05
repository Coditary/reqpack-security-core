#pragma once

#include "ports/internal_ports.h"
#include "rqp/security/security_settings.h"

class SettingsArchiveExtractor final : public IArchiveExtractor {
    SecuritySettings settings;

  public:
    explicit SettingsArchiveExtractor(SecuritySettings settings = default_security_settings());

    [[nodiscard]] rqp::security::Result<std::string>
    extractToDirectory(const std::string& archivePath, const std::string& destinationDir) const override;
};

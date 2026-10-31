#pragma once

#include "rqp/security/security_archive.h"
#include "rqp/security/security_config.h"

#include <string>

struct SecurityNetworkConfig {
    long connectTimeoutSeconds{30};
    long requestTimeoutSeconds{300};
    bool followRedirects{true};
    std::string userAgent{"rqp-security/1.0"};
};

struct SecurityInteractionConfig {
    bool interactive{true};
};

struct SecurityReportConfig {
    bool enabled{false};
};

struct SecuritySettings {
    SecurityConfig security;
    SecurityNetworkConfig network;
    SecurityInteractionConfig interaction;
    SecurityReportConfig reports;
    SecurityArchiveConfig archive;
};

SecuritySettings default_security_settings();
SecuritySettings ecosystem_db_settings(const SecuritySettings& settings, const std::string& ecosystem);

/// Applies named preset values onto `security`. Returns false if preset name is unknown.
bool apply_security_preset(SecurityConfig& security, const std::string& preset);

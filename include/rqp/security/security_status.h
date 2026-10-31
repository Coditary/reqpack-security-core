#pragma once

#include "rqp/security/plugin_metadata_provider.h"
#include "rqp/security/security_settings.h"

#include <ostream>
#include <string>
#include <vector>

struct SecurityStatusReport {
    std::vector<std::string> lines;
    std::vector<std::string> warnings;
    bool hasBlockingIssues{false};
};

SecurityStatusReport build_security_status(const SecuritySettings& settings, PluginMetadataProvider* metadataProvider);

void print_security_status_report(const SecurityStatusReport& report, std::ostream& output);

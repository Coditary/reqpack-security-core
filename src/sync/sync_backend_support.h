#pragma once

#include "rqp/security/security_settings.h"

#include <string>

namespace rqp::sync_backend_internal {

constexpr const char* kDefaultOsvFeedUrl = "https://storage.googleapis.com/osv-vulnerabilities";

std::string resolve_osv_feed_url(const SecuritySettings& config, const std::string& backendFeedUrl);

void merge_osv_gateway_backend(SecuritySettings& out, const SecuritySettings& in, const std::string& backendId);

void merge_gh_advisory_gateway_backend(SecuritySettings& out, const SecuritySettings& in, const std::string& backendId);

void apply_osv_force_refresh(SecuritySettings& out, const std::string& backendId);

void apply_gh_advisory_force_refresh(SecuritySettings& out, const std::string& backendId);

} // namespace rqp::sync_backend_internal

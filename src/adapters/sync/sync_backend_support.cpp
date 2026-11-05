#include "sync/sync_backend_support.h"

namespace rqp::sync_backend_internal {

std::string resolve_osv_feed_url(const SecuritySettings& config, const std::string& backendFeedUrl) {
    const std::string& topLevel = config.security.osvFeedUrl;
    if (!backendFeedUrl.empty()) {
        if (backendFeedUrl == kDefaultOsvFeedUrl && topLevel != kDefaultOsvFeedUrl) {
            return topLevel;
        }
        return backendFeedUrl;
    }
    return topLevel;
}

void merge_osv_gateway_backend(SecuritySettings& out, const SecuritySettings& in, const std::string& backendId) {
    const auto backendIt = in.security.backends.find(backendId);
    if (backendIt == in.security.backends.end()) {
        return;
    }
    out.security.osvFeedUrl = resolve_osv_feed_url(in, backendIt->second.feedUrl);
    out.security.osvRefreshMode = backendIt->second.refreshMode;
    out.security.osvRefreshIntervalSeconds = backendIt->second.refreshIntervalSeconds;
    if (!backendIt->second.overlayPath.empty()) {
        out.security.osvOverlayPath = backendIt->second.overlayPath;
    }
}

void merge_gh_advisory_gateway_backend(SecuritySettings& out, const SecuritySettings& in,
                                       const std::string& backendId) {
    const auto backendIt = in.security.backends.find(backendId);
    if (backendIt == in.security.backends.end()) {
        return;
    }
    out.security.backends[backendId].feedUrl = backendIt->second.feedUrl;
    out.security.backends[backendId].refreshMode = backendIt->second.refreshMode;
    out.security.backends[backendId].refreshIntervalSeconds = backendIt->second.refreshIntervalSeconds;
}

void apply_osv_force_refresh(SecuritySettings& out, const std::string& /*backendId*/) {
    out.security.osvRefreshMode = OsvRefreshMode::ALWAYS;
}

void apply_gh_advisory_force_refresh(SecuritySettings& out, const std::string& backendId) {
    out.security.osvRefreshMode = OsvRefreshMode::ALWAYS;
    out.security.backends[backendId].refreshMode = OsvRefreshMode::ALWAYS;
}

} // namespace rqp::sync_backend_internal

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

std::string normalize_trivy_severity(const std::string& value, double score) {
    const std::string normalized = to_lower_copy(trim_copy(value));
    if (normalized == "critical" || normalized == "high" || normalized == "medium" || normalized == "low") {
        return normalized;
    }
    if (score >= 9.0) {
        return "critical";
    }
    if (score >= 7.0) {
        return "high";
    }
    if (score >= 4.0) {
        return "medium";
    }
    if (score > 0.0) {
        return "low";
    }
    return "unassigned";
}

bool scope_matches(const VulnerabilityDatabase* database, const std::set<std::string>& ecosystems) {
    return rqp_security_detail::sync_scope_matches(database, ecosystems, TRIVY_SYNC_KEY_SCOPE);
}

bool should_refresh(const VulnerabilityDatabase* database, const SecurityBackendConfig& backend, bool forceRefresh) {
    return rqp_security_detail::sync_should_refresh(database, backend, forceRefresh, TRIVY_SYNC_KEY_LAST_SUCCESS);
}

} // namespace trivy_sync_internal

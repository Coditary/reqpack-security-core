#include "detail/sync_refresh.h"

#include "detail/sync_common.h"

namespace rqp_security_detail {

bool sync_scope_matches(const VulnerabilityDatabase* database, const std::set<std::string>& ecosystems,
                        const char* scopeStateKey) {
    if (database == nullptr) {
        return false;
    }
    return database->getSyncState(scopeStateKey).value_or(std::string{}) == join_scope_key(ecosystems);
}

bool sync_should_refresh(const VulnerabilityDatabase* database, const SecurityBackendConfig& backend, bool forceRefresh,
                         const char* lastSuccessStateKey) {
    if (forceRefresh || database == nullptr) {
        return true;
    }
    if (backend.refreshMode == OsvRefreshMode::ALWAYS) {
        return true;
    }
    if (backend.refreshMode == OsvRefreshMode::MANUAL) {
        return !database->hasAdvisories();
    }

    const auto lastSync = database->getSyncState(lastSuccessStateKey);
    if (!lastSync.has_value()) {
        return true;
    }
    try {
        const long last = std::stol(lastSync.value());
        const long now = std::stol(now_epoch_seconds());
        return (now - last) >= backend.refreshIntervalSeconds;
    } catch (...) {
        return true;
    }
}

} // namespace rqp_security_detail

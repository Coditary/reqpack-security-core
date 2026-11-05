#pragma once

#include "rqp/security/security_config.h"
#include "rqp/security/vulnerability_database.h"

#include <set>
#include <string>

namespace rqp_security_detail {

bool sync_scope_matches(const VulnerabilityDatabase* database, const std::set<std::string>& ecosystems,
                        const char* scopeStateKey);

bool sync_should_refresh(const VulnerabilityDatabase* database, const SecurityBackendConfig& backend, bool forceRefresh,
                         const char* lastSuccessStateKey);

} // namespace rqp_security_detail

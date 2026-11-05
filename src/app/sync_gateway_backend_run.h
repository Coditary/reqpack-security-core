#pragma once

#include "rqp/security/security_settings.h"
#include "rqp/security/validator_core.h"

#include <set>
#include <string>
#include <vector>

class PluginMetadataProvider;
class VulnerabilityDatabase;

/// Runs a registered sync backend via `ISyncBackend` when a database is available, otherwise legacy runner.
[[nodiscard]] std::vector<ValidationFinding>
run_registered_sync_backend(const std::string& backendId, VulnerabilityDatabase* database,
                            PluginMetadataProvider* metadataProvider, const SecuritySettings& config,
                            const std::set<std::string>& ecosystems, bool forceRefresh);

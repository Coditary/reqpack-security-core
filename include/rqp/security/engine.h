#pragma once

#include "rqp/security/graph_adapter.h"
#include "rqp/security/osv_core.h"
#include "rqp/security/plugin_metadata_provider.h"
#include "rqp/security/security_settings.h"
#include "rqp/security/security_types.h"
#include "rqp/security/validator_core.h"

#include <span>
#include <vector>

class VulnerabilityDatabase;

namespace rqp::security {

/// Shared scan path for Validator and exchange transforms (inventory in, findings out).
[[nodiscard]] std::vector<ValidationFinding> scan_packages(std::span<const Package> packages,
                                                           const VulnerabilityDatabase* database,
                                                           std::span<const OsvAdvisory> overlayAdvisories,
                                                           PluginMetadataProvider* metadataProvider,
                                                           const SecuritySettings& settings);

[[nodiscard]] std::vector<ValidationFinding> scan_graph(const Graph& graph, const VulnerabilityDatabase* database,
                                                        std::span<const OsvAdvisory> overlayAdvisories,
                                                        PluginMetadataProvider* metadataProvider,
                                                        const SecuritySettings& settings);

} // namespace rqp::security

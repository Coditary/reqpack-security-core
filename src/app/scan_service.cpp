#include "rqp/security/engine.h"

#include "adapters/matching/lmdb_ecosystem_advisory_resolver.h"
#include "rqp/security/vulnerability_database.h"
#include "rqp/security/vulnerability_matcher.h"

namespace rqp::security {

std::vector<ValidationFinding> scan_packages(std::span<const Package> packages, const VulnerabilityDatabase* database,
                                             std::span<const OsvAdvisory> overlayAdvisories,
                                             PluginMetadataProvider* metadataProvider,
                                             const SecuritySettings& settings) {
    LmdbEcosystemAdvisoryResolver advisoryResolver(settings, static_cast<const IAdvisoryReader*>(database));
    VulnerabilityMatcher matcher(metadataProvider, settings);
    matcher.setEcosystemAdvisoryResolver(&advisoryResolver);
    if (!overlayAdvisories.empty()) {
        std::vector<OsvAdvisory> overlay(overlayAdvisories.begin(), overlayAdvisories.end());
        matcher.setAdvisories(std::move(overlay));
    }
    return matcher.matchPackages(packages);
}

std::vector<ValidationFinding> scan_graph(const Graph& graph, const VulnerabilityDatabase* database,
                                          std::span<const OsvAdvisory> overlayAdvisories,
                                          PluginMetadataProvider* metadataProvider, const SecuritySettings& settings) {
    LmdbEcosystemAdvisoryResolver advisoryResolver(settings, static_cast<const IAdvisoryReader*>(database));
    VulnerabilityMatcher matcher(metadataProvider, settings);
    matcher.setEcosystemAdvisoryResolver(&advisoryResolver);
    if (!overlayAdvisories.empty()) {
        std::vector<OsvAdvisory> overlay(overlayAdvisories.begin(), overlayAdvisories.end());
        matcher.setAdvisories(std::move(overlay));
    }
    return matcher.matchGraph(graph);
}

} // namespace rqp::security

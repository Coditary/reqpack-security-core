#include "rqp/security/engine.h"
#include "rqp/security/exchange.h"
#include "rqp/security/graph_adapter.h"
#include "rqp/security/osv_core.h"

VulnScanTransform::VulnScanTransform(const ExchangeCtx& context)
    : settings(context.settings), metadataProvider(context.metadataProvider) {}

ExchangeKind VulnScanTransform::kind() const {
    return ExchangeKind::AUDIT_REPORT;
}

ExchangeDoc VulnScanTransform::transform(const ExchangeDoc& document, const ExchangeCtx& context) const {
    (void)context;
    ExchangeDoc result = document;
    const std::vector<Package> packages = packages_from_graph(document.graph);
    std::vector<OsvAdvisory> overlay;
    if (!this->settings.security.osvOverlayPath.empty()) {
        overlay = osv_load_advisories_from_path(this->settings.security.osvOverlayPath);
    }
    result.findings = rqp::security::scan_packages(packages, nullptr, overlay, this->metadataProvider, this->settings);
    return result;
}

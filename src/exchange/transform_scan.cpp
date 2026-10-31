#include "rqp/security/exchange.h"

#include "rqp/security/vulnerability_matcher.h"

VulnScanTransform::VulnScanTransform(const ExchangeCtx& context)
    : settings(context.settings), metadataProvider(context.metadataProvider) {}

ExchangeKind VulnScanTransform::kind() const {
    return ExchangeKind::AUDIT_REPORT;
}

ExchangeDoc VulnScanTransform::transform(const ExchangeDoc& document,
                                                               const ExchangeCtx& context) const {
    (void)context;
    ExchangeDoc result = document;
    VulnerabilityMatcher matcher(this->metadataProvider, this->settings);
    result.findings = matcher.matchGraph(document.graph);
    return result;
}

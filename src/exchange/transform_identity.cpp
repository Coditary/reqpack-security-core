#include "rqp/security/exchange.h"

ExchangeKind IdentityTransform::kind() const {
    return ExchangeKind::INVENTORY;
}

ExchangeDoc IdentityTransform::transform(const ExchangeDoc& document, const ExchangeCtx& context) const {
    (void)context;
    return document;
}

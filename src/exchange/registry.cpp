#include "rqp/security/exchange.h"

#include <memory>

std::unique_ptr<IExchangeCodec> create_sbom_codec();
std::unique_ptr<IExchangeCodec> create_audit_codec();

std::unique_ptr<IExchangeCodec> create_codec(const ExchangeKind kind) {
    switch (kind) {
    case ExchangeKind::INVENTORY:
        return create_sbom_codec();
    case ExchangeKind::AUDIT_REPORT:
        return create_audit_codec();
    }
    return nullptr;
}

std::unique_ptr<IExchangeIn> create_in(const ExchangeKind kind) {
    std::unique_ptr<IExchangeCodec> codec = create_codec(kind);
    if (codec == nullptr) {
        return nullptr;
    }
    return std::unique_ptr<IExchangeIn>(codec.release());
}

std::unique_ptr<IExchangeOut> create_out(const ExchangeKind kind) {
    std::unique_ptr<IExchangeCodec> codec = create_codec(kind);
    if (codec == nullptr) {
        return nullptr;
    }
    return std::unique_ptr<IExchangeOut>(codec.release());
}

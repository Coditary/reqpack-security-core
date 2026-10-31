#include "rqp/security/exchange.h"

PipelineResult run_pipeline(
    const std::string& inputPayload, WireFormat inputFormat, const IExchangeIn& input,
    const IExchangeTransform& transform, const IExchangeOut& output,
    WireFormat outputFormat, const ExchangeCtx& context) {
    PipelineResult pipelineResult;

    const AcceptResult accepted = input.accept(inputPayload, inputFormat, context);
    pipelineResult.warnings = accepted.warnings;
    if (accepted.error.has_value()) {
        pipelineResult.error = accepted.error;
        return pipelineResult;
    }

    const ExchangeDoc transformed = transform.transform(accepted.document, context);
    const EmitResult emitted = output.emit(transformed, outputFormat, context);
    if (emitted.error.has_value()) {
        pipelineResult.error = emitted.error;
        return pipelineResult;
    }

    pipelineResult.payload = emitted.payload;
    return pipelineResult;
}

PipelineResult run_pipeline(
    const std::string& inputPayload, WireFormat inputFormat, const IExchangeCodec& codec,
    const IExchangeTransform& transform, WireFormat outputFormat,
    const ExchangeCtx& context) {
    return run_pipeline(inputPayload, inputFormat, codec, transform, codec, outputFormat, context);
}

WireFormat wire_format_from_name(const std::string& name) {
    if (name == "cyclonedx" || name == "cyclonedx-json") {
        return WireFormat::CYCLONEDX;
    }
    if (name == "spdx" || name == "spdx-json") {
        return WireFormat::SPDX;
    }
    if (name == "reqpack-json" || name == "reqpack-sbom-json") {
        return WireFormat::REQPACK_SBOM_JSON;
    }
    if (name == "reqpack-audit-json" || name == "audit-json") {
        return WireFormat::REQPACK_AUDIT_JSON;
    }
    return WireFormat::AUTO;
}

PipelineResult transform_inventory(const std::string& inputPayload,
                                                           WireFormat inputFormat,
                                                           const IExchangeTransform& transform,
                                                           WireFormat outputFormat,
                                                           const ExchangeCtx& context) {
    const auto codec = create_codec(ExchangeKind::INVENTORY);
    if (codec == nullptr) {
        return PipelineResult{.error = "inventory document codec is unavailable"};
    }
    return run_pipeline(inputPayload, inputFormat, *codec, transform, outputFormat, context);
}

PipelineResult transform_inventory(const std::string& inputPayload,
                                                           WireFormat inputFormat,
                                                           WireFormat outputFormat,
                                                           const ExchangeCtx& context) {
    IdentityTransform identity;
    return transform_inventory(inputPayload, inputFormat, identity, outputFormat, context);
}

std::string wire_format_name(const WireFormat format) {
    switch (format) {
    case WireFormat::CYCLONEDX:
        return "cyclonedx";
    case WireFormat::SPDX:
        return "spdx";
    case WireFormat::REQPACK_SBOM_JSON:
        return "reqpack-sbom-json";
    case WireFormat::REQPACK_AUDIT_JSON:
        return "reqpack-audit-json";
    case WireFormat::AUTO:
        return "auto";
    }
    return "auto";
}

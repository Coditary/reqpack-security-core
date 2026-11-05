#pragma once

#include "rqp/security/exchange.h"

#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <vector>

enum class PayloadKind {
    INVENTORY,
    AUDIT_REPORT,
};

struct PkgRow {
    std::string ref;
    std::string system;
    std::string name;
    std::string version;
    std::string displayName;
    std::string purl;
    std::string sourcePath;
    bool localTarget{false};
};

struct DepEdge {
    std::string fromRef;
    std::string toRef;
};

struct FindingRow {
    std::string id;
    std::string kind;
    std::string source;
    std::string severity;
    double score{0.0};
    std::string message;
    std::string packageRef;
};

struct ExchangeView {
    PayloadKind kind{PayloadKind::INVENTORY};
    WireFormat sourceFormat{WireFormat::AUTO};
    std::string detectedFormat;

    std::vector<std::string> warnings;
    std::optional<std::string> error;

    std::vector<PkgRow> packages;
    std::vector<DepEdge> dependencies;
    std::vector<FindingRow> findings;
    std::map<std::string, std::size_t> countsBySeverity;
};

struct DecodeResult {
    ExchangeView view;
    std::vector<std::string> warnings;
    std::optional<std::string> error;
};

std::string package_ref(const Package& package);

ExchangeView doc_to_view(const ExchangeDoc& document, WireFormat sourceFormat, const ExchangeCtx& context);

DecodeResult decode_to_view(const std::string& inputPayload, WireFormat inputFormat, const ExchangeCtx& context = {});

DecodeResult decode_to_view(const std::string& inputPayload, WireFormat inputFormat,
                            const IExchangeTransform& transform, const ExchangeCtx& context = {});

std::string view_to_json(const ExchangeView& view);

struct PipelineViewResult {
    PipelineResult wire;
    ExchangeView view;
};

PipelineViewResult run_pipeline_with_view(const std::string& inputPayload, WireFormat inputFormat,
                                          const IExchangeIn& input, const IExchangeTransform& transform,
                                          const IExchangeOut& output, WireFormat outputFormat,
                                          const ExchangeCtx& context);

PipelineViewResult run_pipeline_with_view(const std::string& inputPayload, WireFormat inputFormat,
                                          const IExchangeCodec& codec, const IExchangeTransform& transform,
                                          WireFormat outputFormat, const ExchangeCtx& context);

PipelineViewResult transform_inventory_with_view(const std::string& inputPayload, WireFormat inputFormat,
                                                 const IExchangeTransform& transform, WireFormat outputFormat,
                                                 const ExchangeCtx& context = {});

#pragma once

#include "rqp/security/plugin_metadata_provider.h"
#include "rqp/security/security_settings.h"
#include "rqp/security/security_types.h"
#include "rqp/security/validator_core.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

enum class WireFormat {
    AUTO,
    CYCLONEDX,
    SPDX,
    REQPACK_SBOM_JSON,
    REQPACK_AUDIT_JSON,
};

enum class ExchangeKind {
    INVENTORY,
    AUDIT_REPORT,
};

struct ExchangeCtx {
    SecuritySettings settings = default_security_settings();
    PluginMetadataProvider* metadataProvider{nullptr};
};

struct ExchangeDoc {
    Graph graph;
    std::vector<ValidationFinding> findings;
    std::string detectedFormat;
};

struct AcceptResult {
    ExchangeDoc document;
    std::vector<std::string> warnings;
    std::optional<std::string> error;
};

struct EmitResult {
    std::string payload;
    std::optional<std::string> error;
};

struct PipelineResult {
    std::string payload;
    std::vector<std::string> warnings;
    std::optional<std::string> error;
};

class IExchangeIn {
  public:
    virtual ~IExchangeIn() = default;
    virtual ExchangeKind kind() const = 0;
    virtual AcceptResult accept(const std::string& payload, WireFormat format, const ExchangeCtx& context) const = 0;
};

class IExchangeOut {
  public:
    virtual ~IExchangeOut() = default;
    virtual ExchangeKind kind() const = 0;
    virtual EmitResult emit(const ExchangeDoc& document, WireFormat format, const ExchangeCtx& context) const = 0;
};

class IExchangeCodec : public IExchangeIn, public IExchangeOut {};

class IExchangeTransform {
  public:
    virtual ~IExchangeTransform() = default;
    virtual ExchangeKind kind() const = 0;
    virtual ExchangeDoc transform(const ExchangeDoc& document, const ExchangeCtx& context) const = 0;
};

class IdentityTransform final : public IExchangeTransform {
  public:
    ExchangeKind kind() const override;
    ExchangeDoc transform(const ExchangeDoc& document, const ExchangeCtx& context) const override;
};

class VulnScanTransform final : public IExchangeTransform {
  public:
    explicit VulnScanTransform(const ExchangeCtx& context = {});

    ExchangeKind kind() const override;
    ExchangeDoc transform(const ExchangeDoc& document, const ExchangeCtx& context) const override;

  private:
    SecuritySettings settings;
    PluginMetadataProvider* metadataProvider{nullptr};
};

PipelineResult run_pipeline(const std::string& inputPayload, WireFormat inputFormat, const IExchangeIn& input,
                            const IExchangeTransform& transform, const IExchangeOut& output, WireFormat outputFormat,
                            const ExchangeCtx& context);

PipelineResult run_pipeline(const std::string& inputPayload, WireFormat inputFormat, const IExchangeCodec& codec,
                            const IExchangeTransform& transform, WireFormat outputFormat, const ExchangeCtx& context);

std::unique_ptr<IExchangeCodec> create_codec(ExchangeKind kind);

std::unique_ptr<IExchangeIn> create_in(ExchangeKind kind);
std::unique_ptr<IExchangeOut> create_out(ExchangeKind kind);

WireFormat wire_format_from_name(const std::string& name);
std::string wire_format_name(WireFormat format);

PipelineResult transform_inventory(const std::string& inputPayload, WireFormat inputFormat,
                                   const IExchangeTransform& transform, WireFormat outputFormat,
                                   const ExchangeCtx& context = {});

PipelineResult transform_inventory(const std::string& inputPayload, WireFormat inputFormat, WireFormat outputFormat,
                                   const ExchangeCtx& context = {});

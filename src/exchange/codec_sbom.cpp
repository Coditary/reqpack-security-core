#include "rqp/security/sbom_inventory.h"
#include "rqp/security/exchange.h"

#include "detail/sync_common.h"

#include <boost/graph/graph_traits.hpp>

#include <filesystem>
#include <sstream>
#include <vector>

namespace {

using rqp_security_detail::json_escape;

SbomInventoryFormat to_inventory_format(const WireFormat format) {
    switch (format) {
    case WireFormat::CYCLONEDX:
        return SbomInventoryFormat::CYCLONEDX;
    case WireFormat::SPDX:
        return SbomInventoryFormat::SPDX;
    case WireFormat::REQPACK_SBOM_JSON:
        return SbomInventoryFormat::REQPACK_JSON;
    case WireFormat::AUTO:
        return SbomInventoryFormat::AUTO;
    case WireFormat::REQPACK_AUDIT_JSON:
        return SbomInventoryFormat::AUTO;
    }
    return SbomInventoryFormat::AUTO;
}

std::vector<Graph::vertex_descriptor> ordered_vertices(const Graph& graph) {
    std::vector<Graph::vertex_descriptor> vertices;
    auto [it, end] = boost::vertices(graph);
    for (; it != end; ++it) {
        vertices.push_back(*it);
    }
    return vertices;
}

std::string component_ref(const Package& package) {
    std::ostringstream stream;
    stream << package.system << ':' << package.name;
    if (!package.version.empty()) {
        stream << '@' << package.version;
    }
    return stream.str();
}

std::string display_name(const Package& package) {
    if (package.localTarget && !package.sourcePath.empty()) {
        return std::filesystem::path(package.sourcePath).filename().string();
    }
    return package.name;
}

std::string purl_name_for(const Package& package, const PluginSecurityMetadata& metadata) {
    if (package.name.empty()) {
        return {};
    }
    if (metadata.purlType == "maven") {
        const std::size_t separator = package.name.find(':');
        if (separator == std::string::npos || separator == 0 || separator == package.name.size() - 1) {
            return {};
        }
        return package.name.substr(0, separator) + "/" + package.name.substr(separator + 1);
    }
    return package.name;
}

std::string purl_for(const Package& package, PluginMetadataProvider* metadataProvider) {
    if (package.name.empty() || metadataProvider == nullptr) {
        return {};
    }
    const auto metadata = metadataProvider->getPluginSecurityMetadata(package.system);
    if (!metadata.has_value() || metadata->purlType.empty()) {
        return {};
    }
    const std::string purlName = purl_name_for(package, metadata.value());
    if (purlName.empty()) {
        return {};
    }
    std::string purl = "pkg:" + metadata->purlType + "/" + purlName;
    if (!package.version.empty()) {
        purl += '@' + package.version;
    }
    return purl;
}

EmitResult emit_reqpack_sbom_json(const ExchangeDoc& document) {
    EmitResult result;
    std::ostringstream stream;
    stream << "{\n  \"packages\": [\n";
    const std::vector<Graph::vertex_descriptor> vertices = ordered_vertices(document.graph);
    for (std::size_t index = 0; index < vertices.size(); ++index) {
        const Package& package = document.graph[vertices[index]];
        stream << "    {\n";
        stream << "      \"system\": \"" << json_escape(package.system) << "\",\n";
        stream << "      \"name\": \"" << json_escape(package.name) << "\",\n";
        stream << "      \"version\": \"" << json_escape(package.version) << "\",\n";
        stream << "      \"sourcePath\": \"" << json_escape(package.sourcePath) << "\",\n";
        stream << "      \"localTarget\": " << (package.localTarget ? "true" : "false") << "\n";
        stream << "    }";
        if (index + 1 < vertices.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ]\n}";
    result.payload = stream.str();
    return result;
}

EmitResult emit_cyclonedx(const ExchangeDoc& document, const ExchangeCtx& context) {
    EmitResult result;
    std::ostringstream stream;
    stream << "{\n";
    stream << "  \"bomFormat\": \"CycloneDX\",\n";
    stream << "  \"specVersion\": \"1.5\",\n";
    stream << "  \"version\": 1,\n";
    stream << "  \"components\": [\n";
    const std::vector<Graph::vertex_descriptor> vertices = ordered_vertices(document.graph);
    for (std::size_t index = 0; index < vertices.size(); ++index) {
        const Package& package = document.graph[vertices[index]];
        stream << "    {\n";
        stream << "      \"type\": \"library\",\n";
        stream << "      \"bom-ref\": \"" << json_escape(component_ref(package)) << "\",\n";
        stream << "      \"name\": \"" << json_escape(display_name(package)) << "\"";
        if (!package.version.empty()) {
            stream << ",\n      \"version\": \"" << json_escape(package.version) << "\"";
        }
        const std::string purl = purl_for(package, context.metadataProvider);
        if (!purl.empty()) {
            stream << ",\n      \"purl\": \"" << json_escape(purl) << "\"";
        }
        stream << ",\n      \"properties\": [\n";
        stream << "        {\"name\": \"reqpack:system\", \"value\": \"" << json_escape(package.system) << "\"}\n";
        stream << "      ]\n";
        stream << "    }";
        if (index + 1 < vertices.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ]\n}";
    result.payload = stream.str();
    return result;
}

EmitResult emit_spdx(const ExchangeDoc& document, const ExchangeCtx& context) {
    EmitResult result;
    std::ostringstream stream;
    stream << "{\n";
    stream << "  \"spdxVersion\": \"SPDX-2.3\",\n";
    stream << "  \"dataLicense\": \"CC0-1.0\",\n";
    stream << "  \"SPDXID\": \"SPDXRef-DOCUMENT\",\n";
    stream << "  \"name\": \"reqpack-sbom\",\n";
    stream << "  \"packages\": [\n";
    const std::vector<Graph::vertex_descriptor> vertices = ordered_vertices(document.graph);
    for (std::size_t index = 0; index < vertices.size(); ++index) {
        const Package& package = document.graph[vertices[index]];
        stream << "    {\n";
        stream << "      \"SPDXID\": \"SPDXRef-Package-" << index << "\",\n";
        stream << "      \"name\": \"" << json_escape(display_name(package)) << "\",\n";
        stream << "      \"versionInfo\": \"" << json_escape(package.version) << "\",\n";
        stream << "      \"externalRefs\": [\n";
        stream << "        {\n";
        stream << "          \"referenceCategory\": \"PACKAGE-MANAGER\",\n";
        stream << "          \"referenceType\": \"other\",\n";
        stream << "          \"referenceLocator\": \"" << json_escape("reqpack:" + package.system) << "\"\n";
        stream << "        }";
        const std::string purl = purl_for(package, context.metadataProvider);
        if (!purl.empty()) {
            stream << ",\n        {\n";
            stream << "          \"referenceCategory\": \"PACKAGE-MANAGER\",\n";
            stream << "          \"referenceType\": \"purl\",\n";
            stream << "          \"referenceLocator\": \"" << json_escape(purl) << "\"\n";
            stream << "        }";
        }
        stream << "\n      ]\n";
        stream << "    }";
        if (index + 1 < vertices.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ]\n}";
    result.payload = stream.str();
    return result;
}

WireFormat resolve_auto_output_format(const ExchangeDoc& document) {
    if (document.detectedFormat == "cyclonedx") {
        return WireFormat::CYCLONEDX;
    }
    if (document.detectedFormat == "spdx") {
        return WireFormat::SPDX;
    }
    if (document.detectedFormat == "reqpack-json") {
        return WireFormat::REQPACK_SBOM_JSON;
    }
    return WireFormat::REQPACK_SBOM_JSON;
}

} // namespace

class SbomCodec : public IExchangeCodec {
  public:
    virtual ~SbomCodec() = default;

    ExchangeKind kind() const override {
        return ExchangeKind::INVENTORY;
    }

    AcceptResult accept(const std::string& payload, WireFormat format,
                                        const ExchangeCtx& context) const override {
        AcceptResult result;
        const SbomImportResult imported =
            import_sbom_from_json(payload, context.settings, to_inventory_format(format));
        for (const SbomImportWarning& warning : imported.warnings) {
            result.warnings.push_back(warning.message);
        }
        if (imported.error.has_value()) {
            result.error = imported.error;
            return result;
        }

        result.document.graph = imported.graph;
        result.document.detectedFormat = imported.detectedFormat;
        return result;
    }

    virtual EmitResult emit(const ExchangeDoc& document, WireFormat format,
                                            const ExchangeCtx& context) const override {
        const WireFormat resolved =
            format == WireFormat::AUTO ? resolve_auto_output_format(document) : format;
        switch (resolved) {
        case WireFormat::CYCLONEDX:
            return emit_cyclonedx(document, context);
        case WireFormat::SPDX:
            return emit_spdx(document, context);
        case WireFormat::REQPACK_SBOM_JSON:
            return emit_reqpack_sbom_json(document);
        case WireFormat::REQPACK_AUDIT_JSON:
            return EmitResult{.error = "inventory codec does not support reqpack-audit-json"};
        case WireFormat::AUTO:
            return EmitResult{.error = "unable to resolve sbom output format"};
        }
        return EmitResult{.error = "unsupported sbom output format"};
    }
};

class AuditCodec final : public SbomCodec {
  public:
    ExchangeKind kind() const override {
        return ExchangeKind::AUDIT_REPORT;
    }

    EmitResult emit(const ExchangeDoc& document, WireFormat format,
                                    const ExchangeCtx& context) const override {
        (void)context;
        if (format != WireFormat::REQPACK_AUDIT_JSON && format != WireFormat::AUTO) {
            return EmitResult{.error = "audit codec supports reqpack-audit-json only"};
        }

        EmitResult result;
        std::ostringstream stream;
        stream << "{\n  \"findings\": [\n";
        for (std::size_t index = 0; index < document.findings.size(); ++index) {
            const ValidationFinding& finding = document.findings[index];
            stream << "    {\n";
            stream << "      \"id\": \"" << json_escape(finding.id) << "\",\n";
            stream << "      \"kind\": \"" << json_escape(finding.kind) << "\",\n";
            stream << "      \"source\": \"" << json_escape(finding.source) << "\",\n";
            stream << "      \"severity\": \"" << json_escape(finding.severity) << "\",\n";
            stream << "      \"score\": " << finding.score << ",\n";
            stream << "      \"message\": \"" << json_escape(finding.message) << "\",\n";
            stream << "      \"package\": {\n";
            stream << "        \"system\": \"" << json_escape(finding.package.system) << "\",\n";
            stream << "        \"name\": \"" << json_escape(finding.package.name) << "\",\n";
            stream << "        \"version\": \"" << json_escape(finding.package.version) << "\"\n";
            stream << "      }\n";
            stream << "    }";
            if (index + 1 < document.findings.size()) {
                stream << ',';
            }
            stream << '\n';
        }
        stream << "  ],\n  \"packageCount\": " << boost::num_vertices(document.graph) << "\n}";
        result.payload = stream.str();
        return result;
    }
};

std::unique_ptr<IExchangeCodec> create_sbom_codec() {
    return std::make_unique<SbomCodec>();
}

std::unique_ptr<IExchangeCodec> create_audit_codec() {
    return std::make_unique<AuditCodec>();
}

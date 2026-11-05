#include "rqp/security/exchange_view.h"

#include "detail/sync_common.h"

#include <boost/graph/graph_traits.hpp>

#include <filesystem>
#include <sstream>

namespace {

using rqp_security_detail::json_escape;

std::vector<Graph::vertex_descriptor> ordered_vertices(const Graph& graph) {
    std::vector<Graph::vertex_descriptor> vertices;
    auto [it, end] = boost::vertices(graph);
    for (; it != end; ++it) {
        vertices.push_back(*it);
    }
    return vertices;
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

PkgRow package_record(const Package& package, PluginMetadataProvider* metadataProvider) {
    return PkgRow{
        .ref = package_ref(package),
        .system = package.system,
        .name = package.name,
        .version = package.version,
        .displayName = display_name(package),
        .purl = purl_for(package, metadataProvider),
        .sourcePath = package.sourcePath,
        .localTarget = package.localTarget,
    };
}

void append_dependencies(const Graph& graph, std::vector<DepEdge>& dependencies) {
    auto [edgeIt, edgeEnd] = boost::edges(graph);
    for (; edgeIt != edgeEnd; ++edgeIt) {
        const Package& from = graph[boost::source(*edgeIt, graph)];
        const Package& to = graph[boost::target(*edgeIt, graph)];
        dependencies.push_back(DepEdge{
            .fromRef = package_ref(from),
            .toRef = package_ref(to),
        });
    }
}

void append_findings(const ExchangeDoc& document, ExchangeView& envelope) {
    for (const ValidationFinding& finding : document.findings) {
        envelope.findings.push_back(FindingRow{
            .id = finding.id,
            .kind = finding.kind,
            .source = finding.source,
            .severity = finding.severity,
            .score = finding.score,
            .message = finding.message,
            .packageRef = package_ref(finding.package),
        });
        if (!finding.severity.empty()) {
            envelope.countsBySeverity[finding.severity]++;
        }
    }
}

} // namespace

std::string package_ref(const Package& package) {
    std::ostringstream stream;
    stream << package.system << ':' << package.name;
    if (!package.version.empty()) {
        stream << '@' << package.version;
    }
    return stream.str();
}

ExchangeView doc_to_view(const ExchangeDoc& document, WireFormat sourceFormat, const ExchangeCtx& context) {
    ExchangeView envelope;
    envelope.sourceFormat = sourceFormat;
    envelope.detectedFormat = document.detectedFormat;
    envelope.kind = document.findings.empty() ? PayloadKind::INVENTORY : PayloadKind::AUDIT_REPORT;

    const std::vector<Graph::vertex_descriptor> vertices = ordered_vertices(document.graph);
    for (const Graph::vertex_descriptor vertex : vertices) {
        envelope.packages.push_back(package_record(document.graph[vertex], context.metadataProvider));
    }
    append_dependencies(document.graph, envelope.dependencies);
    append_findings(document, envelope);
    return envelope;
}

DecodeResult decode_to_view(const std::string& inputPayload, WireFormat inputFormat, const ExchangeCtx& context) {
    IdentityTransform identity;
    return decode_to_view(inputPayload, inputFormat, identity, context);
}

DecodeResult decode_to_view(const std::string& inputPayload, WireFormat inputFormat,
                            const IExchangeTransform& transform, const ExchangeCtx& context) {
    DecodeResult result;
    const auto inputAdapter = create_in(ExchangeKind::INVENTORY);
    if (inputAdapter == nullptr) {
        result.error = "inventory document input is unavailable";
        return result;
    }

    const AcceptResult accepted = inputAdapter->accept(inputPayload, inputFormat, context);
    result.warnings = accepted.warnings;
    if (accepted.error.has_value()) {
        result.error = accepted.error;
        return result;
    }

    const ExchangeDoc transformed = transform.transform(accepted.document, context);
    result.view = doc_to_view(transformed, inputFormat, context);
    result.view.warnings = result.warnings;
    return result;
}

PipelineViewResult run_pipeline_with_view(const std::string& inputPayload, WireFormat inputFormat,
                                          const IExchangeCodec& codec, const IExchangeTransform& transform,
                                          WireFormat outputFormat, const ExchangeCtx& context) {
    return run_pipeline_with_view(inputPayload, inputFormat, static_cast<const IExchangeIn&>(codec), transform,
                                  static_cast<const IExchangeOut&>(codec), outputFormat, context);
}

PipelineViewResult run_pipeline_with_view(const std::string& inputPayload, WireFormat inputFormat,
                                          const IExchangeIn& input, const IExchangeTransform& transform,
                                          const IExchangeOut& output, WireFormat outputFormat,
                                          const ExchangeCtx& context) {
    PipelineViewResult combined;
    const AcceptResult accepted = input.accept(inputPayload, inputFormat, context);
    combined.wire.warnings = accepted.warnings;
    combined.view.warnings = accepted.warnings;
    if (accepted.error.has_value()) {
        combined.wire.error = accepted.error;
        combined.view.error = accepted.error;
        return combined;
    }

    const ExchangeDoc transformed = transform.transform(accepted.document, context);
    combined.view = doc_to_view(transformed, inputFormat, context);
    combined.view.warnings = combined.wire.warnings;

    const EmitResult emitted = output.emit(transformed, outputFormat, context);
    if (emitted.error.has_value()) {
        combined.wire.error = emitted.error;
        return combined;
    }
    combined.wire.payload = emitted.payload;
    return combined;
}

PipelineViewResult transform_inventory_with_view(const std::string& inputPayload, WireFormat inputFormat,
                                                 const IExchangeTransform& transform, WireFormat outputFormat,
                                                 const ExchangeCtx& context) {
    const auto codec = create_codec(ExchangeKind::INVENTORY);
    if (codec == nullptr) {
        return PipelineViewResult{.wire = PipelineResult{.error = "inventory document codec is unavailable"}};
    }
    return run_pipeline_with_view(inputPayload, inputFormat, *codec, transform, outputFormat, context);
}

std::string view_to_json(const ExchangeView& envelope) {
    std::ostringstream stream;
    stream << "{\n";
    stream << "  \"kind\": \"" << (envelope.kind == PayloadKind::AUDIT_REPORT ? "audit-report" : "inventory")
           << "\",\n";
    stream << "  \"sourceFormat\": \"" << json_escape(wire_format_name(envelope.sourceFormat)) << "\",\n";
    stream << "  \"detectedFormat\": \"" << json_escape(envelope.detectedFormat) << "\",\n";

    stream << "  \"warnings\": [";
    for (std::size_t index = 0; index < envelope.warnings.size(); ++index) {
        if (index > 0) {
            stream << ", ";
        }
        stream << "\"" << json_escape(envelope.warnings[index]) << "\"";
    }
    stream << "],\n";

    stream << "  \"packages\": [\n";
    for (std::size_t index = 0; index < envelope.packages.size(); ++index) {
        const PkgRow& package = envelope.packages[index];
        stream << "    {\n";
        stream << "      \"ref\": \"" << json_escape(package.ref) << "\",\n";
        stream << "      \"system\": \"" << json_escape(package.system) << "\",\n";
        stream << "      \"name\": \"" << json_escape(package.name) << "\",\n";
        stream << "      \"version\": \"" << json_escape(package.version) << "\",\n";
        stream << "      \"displayName\": \"" << json_escape(package.displayName) << "\",\n";
        stream << "      \"purl\": \"" << json_escape(package.purl) << "\",\n";
        stream << "      \"sourcePath\": \"" << json_escape(package.sourcePath) << "\",\n";
        stream << "      \"localTarget\": " << (package.localTarget ? "true" : "false") << "\n";
        stream << "    }";
        if (index + 1 < envelope.packages.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ],\n";

    stream << "  \"dependencies\": [\n";
    for (std::size_t index = 0; index < envelope.dependencies.size(); ++index) {
        const DepEdge& dependency = envelope.dependencies[index];
        stream << "    {\"fromRef\": \"" << json_escape(dependency.fromRef) << "\", \"toRef\": \""
               << json_escape(dependency.toRef) << "\"}";
        if (index + 1 < envelope.dependencies.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ],\n";

    stream << "  \"findings\": [\n";
    for (std::size_t index = 0; index < envelope.findings.size(); ++index) {
        const FindingRow& finding = envelope.findings[index];
        stream << "    {\n";
        stream << "      \"id\": \"" << json_escape(finding.id) << "\",\n";
        stream << "      \"kind\": \"" << json_escape(finding.kind) << "\",\n";
        stream << "      \"source\": \"" << json_escape(finding.source) << "\",\n";
        stream << "      \"severity\": \"" << json_escape(finding.severity) << "\",\n";
        stream << "      \"score\": " << finding.score << ",\n";
        stream << "      \"message\": \"" << json_escape(finding.message) << "\",\n";
        stream << "      \"packageRef\": \"" << json_escape(finding.packageRef) << "\"\n";
        stream << "    }";
        if (index + 1 < envelope.findings.size()) {
            stream << ',';
        }
        stream << '\n';
    }
    stream << "  ],\n";

    stream << "  \"countsBySeverity\": {";
    bool firstCount = true;
    for (const auto& [severity, count] : envelope.countsBySeverity) {
        if (!firstCount) {
            stream << ", ";
        }
        firstCount = false;
        stream << "\"" << json_escape(severity) << "\": " << count;
    }
    stream << "}\n";
    stream << '}';
    return stream.str();
}

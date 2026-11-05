#include "rqp/security/cyclonedx.h"

#include "cyclonedx/cyclonedx_ffi.h"

#include "rqp/security/json_util.h"

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_traits.hpp>

#include <filesystem>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

struct RustCStringDeleter {
    void operator()(char* pointer) const {
        if (pointer != nullptr) {
            rqp_cyclonedx_free(pointer);
        }
    }
};

using RustCString = std::unique_ptr<char, RustCStringDeleter>;

std::string quote_json_string(const std::string& value) {
    return std::string{"\""} + rqp_json_escape(value) + '"';
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

std::string component_ref(const Package& package) {
    std::ostringstream stream;
    stream << package.system << ':' << package.name;
    if (!package.version.empty()) {
        stream << '@' << package.version;
    }
    if (package.localTarget && !package.sourcePath.empty()) {
        stream << '#' << package.sourcePath;
    }
    return stream.str();
}

std::string display_name(const Package& package) {
    if (package.localTarget && !package.sourcePath.empty()) {
        return std::filesystem::path(package.sourcePath).filename().string();
    }
    return package.name;
}

std::vector<Graph::vertex_descriptor> ordered_vertices(const Graph& graph) {
    std::vector<Graph::vertex_descriptor> vertices;
    auto [it, end] = boost::vertices(graph);
    for (; it != end; ++it) {
        vertices.push_back(*it);
    }
    return vertices;
}

std::string invoke_rust_emit(const std::string& document_json) {
    char* rawOutput = nullptr;
    const int status = rqp_cyclonedx_emit_json(document_json.c_str(), &rawOutput);
    RustCString output(rawOutput);
    if (output == nullptr) {
        throw std::runtime_error("cyclonedx emit returned no payload");
    }
    const std::string payload(output.get());
    if (status != 0) {
        throw std::runtime_error("cyclonedx emit failed: " + payload);
    }
    return payload;
}

void append_component_json(std::ostringstream& stream, const Package& package, PluginMetadataProvider* metadataProvider,
                           const bool first) {
    if (!first) {
        stream << ',';
    }
    stream << '{';
    stream << "\"bom_ref\":" << quote_json_string(component_ref(package)) << ',';
    stream << "\"name\":" << quote_json_string(display_name(package));
    if (!package.version.empty()) {
        stream << ",\"version\":" << quote_json_string(package.version);
    }
    const std::string purl = purl_for(package, metadataProvider);
    if (!purl.empty()) {
        stream << ",\"purl\":" << quote_json_string(purl);
    }
    if (!package.system.empty()) {
        stream << ",\"system\":" << quote_json_string(package.system);
    }
    if (!package.sourcePath.empty()) {
        stream << ",\"source_path\":" << quote_json_string(package.sourcePath);
    }
    if (package.localTarget) {
        stream << ",\"local_target\":true";
    }
    stream << '}';
}

std::string vex_analysis_detail_for(const ValidationFinding& finding) {
    if (finding.kind == "vulnerability") {
        return "Matched by ReqPack audit from local vulnerability data. Reachability and exploitability were not "
               "analyzed.";
    }
    if (finding.kind == "unresolved_version") {
        return "ReqPack could not resolve package version. Vulnerability matching may be incomplete.";
    }
    if (finding.kind == "unsupported_ecosystem") {
        return "ReqPack has no vulnerability ecosystem mapping for this package system.";
    }
    if (finding.kind == "sync_error") {
        return "ReqPack could not fully refresh vulnerability data during audit.";
    }
    return finding.message;
}

std::string message_for(const ValidationFinding& finding) {
    if (!finding.message.empty()) {
        return finding.message;
    }
    if (finding.kind == "vulnerability") {
        return "Vulnerability finding for " + finding.package.system + ':' + finding.package.name;
    }
    return finding.kind;
}

} // namespace

std::string rqp_emit_cyclonedx_inventory_json(const Graph& graph, PluginMetadataProvider* metadataProvider,
                                              const bool includeDependencyEdges) {
    std::ostringstream stream;
    stream << "{\"components\":[";
    const std::vector<Graph::vertex_descriptor> vertices = ordered_vertices(graph);
    for (std::size_t index = 0; index < vertices.size(); ++index) {
        append_component_json(stream, graph[vertices[index]], metadataProvider, index == 0);
    }
    stream << ']';

    if (includeDependencyEdges) {
        stream << ",\"dependencies\":[";
        bool firstDependency = true;
        for (const Graph::vertex_descriptor vertex : vertices) {
            const Package& package = graph[vertex];
            if (!firstDependency) {
                stream << ',';
            }
            firstDependency = false;
            stream << '{';
            stream << "\"ref\":" << quote_json_string(component_ref(package)) << ",\"depends_on\":[";
            auto [adjacentIt, adjacentEnd] = boost::adjacent_vertices(vertex, graph);
            bool firstEdge = true;
            for (; adjacentIt != adjacentEnd; ++adjacentIt) {
                if (!firstEdge) {
                    stream << ',';
                }
                firstEdge = false;
                stream << quote_json_string(component_ref(graph[*adjacentIt]));
            }
            stream << "]}";
        }
        stream << ']';
    }

    stream << '}';
    return invoke_rust_emit(stream.str());
}

std::string rqp_emit_cyclonedx_audit_vex_json(const Graph& graph, const std::vector<ValidationFinding>& findings,
                                              PluginMetadataProvider* metadataProvider,
                                              const bool includeDependencyEdges) {
    std::ostringstream stream;
    stream << '{';
    stream << "\"components\":[";
    const std::vector<Graph::vertex_descriptor> vertices = ordered_vertices(graph);
    for (std::size_t index = 0; index < vertices.size(); ++index) {
        append_component_json(stream, graph[vertices[index]], metadataProvider, index == 0);
    }
    stream << ']';

    if (includeDependencyEdges) {
        stream << ",\"dependencies\":[";
        bool firstDependency = true;
        for (const Graph::vertex_descriptor vertex : vertices) {
            const Package& package = graph[vertex];
            if (!firstDependency) {
                stream << ',';
            }
            firstDependency = false;
            stream << '{';
            stream << "\"ref\":" << quote_json_string(component_ref(package)) << ",\"depends_on\":[";
            auto [adjacentIt, adjacentEnd] = boost::adjacent_vertices(vertex, graph);
            bool firstEdge = true;
            for (; adjacentIt != adjacentEnd; ++adjacentIt) {
                if (!firstEdge) {
                    stream << ',';
                }
                firstEdge = false;
                stream << quote_json_string(component_ref(graph[*adjacentIt]));
            }
            stream << "]}";
        }
        stream << ']';
    }

    stream << ",\"vulnerabilities\":[";
    for (std::size_t index = 0; index < findings.size(); ++index) {
        const ValidationFinding& finding = findings[index];
        if (index > 0) {
            stream << ',';
        }
        const std::string findingId =
            finding.id.empty() ? ("reqpack-" + finding.kind + "-" + std::to_string(index + 1)) : finding.id;
        stream << '{';
        stream << "\"id\":" << quote_json_string(findingId);
        stream << ",\"source\":" << quote_json_string(finding.source.empty() ? "reqpack" : finding.source);
        stream << ",\"severity\":" << quote_json_string(finding.severity.empty() ? "unassigned" : finding.severity);
        stream << ",\"score\":" << finding.score;
        stream << ",\"description\":" << quote_json_string(message_for(finding));
        stream << ",\"analysis_detail\":" << quote_json_string(vex_analysis_detail_for(finding));
        stream << ",\"affects_ref\":" << quote_json_string(component_ref(finding.package));
        stream << '}';
    }
    stream << "]}";
    return invoke_rust_emit(stream.str());
}

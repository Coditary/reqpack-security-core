#include "validator_internal.h"

#include <boost/graph/graph_traits.hpp>

#include <algorithm>
#include <cctype>
#include <string>

namespace {

bool graph_contains_only_remove_actions(const Graph& graph) {
    auto [vertex, vertexEnd] = boost::vertices(graph);
    if (vertex == vertexEnd) {
        return false;
    }

    for (; vertex != vertexEnd; ++vertex) {
        if (graph[*vertex].action != ActionType::REMOVE) {
            return false;
        }
    }

    return true;
}

}  // namespace

namespace validator_internal {

std::vector<ValidationFinding> disposition_findings(const Graph& graph, const std::vector<ValidationFinding>& findings) {
    std::vector<ValidationFinding> filtered;
    filtered.reserve(findings.size());
    const bool removeOnlyGraph = graph_contains_only_remove_actions(graph);
    for (const ValidationFinding& finding : findings) {
        if (finding.kind == "vulnerability" && (removeOnlyGraph || finding.package.action == ActionType::REMOVE)) {
            continue;
        }
        filtered.push_back(finding);
    }
    return filtered;
}

}  // namespace validator_internal

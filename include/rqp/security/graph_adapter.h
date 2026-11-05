#pragma once

#include "rqp/security/security_types.h"

#include <boost/graph/graph_traits.hpp>

#include <vector>

inline std::vector<Package> packages_from_graph(const Graph& graph) {
    std::vector<Package> packages;
    auto [vertex, vertexEnd] = boost::vertices(graph);
    for (; vertex != vertexEnd; ++vertex) {
        packages.push_back(graph[*vertex]);
    }
    return packages;
}

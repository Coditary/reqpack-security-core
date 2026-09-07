#pragma once

#include <boost/graph/adjacency_list.hpp>
#include <string>
#include <vector>

enum class ActionType {
    UNKNOWN,
    INSTALL,
    REMOVE,
    UPDATE,
    SEARCH,
    LIST,
    INFO,
    ENSURE,
    SBOM,
    AUDIT,
    OUTDATED,
    HOST,
    SNAPSHOT,
    PACK,
    SERVE,
    REMOTE
};

struct Package {
    ActionType action{ActionType::UNKNOWN};
    std::string system;
    std::string name;
    std::string version;
    std::string sourcePath;
    bool localTarget{false};
    std::vector<std::string> flags;
    bool directRequest{false};
};

typedef boost::adjacency_list<boost::vecS, boost::vecS, boost::directedS, Package> Graph;

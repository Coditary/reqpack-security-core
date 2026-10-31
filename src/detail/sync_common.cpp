#include "detail/sync_common.h"

#include <boost/property_tree/json_parser.hpp>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <sstream>

namespace rqp_security_detail {

std::string trim_copy(const std::string& value) {
    const std::size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const std::size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string to_lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool starts_with(const std::string& value, const std::string& prefix) {
    return value.rfind(prefix, 0) == 0;
}

std::string json_escape(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (unsigned char c : value) {
        switch (c) {
        case '\\':
            escaped += "\\\\";
            break;
        case '"':
            escaped += "\\\"";
            break;
        case '\b':
            escaped += "\\b";
            break;
        case '\f':
            escaped += "\\f";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            if (c < 0x20) {
                char buffer[8];
                std::snprintf(buffer, sizeof(buffer), "\\u%04x", static_cast<unsigned>(c));
                escaped += buffer;
            } else {
                escaped.push_back(static_cast<char>(c));
            }
            break;
        }
    }
    return escaped;
}

std::string now_epoch_seconds() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::to_string(std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

std::string join_scope_key(const std::set<std::string>& ecosystems) {
    std::ostringstream stream;
    bool first = true;
    for (const std::string& ecosystem : ecosystems) {
        if (!first) {
            stream << '\n';
        }
        first = false;
        stream << ecosystem;
    }
    return stream.str();
}

bool parse_json_tree(const std::string& json, boost::property_tree::ptree& tree) {
    try {
        std::istringstream input(json);
        boost::property_tree::read_json(input, tree);
        return true;
    } catch (...) {
        return false;
    }
}

int severity_rank(const std::string& severity) {
    if (severity == "critical") {
        return 4;
    }
    if (severity == "high") {
        return 3;
    }
    if (severity == "medium") {
        return 2;
    }
    if (severity == "low") {
        return 1;
    }
    return 0;
}

std::string severity_from_score(const double score) {
    if (score >= 9.0) {
        return "critical";
    }
    if (score >= 7.0) {
        return "high";
    }
    if (score >= 4.0) {
        return "medium";
    }
    if (score > 0.0) {
        return "low";
    }
    return "unassigned";
}

} // namespace rqp_security_detail

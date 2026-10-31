#pragma once

#include "rqp/security/osv_core.h"
#include "rqp/security/security_settings.h"
#include "rqp/security/security_types.h"

#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

inline std::size_t stress_env_size(const char* name, std::size_t defaultValue) {
    if (const char* raw = std::getenv(name)) {
        try {
            const long parsed = std::stol(raw);
            if (parsed > 0) {
                return static_cast<std::size_t>(parsed);
            }
        } catch (...) {
        }
    }
    return defaultValue;
}

struct StressStopwatch {
    std::chrono::steady_clock::time_point start{std::chrono::steady_clock::now()};

    double elapsed_ms() const {
        const auto end = std::chrono::steady_clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    }

    void reset() {
        start = std::chrono::steady_clock::now();
    }
};

inline void stress_log_line(const std::string& scenario, double elapsedMs, std::size_t operations,
                            const std::string& detail = {}) {
    const double perSec = elapsedMs > 0.0 ? (static_cast<double>(operations) * 1000.0 / elapsedMs) : 0.0;
    std::ostringstream stream;
    stream << "[stress] " << std::left << std::setw(28) << scenario << "  " << std::fixed << std::setprecision(2)
           << elapsedMs << " ms  " << operations << " ops  " << std::setprecision(1) << perSec << " ops/s";
    if (!detail.empty()) {
        stream << "  (" << detail << ')';
    }
    std::cerr << stream.str() << '\n';
}

inline std::string stress_package_name(std::size_t index) {
    return "stress-pkg-" + std::to_string(index);
}

inline std::string stress_advisory_id(std::size_t index) {
    return "CVE-STRESS-" + std::to_string(index);
}

inline constexpr const char* stress_osv_ecosystem() {
    return "Debian";
}

inline constexpr const char* stress_package_system() {
    return "dnf";
}

inline std::string stress_advisory_json(std::size_t index) {
    const std::string packageName = stress_package_name(index);
    const std::string id = stress_advisory_id(index);
    std::ostringstream json;
    json << R"({"id":")" << id << R"(","modified":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":")"
         << stress_osv_ecosystem() << R"(","name":")" << packageName
         << R"("},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"99.0.0"}]}]}]})";
    return json.str();
}

inline OsvAdvisory stress_advisory(std::size_t index) {
    OsvAdvisory advisory;
    advisory.id = stress_advisory_id(index);
    advisory.modified = "2026-01-01T00:00:00Z";
    advisory.rawJson = stress_advisory_json(index);
    advisory.affected.push_back(OsvAffectedPackage{
        .ecosystem = stress_osv_ecosystem(),
        .name = stress_package_name(index),
        .events = {OsvRangeEvent{.introduced = "0", .fixed = "99.0.0"}},
    });
    return advisory;
}

inline Graph stress_package_graph(std::size_t packageCount, const std::string& version = "3.0.0") {
    Graph graph;
    for (std::size_t index = 0; index < packageCount; ++index) {
        boost::add_vertex(
            Package{
                .action = ActionType::INSTALL,
                .system = stress_package_system(),
                .name = stress_package_name(index),
                .version = version,
            },
            graph);
    }
    return graph;
}

inline void stress_apply_ecosystem_map(SecuritySettings& config) {
    config.security.osvEcosystemMap[stress_package_system()] = stress_osv_ecosystem();
}

inline std::string stress_reqpack_sbom_json(std::size_t packageCount) {
    std::ostringstream payload;
    payload << R"({"packages":[)";
    for (std::size_t index = 0; index < packageCount; ++index) {
        if (index > 0) {
            payload << ',';
        }
        payload << R"({"system":"npm","name":")" << stress_package_name(index) << R"(","version":"1.0.0"})";
    }
    payload << "]}";
    return payload.str();
}

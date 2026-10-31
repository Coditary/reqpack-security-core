#include "sync/snyk/snyk_sync_internal.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <thread>
#include <utility>

namespace snyk_sync_internal {

double parse_score(const std::string& value) {
    const std::string trimmed = trim_copy(value);
    if (trimmed.empty()) {
        return 0.0;
    }
    try {
        return std::stod(trimmed);
    } catch (...) {
        return 0.0;
    }
}

std::string severity_from_row(const std::string& value, const double score) {
    const std::string normalized = to_lower_copy(trim_copy(value));
    if (normalized == "critical" || normalized == "high" || normalized == "medium" || normalized == "low") {
        return normalized;
    }
    if (normalized == "moderate") {
        return "medium";
    }
    return rqp_security_detail::severity_from_score(score);
}

bool is_maven_purl(const std::string& value) {
    return value.rfind("pkg:maven/", 0) == 0;
}

std::optional<ParsedSnykPackageLocal> parse_maven_package_name_and_version(const std::string& value) {
    const std::string trimmed = trim_copy(value);
    if (!is_maven_purl(trimmed)) {
        return std::nullopt;
    }

    const std::size_t at = trimmed.rfind('@');
    if (at == std::string::npos || at <= std::string{"pkg:maven/"}.size() || at == trimmed.size() - 1) {
        return std::nullopt;
    }

    const std::string packagePath =
        trimmed.substr(std::string{"pkg:maven/"}.size(), at - std::string{"pkg:maven/"}.size());
    const std::size_t slash = packagePath.rfind('/');
    if (slash == std::string::npos || slash == 0 || slash == packagePath.size() - 1) {
        return std::nullopt;
    }

    return ParsedSnykPackageLocal{
        .name = packagePath.substr(0, slash) + ":" + packagePath.substr(slash + 1),
        .version = trimmed.substr(at + 1),
    };
}

std::vector<std::string> parse_csv_line_impl(std::string_view line) {
    std::vector<std::string> fields;
    std::string current;
    bool quoted = false;

    for (std::size_t index = 0; index < line.size(); ++index) {
        const char ch = line[index];
        if (quoted) {
            if (ch == '"') {
                if (index + 1 < line.size() && line[index + 1] == '"') {
                    current.push_back('"');
                    ++index;
                } else {
                    quoted = false;
                }
            } else {
                current.push_back(ch);
            }
            continue;
        }

        if (ch == '"') {
            quoted = true;
            continue;
        }
        if (ch == ',') {
            fields.push_back(current);
            current.clear();
            continue;
        }
        current.push_back(ch);
    }

    fields.push_back(current);
    return fields;
}

std::optional<SnykExportRow> parse_export_row_impl(const std::vector<std::string>& header,
                                                   const std::vector<std::string>& values) {
    if (header.size() != values.size()) {
        return std::nullopt;
    }

    std::map<std::string, std::string> row;
    for (std::size_t index = 0; index < header.size(); ++index) {
        row[header[index]] = values[index];
    }

    SnykExportRow parsed;
    parsed.problemId = trim_copy(row["PROBLEM_ID"]);
    parsed.problemTitle = trim_copy(row["PROBLEM_TITLE"]);
    parsed.cve = trim_copy(row["CVE"]);
    parsed.packageNameAndVersion = trim_copy(row["PACKAGE_NAME_AND_VERSION"]);
    parsed.semverVulnerableRange = trim_copy(row["SEMVER_VULNERABLE_RANGE"]);
    parsed.issueSeverity = trim_copy(row["ISSUE_SEVERITY"]);
    parsed.nvdScore = parse_score(row["NVD_SCORE"]);
    parsed.snykCvssScore = parse_score(row["SNYK_CVSS_SCORE"]);
    parsed.updatedAt = trim_copy(row["UPDATED_AT"]);
    parsed.fixedInVersion = trim_copy(row["FIXED_IN_VERSION"]);
    parsed.productName = trim_copy(row["PRODUCT_NAME"]);

    if (parsed.problemId.empty() || parsed.packageNameAndVersion.empty()) {
        return std::nullopt;
    }
    return parsed;
}


} // namespace snyk_sync_internal

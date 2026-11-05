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

bool row_matches_ecosystem(const SnykExportRow& row, const std::string& ecosystem) {
    return ecosystem == "Maven" && is_maven_purl(row.packageNameAndVersion);
}

std::optional<VulnerabilityDatabase::IndexedAdvisory> build_indexed_advisory(const SnykGroupedAdvisory& grouped,
                                                                             const std::string& ecosystem) {
    std::ostringstream raw;
    raw << '{';
    raw << "\"id\":\"" << json_escape(grouped.id) << "\",";
    raw << "\"modified\":\"" << json_escape(grouped.updatedAt) << "\",";
    raw << "\"summary\":\"" << json_escape(grouped.title.empty() ? grouped.id : grouped.title) << "\",";
    raw << "\"details\":\""
        << json_escape(grouped.fixedInVersion.empty()
                           ? std::string{"Imported from Snyk issues export"}
                           : "Imported from Snyk issues export. Fixed in: " + grouped.fixedInVersion)
        << "\",";
    if (!grouped.cve.empty()) {
        raw << "\"aliases\":[\"" << json_escape(grouped.cve) << "\"],";
    }
    raw << "\"severity\":[{\"type\":\"CVSS_V3\",\"score\":\"" << grouped.score << "\"}],";
    raw << "\"database_specific\":{\"severity\":\"" << json_escape(grouped.severity) << "\"},";
    raw << "\"affected\":[";

    bool firstPackage = true;
    for (const auto& [packageName, versions] : grouped.versionsByPackage) {
        if (!firstPackage) {
            raw << ',';
        }
        firstPackage = false;
        raw << '{';
        raw << "\"package\":{\"ecosystem\":\"" << json_escape(ecosystem) << "\",\"name\":\"" << json_escape(packageName)
            << "\"},";
        raw << "\"database_specific\":{\"severity\":\"" << json_escape(grouped.severity) << "\"},";
        raw << "\"versions\":[";
        bool firstVersion = true;
        for (const std::string& version : versions) {
            if (!firstVersion) {
                raw << ',';
            }
            firstVersion = false;
            raw << "\"" << json_escape(version) << "\"";
        }
        raw << ']';
        raw << '}';
    }
    raw << "]}";

    const auto parsed = osv_parse_advisory(raw.str());
    if (!parsed.has_value()) {
        return std::nullopt;
    }

    std::vector<std::pair<std::string, std::string>> packageKeys;
    for (const OsvAffectedPackage& package : parsed->affected) {
        packageKeys.emplace_back(package.ecosystem, osv_normalize_package_name(package.name));
    }

    return VulnerabilityDatabase::IndexedAdvisory{
        .advisory = parsed.value(),
        .packageKeys = packageKeys,
    };
}

std::vector<ValidationFinding> import_rows(VulnerabilityDatabase* database, const std::set<std::string>& ecosystems,
                                           const std::vector<SnykExportRow>& rows) {
    std::vector<ValidationFinding> findings;
    if (database == nullptr || ecosystems.empty()) {
        return findings;
    }
    std::map<std::string, SnykGroupedAdvisory> grouped;

    for (const SnykExportRow& row : rows) {
        for (const std::string& ecosystem : ecosystems) {
            if (!row_matches_ecosystem(row, ecosystem)) {
                continue;
            }
            const auto parsed = parse_maven_package_name_and_version(row.packageNameAndVersion);
            if (!parsed.has_value()) {
                findings.push_back(ValidationFinding{
                    .kind = "sync_warning",
                    .source = "snyk",
                    .severity = "low",
                    .message = "skipping Snyk row with unsupported package format",
                });
                continue;
            }

            SnykGroupedAdvisory& advisory = grouped[row.problemId];
            advisory.id = row.problemId;
            advisory.title = row.problemTitle;
            advisory.cve = row.cve;
            advisory.updatedAt = std::max(advisory.updatedAt, row.updatedAt);
            advisory.fixedInVersion = advisory.fixedInVersion.empty() ? row.fixedInVersion : advisory.fixedInVersion;
            advisory.semverVulnerableRange =
                advisory.semverVulnerableRange.empty() ? row.semverVulnerableRange : advisory.semverVulnerableRange;
            advisory.productName = advisory.productName.empty() ? row.productName : advisory.productName;
            const double score = row.snykCvssScore > 0.0 ? row.snykCvssScore : row.nvdScore;
            if (score > advisory.score) {
                advisory.score = score;
            }
            const std::string severity = severity_from_row(row.issueSeverity, score);
            if (severity_rank(severity) > severity_rank(advisory.severity)) {
                advisory.severity = severity;
            }
            advisory.versionsByPackage[parsed->name].insert(parsed->version);
        }
    }

    std::vector<VulnerabilityDatabase::IndexedAdvisory> advisories;
    advisories.reserve(grouped.size());
    std::string latestUpdated;
    for (const auto& [_, groupedAdvisory] : grouped) {
        if (!groupedAdvisory.updatedAt.empty() && groupedAdvisory.updatedAt > latestUpdated) {
            latestUpdated = groupedAdvisory.updatedAt;
        }
        const auto advisory = build_indexed_advisory(groupedAdvisory, *ecosystems.begin());
        if (advisory.has_value()) {
            advisories.push_back(advisory.value());
        }
    }

    if (advisories.empty()) {
        if (!database->clearAll()) {
            return {ValidationFinding{
                .kind = "sync_error",
                .source = "snyk",
                .severity = "high",
                .message = "failed to reset local Snyk database",
            }};
        }
        (void)database->setSyncState(SNYK_SYNC_KEY_SCOPE, join_scope_key(ecosystems));
        (void)database->setSyncState(SNYK_SYNC_KEY_LAST_SUCCESS, now_epoch_seconds());
        (void)database->setSyncState(vulnerability_database_backend_sync_key(), "snyk");
        return findings;
    }

    if (!database->clearAll()) {
        return {ValidationFinding{
            .kind = "sync_error",
            .source = "snyk",
            .severity = "high",
            .message = "failed to reset local Snyk database",
        }};
    }
    if (!database->upsertIndexedAdvisories(advisories, SNYK_IMPORT_BATCH_SIZE)) {
        return {ValidationFinding{
            .kind = "sync_error",
            .source = "snyk",
            .severity = "high",
            .message = "failed to import Snyk advisory batch",
        }};
    }

    if (!latestUpdated.empty()) {
        (void)database->setSyncState(SNYK_SYNC_KEY_LAST_UPDATED, latestUpdated);
    }
    (void)database->setSyncState(SNYK_SYNC_KEY_SCOPE, join_scope_key(ecosystems));
    (void)database->setSyncState(SNYK_SYNC_KEY_LAST_SUCCESS, now_epoch_seconds());
    (void)database->setSyncState(vulnerability_database_backend_sync_key(), "snyk");
    return findings;
}

bool scope_matches(const VulnerabilityDatabase* database, const std::set<std::string>& ecosystems) {
    return rqp_security_detail::sync_scope_matches(database, ecosystems, SNYK_SYNC_KEY_SCOPE);
}

bool should_refresh(const VulnerabilityDatabase* database, const SecurityBackendConfig& backend, bool forceRefresh) {
    return rqp_security_detail::sync_should_refresh(database, backend, forceRefresh, SNYK_SYNC_KEY_LAST_SUCCESS);
}

} // namespace snyk_sync_internal

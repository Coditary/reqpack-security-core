#include "sync/trivy/trivy_sync_internal.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <regex>
#include <sstream>
#include <system_error>
#include <utility>

namespace trivy_sync_internal {

bool append_unique_range(std::vector<TrivyHelperRange>& ranges, const TrivyHelperRange& candidate) {
    const auto duplicate = std::find_if(ranges.begin(), ranges.end(), [&](const TrivyHelperRange& existing) {
        return existing.introduced == candidate.introduced && existing.fixed == candidate.fixed &&
               existing.lastAffected == candidate.lastAffected && existing.limit == candidate.limit;
    });
    if (duplicate != ranges.end()) {
        return false;
    }
    ranges.push_back(candidate);
    return true;
}

std::optional<VulnerabilityDatabase::IndexedAdvisory> build_indexed_advisory(const TrivyGroupedAdvisory& grouped,
                                                                             const std::string& ecosystem) {
    std::ostringstream raw;
    raw << '{';
    raw << "\"id\":\"" << json_escape(grouped.id) << "\",";
    if (!grouped.modified.empty()) {
        raw << "\"modified\":\"" << json_escape(grouped.modified) << "\",";
    }
    if (!grouped.published.empty()) {
        raw << "\"published\":\"" << json_escape(grouped.published) << "\",";
    }
    raw << "\"summary\":\"" << json_escape(grouped.summary.empty() ? grouped.id : grouped.summary) << "\",";
    raw << "\"details\":\""
        << json_escape(grouped.description.empty() ? std::string{"Imported from Trivy vulnerability database"}
                                                   : grouped.description)
        << "\",";
    if (!grouped.aliases.empty()) {
        raw << "\"aliases\":[";
        bool firstAlias = true;
        for (const std::string& alias : grouped.aliases) {
            if (!firstAlias) {
                raw << ',';
            }
            firstAlias = false;
            raw << "\"" << json_escape(alias) << "\"";
        }
        raw << "],";
    }
    if (!grouped.references.empty()) {
        raw << "\"references\":[";
        bool firstReference = true;
        for (const std::string& reference : grouped.references) {
            if (!firstReference) {
                raw << ',';
            }
            firstReference = false;
            raw << "{\"type\":\"WEB\",\"url\":\"" << json_escape(reference) << "\"}";
        }
        raw << "],";
    }
    if (grouped.score > 0.0) {
        raw << "\"severity\":[{\"type\":\"CVSS_V3\",\"score\":\"" << grouped.score << "\"}],";
    }
    raw << "\"database_specific\":{\"severity\":\"" << json_escape(grouped.severity) << "\"},";
    raw << "\"affected\":[";

    bool firstPackage = true;
    for (const auto& [packageName, package] : grouped.packages) {
        if (!firstPackage) {
            raw << ',';
        }
        firstPackage = false;
        raw << '{';
        raw << "\"package\":{\"ecosystem\":\"" << json_escape(ecosystem) << "\",\"name\":\"" << json_escape(packageName)
            << "\"},";
        raw << "\"database_specific\":{\"severity\":\"" << json_escape(grouped.severity) << "\"}";
        if (grouped.score > 0.0) {
            raw << ",\"severity\":[{\"type\":\"CVSS_V3\",\"score\":\"" << grouped.score << "\"}]";
        }
        if (!package.versions.empty()) {
            raw << ",\"versions\":[";
            bool firstVersion = true;
            for (const std::string& version : package.versions) {
                if (!firstVersion) {
                    raw << ',';
                }
                firstVersion = false;
                raw << "\"" << json_escape(version) << "\"";
            }
            raw << ']';
        }
        if (!package.ranges.empty()) {
            raw << ",\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":[";
            bool firstEvent = true;
            for (const TrivyHelperRange& range : package.ranges) {
                if (!firstEvent) {
                    raw << ',';
                }
                firstEvent = false;
                raw << '{';
                bool hasField = false;
                if (!range.introduced.empty()) {
                    raw << "\"introduced\":\"" << json_escape(range.introduced) << "\"";
                    hasField = true;
                }
                if (!range.fixed.empty()) {
                    if (hasField)
                        raw << ',';
                    raw << "\"fixed\":\"" << json_escape(range.fixed) << "\"";
                    hasField = true;
                }
                if (!range.lastAffected.empty()) {
                    if (hasField)
                        raw << ',';
                    raw << "\"last_affected\":\"" << json_escape(range.lastAffected) << "\"";
                    hasField = true;
                }
                if (!range.limit.empty()) {
                    if (hasField)
                        raw << ',';
                    raw << "\"limit\":\"" << json_escape(range.limit) << "\"";
                }
                raw << '}';
            }
            raw << "]}]";
        }
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

std::optional<std::vector<TrivyHelperRecord>> load_helper_records(const std::string& output) {
    std::vector<TrivyHelperRecord> records;
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        if (trim_copy(line).empty()) {
            continue;
        }
        const auto record = trivy_parse_helper_record(line);
        if (!record.has_value()) {
            return std::nullopt;
        }
        records.push_back(record.value());
    }
    return records;
}

std::vector<ValidationFinding> import_records(VulnerabilityDatabase* database, const std::set<std::string>& ecosystems,
                                              const std::vector<TrivyHelperRecord>& records,
                                              const std::string& sourceRepository, const TrivyDbMetadata& metadata) {
    if (database == nullptr || ecosystems.empty()) {
        return {};
    }

    std::vector<ValidationFinding> findings;
    std::map<std::string, TrivyGroupedAdvisory> grouped;

    for (const TrivyHelperRecord& record : records) {
        if (!ecosystems.contains(record.ecosystem)) {
            continue;
        }
        TrivyGroupedAdvisory& advisory = grouped[record.ecosystem + "\n" + record.advisoryId];
        advisory.ecosystem = record.ecosystem;
        advisory.id = record.advisoryId;
        advisory.summary = advisory.summary.empty() ? record.summary : advisory.summary;
        advisory.description = advisory.description.empty() ? record.description : advisory.description;
        advisory.modified = std::max(advisory.modified, record.modified);
        advisory.published = std::max(advisory.published, record.published);
        if (record.score > advisory.score) {
            advisory.score = record.score;
        }
        if (severity_rank(record.severity) > severity_rank(advisory.severity)) {
            advisory.severity = record.severity;
        }
        advisory.aliases.insert(record.aliases.begin(), record.aliases.end());
        advisory.references.insert(record.references.begin(), record.references.end());

        TrivyGroupedPackage& package = advisory.packages[record.packageName];
        package.versions.insert(record.versions.begin(), record.versions.end());
        for (const TrivyHelperRange& range : record.ranges) {
            (void)append_unique_range(package.ranges, range);
        }
    }

    std::vector<VulnerabilityDatabase::IndexedAdvisory> advisories;
    advisories.reserve(grouped.size());
    for (const auto& [_, groupedAdvisory] : grouped) {
        const auto advisory = build_indexed_advisory(groupedAdvisory, groupedAdvisory.ecosystem);
        if (!advisory.has_value()) {
            findings.push_back(ValidationFinding{
                .kind = "sync_warning",
                .source = "trivy",
                .severity = "low",
                .message = "skipping Trivy advisory that could not be normalized",
            });
            continue;
        }
        advisories.push_back(advisory.value());
    }

    if (!database->clearAll()) {
        return {ValidationFinding{
            .kind = "sync_error",
            .source = "trivy",
            .severity = "high",
            .message = "failed to reset local Trivy database",
        }};
    }
    if (!advisories.empty() && !database->upsertIndexedAdvisories(advisories, TRIVY_IMPORT_BATCH_SIZE)) {
        return {ValidationFinding{
            .kind = "sync_error",
            .source = "trivy",
            .severity = "high",
            .message = "failed to import Trivy advisory batch",
        }};
    }

    (void)database->setSyncState(TRIVY_SYNC_KEY_SCOPE, join_scope_key(ecosystems));
    (void)database->setSyncState(TRIVY_SYNC_KEY_LAST_SUCCESS, now_epoch_seconds());
    (void)database->setSyncState(vulnerability_database_backend_sync_key(), "trivy");
    if (!sourceRepository.empty()) {
        (void)database->setSyncState(TRIVY_SYNC_KEY_SOURCE_REPOSITORY, sourceRepository);
    }
    if (!metadata.version.empty()) {
        (void)database->setSyncState(TRIVY_SYNC_KEY_METADATA_VERSION, metadata.version);
    }
    return findings;
}


} // namespace trivy_sync_internal

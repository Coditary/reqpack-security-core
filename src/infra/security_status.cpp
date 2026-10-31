#include "rqp/security/security_status.h"

#include "rqp/security/security_paths.h"
#include "rqp/security/vulnerability_database.h"

#include <filesystem>
#include <sstream>

namespace {

void append_line(SecurityStatusReport& report, const std::string& line) {
    report.lines.push_back(line);
}

std::string mapping_hint_for_system(const std::string& system) {
    return "security.osvEcosystemMap[\"" + system + "\"] = \"<OSV ecosystem>\"  (or plugin osvEcosystem metadata)";
}

}  // namespace

SecurityStatusReport build_security_status(const SecuritySettings& settings, PluginMetadataProvider* metadataProvider) {
    SecurityStatusReport report;

    append_line(report, "security enabled: " + std::string(settings.security.enabled ? "yes" : "no"));
    if (!settings.security.preset.empty()) {
        append_line(report, "security preset: " + settings.security.preset);
    }
    append_line(report, "onUnsafe: " + to_string(settings.security.onUnsafe));
    append_line(report, "strictEcosystemMapping: " + std::string(settings.security.strictEcosystemMapping ? "yes" : "no"));
    append_line(report, "auditFailOnFindings: " + std::string(settings.security.auditFailOnFindings ? "yes" : "no"));
    append_line(report, "osvDatabasePath: " + settings.security.osvDatabasePath);
    append_line(report, "osvFeedUrl: " + settings.security.osvFeedUrl);
    append_line(report, "osvRefreshMode: " + to_string(settings.security.osvRefreshMode));

    const std::filesystem::path databasePath(settings.security.osvDatabasePath);
    if (!std::filesystem::exists(databasePath)) {
        report.warnings.push_back("vulnerability database path does not exist yet");
        report.hasBlockingIssues = true;
    }

    VulnerabilityDatabase database(settings);
    if (!database.ensureReady()) {
        report.warnings.push_back("vulnerability database could not be opened");
        report.hasBlockingIssues = true;
    } else {
        append_line(report, "database ready: yes");
        append_line(report, "database has advisories: " + std::string(database.hasAdvisories() ? "yes" : "no"));
        if (!database.hasAdvisories()) {
            report.warnings.push_back("database is empty; run `rqp audit --osv-refresh always` or enable autoFetch");
            report.hasBlockingIssues = true;
        }
        append_line(report, "sync backend: " + database.resolvedSyncSource());
        if (const auto lastSync = database.getSyncState("last_successful_sync_at"); lastSync.has_value()) {
            append_line(report, "last successful sync (epoch): " + lastSync.value());
        }
    }

    if (!settings.security.osvEcosystemMap.empty()) {
        append_line(report, "configured osvEcosystemMap:");
        for (const auto& [system, ecosystem] : settings.security.osvEcosystemMap) {
            append_line(report, "  " + system + " -> " + ecosystem);
        }
    }

    if (metadataProvider != nullptr) {
        append_line(report, "plugin ecosystem metadata:");
        for (const std::string& name : metadataProvider->getKnownPluginNames()) {
            const auto metadata = metadataProvider->getPluginSecurityMetadata(name);
            if (!metadata.has_value()) {
                continue;
            }
            if (metadata->role == "security-provider") {
                append_line(report, "  " + name + " (security-provider)");
                continue;
            }
            const auto mapped = settings.security.osvEcosystemMap.find(name);
            const bool hasConfigMap = mapped != settings.security.osvEcosystemMap.end();
            if (!metadata->osvEcosystem.empty()) {
                append_line(report, "  " + name + " -> " + metadata->osvEcosystem + " (plugin metadata)");
            } else if (hasConfigMap) {
                append_line(report, "  " + name + " -> " + mapped->second + " (config map)");
            } else {
                append_line(report, "  " + name + " -> (unmapped)");
                report.warnings.push_back("no OSV mapping for plugin system '" + name + "': " + mapping_hint_for_system(name));
                if (settings.security.strictEcosystemMapping) {
                    report.hasBlockingIssues = true;
                }
            }
        }
    }

    if (!report.warnings.empty()) {
        append_line(report, "hints:");
        for (const std::string& warning : report.warnings) {
            append_line(report, "  - " + warning);
        }
    }

    return report;
}

void print_security_status_report(const SecurityStatusReport& report, std::ostream& output) {
    for (const std::string& line : report.lines) {
        output << line << '\n';
    }
}

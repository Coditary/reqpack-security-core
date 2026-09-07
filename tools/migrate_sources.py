#!/usr/bin/env python3
"""Bulk-adapt copied ReqPack security sources for reqpack-security-core."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REPLACEMENTS = [
    ('#include "core/security/', '#include "rqp/security/'),
    ('#include "core/config/configuration.h"', '#include "rqp/security/security_settings.h"'),
    ('#include "core/common/types.h"', '#include "rqp/security/security_types.h"'),
    ('#include "core/plugins/plugin_metadata_provider.h"', '#include "rqp/security/plugin_metadata_provider.h"'),
    ('#include "core/common/version_compare.h"', '#include "rqp/security/version_compare.h"'),
    ('#include "core/common/network_environment.h"', '#include "rqp/security/security_network.h"'),
    ('#include "core/common/process_runner.h"', '#include "rqp/security/security_process.h"'),
    ('#include "core/common/pipe_helpers.h"', '#include "rqp/security/pipe_helpers.h"'),
    ('#include "core/archive/archive_resolver.h"', '#include "rqp/security/security_archive.h"'),
    ('#include "output/logger.h"', '#include "rqp/security/security_log.h"'),
    ('ReqPackConfig', 'SecuritySettings'),
    ('default_reqpack_config()', 'default_security_settings()'),
    ('default_reqpack_security_index_path()', 'default_security_index_path()'),
    ('default_reqpack_osv_database_path()', 'default_osv_database_path()'),
    ('default_reqpack_security_cache_path()', 'default_security_cache_path()'),
    ('config.downloader.', 'config.network.'),
    ('this->config.downloader.', 'this->config.network.'),
    ('reqpack_apply_curl_ca_bundle', 'rqp_security_apply_curl_ca_bundle'),
    ('reqpack_sanitized_process_environment', 'rqp_security_sanitized_process_environment'),
    ('reqpack_run_process_capture', 'rqp_security_run_process_capture'),
    ('reqpack_run_process', 'rqp_security_run_process'),
    ('ReqpackProcessResult', 'RqpSecurityProcessResult'),
    ('extract_archive_to_temp_directory', 'config.archive.extractToTemp'),
    ('ArchiveResolution', 'SecurityArchiveResolution'),
    ('ecosystem_db_config(', 'ecosystem_db_settings('),
]

LOG_REPLACEMENTS = [
    (
        r'Logger::instance\(\)\.emit\(OutputAction::LOG,\s*OutputContext\{[^}]+\}\);',
        lambda m: 'security_log(SecurityLogLevel::Info, "security", "OSV sync: " + message);',
    ),
]

def adapt_file(path: Path) -> None:
    text = path.read_text()
    original = text

    for old, new in REPLACEMENTS:
        text = text.replace(old, new)

    text = re.sub(
        r'Logger::instance\(\)\.emit\(OutputAction::LOG,\s*OutputContext\{[^}]*\.message = "OSV sync: " \+ message,[^}]*\}\);',
        'security_log(SecurityLogLevel::Info, "security", "OSV sync: " + message);',
        text,
        flags=re.DOTALL,
    )

    text = text.replace('Logger& logger = Logger::instance();', '')
    text = text.replace('logger.logStdout(', 'security_log_stdout(')
    text = text.replace('logger.flushSync();', 'security_flush();')
    text = text.replace(
        'logger.diagnostic(make_error_diagnostic(\n\t\t\t"security",\n\t\t\t"interactive mode is disabled; refusing to continue.",\n\t\t\t"Security policy requires user confirmation, but interactive prompts are disabled.",\n\t\t\t"Re-run without `--non-interactive`, or switch `security.onUnsafe` to `abort` or `allow`."\n\t\t));',
        'security_log_diagnostic("security", "interactive mode is disabled; refusing to continue.", "Re-run without `--non-interactive`, or switch `security.onUnsafe` to `abort` or `allow`.");',
    )

    if path.name == 'security_gateway_service.cpp':
        text = re.sub(
            r'SecurityGatewayService::SecurityGatewayService\(\s*Registry\* registry,\s*PluginMetadataProvider\* metadataProvider,\s*const SecuritySettings& config\s*\)\s*:\s*registry\(registry\),\s*metadataProvider\(metadataProvider\),\s*config\(config\) \{\}',
            'SecurityGatewayService::SecurityGatewayService(\n    PluginMetadataProvider* metadataProvider,\n    const SecuritySettings& config\n) : metadataProvider(metadataProvider), config(config) {}',
            text,
        )

    if path.name == 'validator.cpp':
        text = text.replace(
            'securityGateway(nullptr, metadataProvider, config),',
            'securityGateway(metadataProvider, config),',
        )

    if path.name == 'validator_internal.h':
        text = text.replace('#include "core/security/validator.h"', '#include "rqp/security/validator.h"')

    if path.name == 'pipe_helpers.cpp':
        text = text.replace('#include "core/common/pipe_helpers.h"', '#include "rqp/security/pipe_helpers.h"')

    if text != original:
        path.write_text(text)

def adapt_headers() -> None:
    header_updates = {
        'validator.h': '''#pragma once

#include "rqp/security/security_settings.h"
#include "rqp/security/osv_core.h"
#include "rqp/security/plugin_metadata_provider.h"
#include "rqp/security/security_gateway_service.h"
#include "rqp/security/security_types.h"
#include "rqp/security/validator_core.h"
#include "rqp/security/vulnerability_database.h"
#include "rqp/security/vulnerability_matcher.h"
#include "rqp/security/vulnerability_sync_service.h"

#include <string>
#include <vector>

class Validator {
\tSecuritySettings config;
\tPluginMetadataProvider* metadataProvider;
\tVulnerabilityDatabase database;
\tVulnerabilitySyncService syncService;
\tSecurityGatewayService securityGateway;
\tVulnerabilityMatcher matcher;
\tstd::vector<ValidationFinding> lastFindings;

\tstd::vector<Package> collectPackages(const Graph& graph) const;
\tstd::vector<ValidationFinding> prepareSecurityData(const Graph& graph) const;
\tstd::vector<OsvAdvisory> loadAdvisories() const;

protected:
\tvirtual std::vector<ValidationFinding> scanGraph(const Graph& graph) const;
\tvirtual bool requestUserDecision(const std::vector<ValidationFinding>& findings) const;
\tvirtual void generateReport(const Graph& graph, const std::vector<ValidationFinding>& findings) const;

public:
\tValidator(PluginMetadataProvider* metadataProvider = nullptr, const SecuritySettings& config = default_security_settings());
\tvirtual ~Validator();

\tGraph* validate(Graph *graph);
\tstd::vector<ValidationFinding> audit(Graph* graph);
\tconst std::vector<ValidationFinding>& getLastFindings() const;
};
''',
        'security_gateway_service.h': '''#pragma once

#include "rqp/security/security_settings.h"
#include "rqp/security/plugin_metadata_provider.h"
#include "rqp/security/validator_core.h"

#include <set>
#include <string>
#include <vector>

class SecurityGatewayService {
    PluginMetadataProvider* metadataProvider;
    SecuritySettings config;

    std::string normalizeGatewayName(const std::string& gateway) const;
    std::set<std::string> discoverSecurityProviders() const;
    std::set<std::string> resolveGatewayBackends(const std::string& gateway) const;
    std::optional<std::string> resolveCanonicalEcosystem(const std::string& target) const;

public:
    SecurityGatewayService(
        PluginMetadataProvider* metadataProvider = nullptr,
        const SecuritySettings& config = default_security_settings()
    );

    bool isGatewaySystem(const std::string& system) const;
    std::set<std::string> configuredGatewayNames() const;
    std::set<std::string> resolvePackageEcosystems(const std::vector<Package>& packages) const;
    std::vector<ValidationFinding> ensureEcosystemsReady(
        const std::set<std::string>& ecosystems,
        const std::string& gateway = {},
        bool forceRefresh = false
    ) const;
    std::vector<ValidationFinding> executeGatewayRequest(
        ActionType action,
        const std::string& gateway,
        const std::vector<Package>& packages
    ) const;
};
''',
        'validator_core.h': '''#pragma once

#include "rqp/security/security_settings.h"
#include "rqp/security/security_types.h"

#include <string>
#include <vector>

struct ValidationFinding {
    std::string id;
    std::string kind{"vulnerability"};
    Package package;
    std::string source;
    std::string severity;
    double score{0.0};
    std::string message;
};

struct ValidationPolicy {
    bool promptOnUnsafe{false};
    std::string abortThreshold{"critical"};
    double abortScoreThreshold{0.0};
    bool generateReport{false};
    UnsafeAction unresolvedVersionAction{UnsafeAction::CONTINUE};
    bool strictEcosystemMapping{false};
};

enum class ValidationDisposition {
    Continue,
    Prompt,
    Abort,
};

ValidationPolicy validator_policy_from_config(const SecuritySettings& config);
int validator_severity_rank(const std::string& severity);
bool validator_is_blocking_finding(const ValidationFinding& finding, const ValidationPolicy& policy);
std::vector<ValidationFinding> validator_apply_rules(
    const std::vector<ValidationFinding>& findings,
    const std::vector<std::string>& allowIds,
    const std::vector<std::string>& ignoreIds
);
bool validator_findings_exceed_threshold(const std::vector<ValidationFinding>& findings, const ValidationPolicy& policy);
bool validator_should_prompt_user(const std::vector<ValidationFinding>& findings, const ValidationPolicy& policy);
ValidationDisposition validator_disposition(const std::vector<ValidationFinding>& findings, const ValidationPolicy& policy);
''',
        'vulnerability_database.h': '''#pragma once

#include "rqp/security/security_settings.h"
#include "rqp/security/osv_core.h"

#include <lmdb.h>

#include <cstddef>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

class VulnerabilityDatabase {
    SecuritySettings config;
    mutable std::mutex mutex;
    mutable MDB_env* env{nullptr};
    mutable MDB_dbi dbi{0};
    mutable bool initialized{false};

    bool initStorage() const;
    std::optional<std::string> loadString(const std::string& key) const;
    std::vector<std::pair<std::string, std::string>> loadPrefixed(const std::string& prefix) const;
    bool putString(const std::string& key, const std::string& value) const;

public:
    struct IndexedAdvisory {
        OsvAdvisory advisory;
        std::vector<std::pair<std::string, std::string>> packageKeys;
    };

    explicit VulnerabilityDatabase(const SecuritySettings& config = default_security_settings());
    ~VulnerabilityDatabase();

    bool ensureReady() const;
    bool hasAdvisories() const;
    bool clearAll() const;
    bool upsertAdvisory(const OsvAdvisory& advisory) const;
    bool upsertAdvisories(const std::vector<OsvAdvisory>& advisories, std::size_t batchSize = 256) const;
    bool upsertIndexedAdvisories(const std::vector<IndexedAdvisory>& advisories, std::size_t batchSize = 256) const;
    std::vector<OsvAdvisory> loadAllAdvisories() const;
    std::vector<OsvAdvisory> loadAdvisoriesForPackage(const std::string& ecosystem, const std::string& name) const;
    std::optional<std::string> resolveAlias(const std::string& id) const;
    std::vector<std::string> advisoryIdsForPackage(const std::string& ecosystem, const std::string& name) const;
    bool setSyncState(const std::string& key, const std::string& value) const;
    std::optional<std::string> getSyncState(const std::string& key) const;
};
''',
        'vulnerability_sync_service.h': '''#pragma once

#include "rqp/security/security_settings.h"
#include "rqp/security/plugin_metadata_provider.h"
#include "rqp/security/validator_core.h"
#include "rqp/security/vulnerability_database.h"

#include <set>
#include <string>
#include <vector>

class VulnerabilitySyncService {
    SecuritySettings config;
    VulnerabilityDatabase* database;
    PluginMetadataProvider* metadataProvider;
    std::set<std::string> explicitScope;

    bool shouldRefresh() const;
    std::set<std::string> activeEcosystemScope() const;
    std::string activeEcosystemScopeKey() const;
    bool storedScopeMatches() const;
    std::vector<ValidationFinding> fullSync() const;
    std::vector<ValidationFinding> deltaSync() const;

public:
    VulnerabilitySyncService(
        VulnerabilityDatabase* database,
        PluginMetadataProvider* metadataProvider = nullptr,
        const SecuritySettings& config = default_security_settings(),
        std::set<std::string> explicitScope = {}
    );

    std::vector<ValidationFinding> ensureReady() const;
};
''',
        'vulnerability_matcher.h': '''#pragma once

#include "rqp/security/security_settings.h"
#include "rqp/security/plugin_metadata_provider.h"
#include "rqp/security/validator_core.h"
#include "rqp/security/vulnerability_database.h"

#include <vector>

class VulnerabilityMatcher {
    SecuritySettings config;
    PluginMetadataProvider* metadataProvider;
    VulnerabilityDatabase* database;

public:
    VulnerabilityMatcher(
        PluginMetadataProvider* metadataProvider,
        const SecuritySettings& config = default_security_settings()
    );

    std::vector<ValidationFinding> matchPackages(const std::vector<Package>& packages) const;
};
''',
    }

    for name, content in header_updates.items():
        (ROOT / 'include' / 'rqp' / 'security' / name).write_text(content)

    for header in (ROOT / 'include' / 'rqp' / 'security').glob('*.h'):
        if header.name in header_updates:
            continue
        adapt_file(header)

def main() -> None:
    for directory in [ROOT / 'src', ROOT / 'tests' / 'unit']:
        for path in directory.rglob('*'):
            if path.is_file() and path.suffix in {'.cpp', '.h'}:
                adapt_file(path)
    adapt_headers()
    print('Migration complete.')

if __name__ == '__main__':
    main()

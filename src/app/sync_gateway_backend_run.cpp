#include "app/sync_gateway_backend_run.h"

#include "adapters/infra/curl_http_client.h"
#include "adapters/infra/settings_archive_extractor.h"
#include "ports/internal_ports.h"
#include "rqp/security/sync_backend_registry.h"
#include "rqp/security/vulnerability_database.h"

std::vector<ValidationFinding>
run_registered_sync_backend(const std::string& backendId, VulnerabilityDatabase* database,
                            PluginMetadataProvider* metadataProvider, const SecuritySettings& config,
                            const std::set<std::string>& ecosystems, const bool forceRefresh) {
    const ISyncBackend* backend = find_sync_backend(backendId);
    if (backend == nullptr) {
        return {ValidationFinding{
            .kind = "sync_warning",
            .source = backendId,
            .severity = "low",
            .message = "security backend is not available in this build",
        }};
    }

    CurlHttpClient httpClient(config);
    SettingsArchiveExtractor archiveExtractor(config);
    SecurityIoPorts io{httpClient, archiveExtractor};

    SecuritySettings runConfig = config;
    backend->mergeGatewayBackendConfig(runConfig, config);
    if (forceRefresh) {
        backend->applyForceRefresh(runConfig);
    }

    SyncOptions options{
        .forceRefresh = forceRefresh,
        .ecosystems = ecosystems,
        .settings = runConfig,
        .metadataProvider = metadataProvider,
    };

    if (backend->scope() == SyncBackendScope::MultiEcosystem) {
        VulnerabilityDatabase noopStore(runConfig);
        IAdvisoryWriter& store =
            database != nullptr ? static_cast<IAdvisoryWriter&>(*database) : static_cast<IAdvisoryWriter&>(noopStore);
        const rqp::security::Result<std::vector<ValidationFinding>> findings = backend->sync(store, options, io);
        if (findings) {
            return findings.value();
        }
        return {ValidationFinding{
            .kind = "sync_error",
            .source = backendId,
            .severity = "high",
            .message = findings.error().message,
        }};
    }

    if (database == nullptr) {
        return {ValidationFinding{
            .kind = "sync_error",
            .source = backendId,
            .severity = "high",
            .message = "vulnerability database required for per-ecosystem backend",
        }};
    }

    const rqp::security::Result<std::vector<ValidationFinding>> findings =
        backend->sync(static_cast<IAdvisoryWriter&>(*database), options, io);
    if (findings) {
        return findings.value();
    }
    return {ValidationFinding{
        .kind = "sync_error",
        .source = backendId,
        .severity = "high",
        .message = findings.error().message,
    }};
}

#include "adapters/matching/lmdb_ecosystem_advisory_resolver.h"

#include "rqp/security/security_paths.h"
#include "rqp/security/vulnerability_database.h"

#include <filesystem>

namespace {

std::filesystem::path ecosystem_index_path(const SecuritySettings& config, const std::string& ecosystem) {
    std::filesystem::path root = config.security.indexPath;
    const std::filesystem::path defaultIndexPath = default_security_index_path();
    const std::filesystem::path defaultOsvDatabasePath = default_osv_database_path();
    if (root == defaultIndexPath && std::filesystem::path(config.security.osvDatabasePath) != defaultOsvDatabasePath) {
        root = config.security.osvDatabasePath;
    }
    return root / ecosystem;
}

AdvisoryReaderSelection selectionFromReader(const IAdvisoryReader* reader) {
    if (reader == nullptr) {
        return {};
    }
    return AdvisoryReaderSelection{.reader = reader, .source = reader->resolvedSyncSource()};
}

} // namespace

LmdbEcosystemAdvisoryResolver::LmdbEcosystemAdvisoryResolver(SecuritySettings config,
                                                             const IAdvisoryReader* primaryReader)
    : config(std::move(config)), primaryReader(primaryReader) {}

AdvisoryReaderSelection LmdbEcosystemAdvisoryResolver::readerForEcosystem(const std::string& ecosystem) const {
    const std::filesystem::path ecosystemIndexPath = ecosystem_index_path(this->config, ecosystem);
    if (!std::filesystem::exists(ecosystemIndexPath)) {
        if (this->primaryReader != nullptr && this->primaryReader->hasAdvisories()) {
            return selectionFromReader(this->primaryReader);
        }
        return selectionFromReader(this->primaryReader);
    }

    const std::string pathKey = ecosystemIndexPath.string();
    VulnerabilityDatabase* ecosystemDatabase = nullptr;
    {
        std::lock_guard lock(this->cacheMutex);
        const auto cached = this->ecosystemDatabases.find(pathKey);
        if (cached != this->ecosystemDatabases.end()) {
            ecosystemDatabase = cached->second.get();
        } else {
            SecuritySettings ecosystemConfig = this->config;
            ecosystemConfig.security.osvDatabasePath = pathKey;
            auto inserted = this->ecosystemDatabases.emplace(
                pathKey, std::make_unique<VulnerabilityDatabase>(std::move(ecosystemConfig)));
            ecosystemDatabase = inserted.first->second.get();
        }
    }

    if (ecosystemDatabase->hasAdvisories()) {
        return selectionFromReader(ecosystemDatabase);
    }
    if (this->primaryReader != nullptr && this->primaryReader->hasAdvisories()) {
        return selectionFromReader(this->primaryReader);
    }
    return selectionFromReader(ecosystemDatabase);
}

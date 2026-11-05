#pragma once

#include "rqp/security/osv_core.h"
#include "rqp/security/ports.h"

#include <algorithm>
#include <map>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

/// Test double for IAdvisoryReader/IAdvisoryWriter without LMDB.
class InMemoryAdvisoryStore final : public IAdvisoryReader, public IAdvisoryWriter {
    mutable std::shared_mutex mutex;
    std::map<std::string, OsvAdvisory> advisoriesById;
    std::map<std::string, std::vector<std::string>> idsByPackageKey;
    std::map<std::string, std::string> aliases;
    std::map<std::string, std::string> syncState;
    std::string syncSource{"memory"};

  public:
    void setSyncSource(std::string source) {
        this->syncSource = std::move(source);
    }

    bool upsert(const OsvAdvisory& advisory) {
        std::unique_lock lock(this->mutex);
        this->advisoriesById[advisory.id] = advisory;
        for (const OsvAffectedPackage& affected : advisory.affected) {
            const std::string key = package_key(affected.ecosystem, affected.name);
            auto& ids = this->idsByPackageKey[key];
            if (std::find(ids.begin(), ids.end(), advisory.id) == ids.end()) {
                ids.push_back(advisory.id);
            }
        }
        for (const std::string& alias : advisory.aliases) {
            this->aliases[osv_to_lower_copy(alias)] = advisory.id;
        }
        return true;
    }

    bool ensureReady() const override {
        return true;
    }

    bool hasAdvisories() const override {
        std::shared_lock lock(this->mutex);
        return !this->advisoriesById.empty();
    }

    bool upsertAdvisories(const std::vector<OsvAdvisory>& advisories, std::size_t batchSize) const override {
        (void)batchSize;
        for (const OsvAdvisory& advisory : advisories) {
            const_cast<InMemoryAdvisoryStore*>(this)->upsert(advisory);
        }
        return true;
    }

    std::vector<OsvAdvisory> loadAdvisoriesForPackage(const std::string& ecosystem,
                                                      const std::string& name) const override {
        std::shared_lock lock(this->mutex);
        std::vector<OsvAdvisory> result;
        const auto it = this->idsByPackageKey.find(package_key(ecosystem, name));
        if (it == this->idsByPackageKey.end()) {
            return result;
        }
        for (const std::string& id : it->second) {
            const auto advisoryIt = this->advisoriesById.find(id);
            if (advisoryIt != this->advisoriesById.end()) {
                result.push_back(advisoryIt->second);
            }
        }
        return result;
    }

    std::vector<std::pair<std::string, std::string>> loadPackageAdvisoryRaw(const std::string& ecosystem,
                                                                            const std::string& name) const override {
        std::vector<std::pair<std::string, std::string>> rows;
        for (const OsvAdvisory& advisory : this->loadAdvisoriesForPackage(ecosystem, name)) {
            rows.emplace_back(advisory.id, advisory.rawJson.empty() ? "{}" : advisory.rawJson);
        }
        return rows;
    }

    std::optional<std::string> resolveAlias(const std::string& id) const override {
        std::shared_lock lock(this->mutex);
        const auto it = this->aliases.find(osv_to_lower_copy(id));
        if (it == this->aliases.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    bool setSyncState(const std::string& key, const std::string& value) const override {
        std::unique_lock lock(this->mutex);
        const_cast<InMemoryAdvisoryStore*>(this)->syncState[key] = value;
        return true;
    }

    std::optional<std::string> getSyncState(const std::string& key) const override {
        std::shared_lock lock(this->mutex);
        const auto it = this->syncState.find(key);
        if (it == this->syncState.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    std::string resolvedSyncSource() const override {
        return this->syncSource;
    }

  private:
    static std::string package_key(const std::string& ecosystem, const std::string& name) {
        return osv_to_lower_copy(ecosystem) + '\0' + osv_to_lower_copy(name);
    }
};

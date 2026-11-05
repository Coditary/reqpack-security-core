#pragma once

#include "rqp/security/osv_core.h"
#include "rqp/security/validator_core.h"

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

enum class PolicyDecision {
    Allow,
    Deny,
};

/// Host-controlled response when policy requires user confirmation (no stdin in core by default).
class IPolicyDecisionHandler {
  public:
    virtual ~IPolicyDecisionHandler() = default;
    virtual PolicyDecision onPolicyViolation(std::span<const ValidationFinding> findings) const = 0;
};

class IAdvisoryReader {
  public:
    virtual ~IAdvisoryReader() = default;

    [[nodiscard]] virtual bool hasAdvisories() const = 0;
    [[nodiscard]] virtual std::vector<OsvAdvisory> loadAdvisoriesForPackage(const std::string& ecosystem,
                                                                            const std::string& name) const = 0;
    [[nodiscard]] virtual std::vector<std::pair<std::string, std::string>>
    loadPackageAdvisoryRaw(const std::string& ecosystem, const std::string& name) const = 0;
    [[nodiscard]] virtual std::optional<std::string> resolveAlias(const std::string& id) const = 0;
    [[nodiscard]] virtual std::string resolvedSyncSource() const = 0;
};

class IAdvisoryWriter {
  public:
    virtual ~IAdvisoryWriter() = default;

    [[nodiscard]] virtual bool ensureReady() const = 0;
    [[nodiscard]] virtual bool upsertAdvisories(const std::vector<OsvAdvisory>& advisories,
                                                std::size_t batchSize = 256) const = 0;
    [[nodiscard]] virtual bool setSyncState(const std::string& key, const std::string& value) const = 0;
    [[nodiscard]] virtual std::optional<std::string> getSyncState(const std::string& key) const = 0;
};

struct AdvisoryReaderSelection {
    const IAdvisoryReader* reader{nullptr};
    std::string source{"osv"};
};

/// Resolves per-ecosystem advisory stores (LMDB index paths live in adapter implementations).
class IEcosystemAdvisoryResolver {
  public:
    virtual ~IEcosystemAdvisoryResolver() = default;
    [[nodiscard]] virtual AdvisoryReaderSelection readerForEcosystem(const std::string& ecosystem) const = 0;
};

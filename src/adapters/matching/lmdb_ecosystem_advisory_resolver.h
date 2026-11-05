#pragma once

#include "rqp/security/ports.h"
#include "rqp/security/security_settings.h"
#include "rqp/security/vulnerability_database.h"

class LmdbEcosystemAdvisoryResolver final : public IEcosystemAdvisoryResolver {
    SecuritySettings config;
    const IAdvisoryReader* primaryReader{nullptr};

    mutable std::mutex cacheMutex;
    mutable std::map<std::string, std::unique_ptr<VulnerabilityDatabase>> ecosystemDatabases;

  public:
    LmdbEcosystemAdvisoryResolver(SecuritySettings config, const IAdvisoryReader* primaryReader = nullptr);

    [[nodiscard]] AdvisoryReaderSelection readerForEcosystem(const std::string& ecosystem) const override;
};

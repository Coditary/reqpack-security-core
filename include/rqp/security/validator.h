#pragma once

#include "rqp/security/osv_core.h"
#include "rqp/security/plugin_metadata_provider.h"
#include "rqp/security/security_gateway_service.h"
#include "rqp/security/security_settings.h"
#include "rqp/security/security_types.h"
#include "rqp/security/validator_core.h"
#include "rqp/security/vulnerability_database.h"
#include "rqp/security/vulnerability_matcher.h"
#include "rqp/security/vulnerability_sync_service.h"

#include <string>
#include <vector>

class Validator {
    SecuritySettings config;
    PluginMetadataProvider* metadataProvider;
    VulnerabilityDatabase database;
    VulnerabilitySyncService syncService;
    SecurityGatewayService securityGateway;
    VulnerabilityMatcher matcher;
    std::vector<ValidationFinding> lastFindings;

    std::vector<Package> collectPackages(const Graph& graph) const;
    std::vector<OsvAdvisory> loadAdvisories() const;

  protected:
    virtual std::vector<ValidationFinding> prepareSecurityData(const Graph& graph) const;
    virtual std::vector<ValidationFinding> scanGraph(const Graph& graph) const;
    virtual bool requestUserDecision(const std::vector<ValidationFinding>& findings) const;
    virtual void generateReport(const Graph& graph, const std::vector<ValidationFinding>& findings) const;

  public:
    Validator(PluginMetadataProvider* metadataProvider = nullptr,
              const SecuritySettings& config = default_security_settings());
    virtual ~Validator();

    Graph* validate(Graph* graph);
    std::vector<ValidationFinding> audit(Graph* graph);
    const std::vector<ValidationFinding>& getLastFindings() const;
};

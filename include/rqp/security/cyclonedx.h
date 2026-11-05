#pragma once

#include "rqp/security/plugin_metadata_provider.h"
#include "rqp/security/security_types.h"
#include "rqp/security/validator_core.h"

#include <string>
#include <vector>

std::string rqp_emit_cyclonedx_inventory_json(const Graph& graph, PluginMetadataProvider* metadataProvider,
                                              bool includeDependencyEdges);

std::string rqp_emit_cyclonedx_audit_vex_json(const Graph& graph, const std::vector<ValidationFinding>& findings,
                                              PluginMetadataProvider* metadataProvider, bool includeDependencyEdges);

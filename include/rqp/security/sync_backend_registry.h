#pragma once

#include "rqp/security/security_config.h"
#include "rqp/security/security_settings.h"
#include "rqp/security/validator_core.h"

#include <functional>
#include <set>
#include <string>
#include <vector>

class PluginMetadataProvider;
class VulnerabilityDatabase;

/// Built-in backend identifiers (config / gateway `backends` list).
namespace rqp::sync_backend {

inline constexpr const char* kOsv = "osv";
inline constexpr const char* kGhAdvisory = "gh-advisory";
inline constexpr const char* kSnyk = "snyk";
inline constexpr const char* kTrivy = "trivy";

} // namespace rqp::sync_backend

enum class SyncBackendScope {
    /// One VulnerabilityDatabase + sync run per ecosystem (osv, snyk, trivy).
    PerEcosystem,
    /// Single run for all ecosystems (gh-advisory).
    MultiEcosystem,
};

struct SyncBackendContext {
    VulnerabilityDatabase* database{nullptr};
    PluginMetadataProvider* metadataProvider{nullptr};
    SecuritySettings config{};
    std::set<std::string> ecosystems{};
    bool forceRefresh{false};
};

using SyncBackendRunner = std::function<std::vector<ValidationFinding>(const SyncBackendContext&)>;

struct SyncBackendRegistration {
    std::string id;
    SyncBackendScope scope{SyncBackendScope::PerEcosystem};
    /// When true, gateway may treat package names as ecosystem keys (gh-advisory).
    bool allowsRawPackageNamesAsEcosystem{false};
    /// Fills `security.backends[id]` when missing (optional URLs/tokens).
    std::function<void(SecurityConfig& security)> applyDefaultConfig;
    /// Merges gateway backend entry into a per-run SecuritySettings copy.
    std::function<void(SecuritySettings& out, const SecuritySettings& in, const std::string& backendId)>
        mergeGatewayBackendConfig;
    std::function<void(SecuritySettings& out, const std::string& backendId)> applyForceRefresh;
    SyncBackendRunner run;
};

/// Links built-in backends into the registry (idempotent).
void rqp_security_register_builtin_sync_backends();

void register_sync_backend(SyncBackendRegistration registration);

const SyncBackendRegistration* find_sync_backend(const std::string& backendId);

bool sync_backend_is_registered(const std::string& backendId);

/// Applies `applyDefaultConfig` for every registered backend.
void sync_backend_apply_registered_defaults(SecurityConfig& security);

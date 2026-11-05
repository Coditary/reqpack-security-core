#pragma once

#include "rqp/security/security_config.h"
#include "rqp/security/security_settings.h"
#include "rqp/security/validator_core.h"

#include <memory>
#include <set>
#include <string>
#include <vector>

class ISyncBackend;
class IAdvisoryWriter;
class PluginMetadataProvider;
class VulnerabilityDatabase;

namespace rqp::sync_backend {

inline constexpr const char* kOsv = "osv";
inline constexpr const char* kGhAdvisory = "gh-advisory";
inline constexpr const char* kSnyk = "snyk";
inline constexpr const char* kTrivy = "trivy";

} // namespace rqp::sync_backend

enum class SyncBackendScope {
    PerEcosystem,
    MultiEcosystem,
};

struct SecurityIoPorts;

struct SyncBackendContext {
    VulnerabilityDatabase* database{nullptr};
    PluginMetadataProvider* metadataProvider{nullptr};
    SecuritySettings config{};
    std::set<std::string> ecosystems{};
    bool forceRefresh{false};
    SecurityIoPorts* io{nullptr};
};

void rqp_security_register_builtin_sync_backends();

void register_sync_backend(std::unique_ptr<ISyncBackend> backend);

[[nodiscard]] const ISyncBackend* find_sync_backend(const std::string& backendId);

[[nodiscard]] bool sync_backend_is_registered(const std::string& backendId);

void sync_backend_apply_registered_defaults(SecurityConfig& security);

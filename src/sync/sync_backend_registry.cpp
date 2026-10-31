#include "rqp/security/sync_backend_registry.h"

#include <mutex>
#include <vector>

namespace {

std::mutex g_registryMutex;
std::vector<SyncBackendRegistration> g_backends;
bool g_builtinsRegistered{false};

void ensure_builtin_backends_registered() {
    if (g_builtinsRegistered) {
        return;
    }
    rqp_security_register_builtin_sync_backends();
    g_builtinsRegistered = true;
}

} // namespace

void register_sync_backend(SyncBackendRegistration registration) {
    if (registration.id.empty() || !registration.run) {
        return;
    }
    std::lock_guard lock(g_registryMutex);
    for (const auto& existing : g_backends) {
        if (existing.id == registration.id) {
            return;
        }
    }
    g_backends.push_back(std::move(registration));
}

const SyncBackendRegistration* find_sync_backend(const std::string& backendId) {
    ensure_builtin_backends_registered();
    std::lock_guard lock(g_registryMutex);
    for (const auto& backend : g_backends) {
        if (backend.id == backendId) {
            return &backend;
        }
    }
    return nullptr;
}

bool sync_backend_is_registered(const std::string& backendId) {
    return find_sync_backend(backendId) != nullptr;
}

void sync_backend_apply_registered_defaults(SecurityConfig& security) {
    ensure_builtin_backends_registered();
    std::lock_guard lock(g_registryMutex);
    for (const auto& backend : g_backends) {
        if (backend.applyDefaultConfig) {
            backend.applyDefaultConfig(security);
        }
    }
}

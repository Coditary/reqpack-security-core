#include "rqp/security/sync_backend_registry.h"

#include "ports/internal_ports.h"

#include <memory>
#include <mutex>
#include <vector>

namespace {

std::mutex g_registryMutex;
std::vector<std::unique_ptr<ISyncBackend>> g_backends;
bool g_builtinsRegistered{false};

void ensure_builtin_backends_registered() {
    if (g_builtinsRegistered) {
        return;
    }
    rqp_security_register_builtin_sync_backends();
    g_builtinsRegistered = true;
}

} // namespace

void register_sync_backend(std::unique_ptr<ISyncBackend> backend) {
    if (backend == nullptr || backend->id().empty()) {
        return;
    }
    std::lock_guard lock(g_registryMutex);
    for (const auto& existing : g_backends) {
        if (existing->id() == backend->id()) {
            return;
        }
    }
    g_backends.push_back(std::move(backend));
}

const ISyncBackend* find_sync_backend(const std::string& backendId) {
    ensure_builtin_backends_registered();
    std::lock_guard lock(g_registryMutex);
    for (const auto& backend : g_backends) {
        if (backend->id() == backendId) {
            return backend.get();
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
        backend->applyDefaultConfig(security);
    }
}

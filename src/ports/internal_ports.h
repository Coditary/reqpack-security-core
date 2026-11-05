#pragma once

#include "rqp/security/error.h"
#include "rqp/security/plugin_metadata_provider.h"
#include "rqp/security/ports.h"
#include "rqp/security/security_config.h"
#include "rqp/security/security_settings.h"
#include "rqp/security/sync_backend_registry.h"
#include "rqp/security/validator_core.h"

#include <map>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

struct SyncOptions {
    bool forceRefresh{false};
    std::string gateway;
    std::set<std::string> ecosystems;
    SecuritySettings settings = default_security_settings();
    PluginMetadataProvider* metadataProvider{nullptr};
};

struct HttpRequest {
    std::string url;
    std::string method{"GET"};
    std::span<const std::pair<std::string, std::string>> headers{};
    std::string body;
};

struct HttpResponse {
    long statusCode{0};
    std::string body;
    std::string error;
    std::map<std::string, std::string> headers;
};

class IHttpClient {
  public:
    virtual ~IHttpClient() = default;
    [[nodiscard]] virtual HttpResponse perform(const HttpRequest& request) const = 0;
};

class IArchiveExtractor {
  public:
    virtual ~IArchiveExtractor() = default;
    [[nodiscard]] virtual rqp::security::Result<std::string>
    extractToDirectory(const std::string& archivePath, const std::string& destinationDir) const = 0;
};

struct SecurityIoPorts {
    IHttpClient& http;
    IArchiveExtractor& archive;
};

class ISyncBackend {
  public:
    virtual ~ISyncBackend() = default;
    [[nodiscard]] virtual std::string id() const = 0;
    [[nodiscard]] virtual SyncBackendScope scope() const = 0;
    [[nodiscard]] virtual bool allowsRawPackageNamesAsEcosystem() const = 0;
    [[nodiscard]] virtual bool supportsEcosystem(const std::string& ecosystem) const = 0;
    virtual void applyDefaultConfig(SecurityConfig& security) const = 0;
    virtual void mergeGatewayBackendConfig(SecuritySettings& out, const SecuritySettings& in) const = 0;
    virtual void applyForceRefresh(SecuritySettings& out) const = 0;
    [[nodiscard]] virtual rqp::security::Result<std::vector<ValidationFinding>>
    sync(IAdvisoryWriter& store, const SyncOptions& options, SecurityIoPorts& io) const = 0;
};

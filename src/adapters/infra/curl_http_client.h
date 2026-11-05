#pragma once

#include "ports/internal_ports.h"
#include "rqp/security/security_settings.h"

class CurlHttpClient final : public IHttpClient {
    SecuritySettings settings;

  public:
    explicit CurlHttpClient(SecuritySettings settings = default_security_settings());

    [[nodiscard]] HttpResponse perform(const HttpRequest& request) const override;
};

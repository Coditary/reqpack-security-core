#pragma once

#include "rqp/security/ports.h"
#include "rqp/security/security_settings.h"

/// Default handler: logs findings and reads stdin when interaction is enabled.
class ConsolePromptDecisionHandler final : public IPolicyDecisionHandler {
    SecuritySettings settings;

  public:
    explicit ConsolePromptDecisionHandler(SecuritySettings settings = default_security_settings());

    PolicyDecision onPolicyViolation(std::span<const ValidationFinding> findings) const override;
};

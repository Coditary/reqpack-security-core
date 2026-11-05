#include "validator_internal.h"

#include "app/policy_decision_console.h"

bool Validator::requestUserDecision(const std::vector<ValidationFinding>& findings) const {
    if (this->config.policyDecisionHandler != nullptr) {
        return this->config.policyDecisionHandler->onPolicyViolation(findings) == PolicyDecision::Allow;
    }

    const ConsolePromptDecisionHandler consoleHandler(this->config);
    return consoleHandler.onPolicyViolation(findings) == PolicyDecision::Allow;
}

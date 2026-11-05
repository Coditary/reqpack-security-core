#include "app/policy_decision_console.h"

#include "rqp/security/security_log.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <string>

namespace {

std::string to_lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

} // namespace

ConsolePromptDecisionHandler::ConsolePromptDecisionHandler(SecuritySettings settings) : settings(std::move(settings)) {}

PolicyDecision ConsolePromptDecisionHandler::onPolicyViolation(std::span<const ValidationFinding> findings) const {
    security_log_stdout("unsafe findings require confirmation (" + std::to_string(findings.size()) + " total):");
    constexpr std::size_t kMaxPromptFindings = 12;
    std::size_t shown = 0;
    for (const ValidationFinding& finding : findings) {
        std::string message = finding.message.empty() ? finding.id : finding.message;
        if (!finding.source.empty()) {
            message += " [" + finding.source + "]";
        }
        if (!finding.package.system.empty() && !finding.package.name.empty()) {
            message += " [" + finding.package.system + ":" + finding.package.name + "]";
        }
        security_log_stdout("- " + message);
        ++shown;
        if (shown >= kMaxPromptFindings) {
            break;
        }
    }
    if (findings.size() > kMaxPromptFindings) {
        security_log_stdout("... " + std::to_string(findings.size() - kMaxPromptFindings) +
                            " more; run `rqp audit` on the same packages for the full list.");
    }

    if (!this->settings.interaction.interactive) {
        security_log_diagnostic("security", "interactive mode is disabled; refusing to continue.",
                                "Re-run without `--non-interactive`, set `security.onUnsafe` to `abort`/`continue`, or "
                                "use `--fail-on-unresolved-version` / audit first.");
        security_flush();
        return PolicyDecision::Deny;
    }

    security_log_stdout("Continue? [y/N]");
    security_flush();
    std::string answer;
    if (!std::getline(std::cin, answer)) {
        security_log_stdout("aborted.");
        security_flush();
        return PolicyDecision::Deny;
    }

    const std::string normalizedAnswer = to_lower_copy(answer);
    if (normalizedAnswer == "y" || normalizedAnswer == "yes") {
        return PolicyDecision::Allow;
    }

    security_log_stdout("aborted.");
    security_flush();
    return PolicyDecision::Deny;
}

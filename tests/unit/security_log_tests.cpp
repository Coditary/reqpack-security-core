#include <catch2/catch.hpp>

#include "rqp/security/security_log.h"
#include "test_helpers.h"

TEST_CASE("security log callbacks receive structured messages", "[unit][security_log]") {
    ScopedSecurityLogCapture capture;

    security_log(SecurityLogLevel::Warn, "security", "sync stalled");
    security_log_stdout("continue prompt");
    security_log_diagnostic("security", "interactive mode is disabled; refusing to continue.",
                            "enable interactive mode");
    security_flush();

    CHECK(capture.stdoutMessages.size() == 1);
    CHECK(capture.stdoutMessages.front() == "continue prompt");
    REQUIRE(capture.diagnosticMessages.size() == 1);
    CHECK(capture.diagnosticMessages.front().find("interactive mode is disabled") != std::string::npos);
}

TEST_CASE("security log callback receives categorized messages", "[unit][security_log]") {
    std::vector<std::string> messages;
    set_security_log_callback(
        [&messages](SecurityLogLevel level, const std::string& category, const std::string& message) {
            messages.push_back(std::to_string(static_cast<int>(level)) + ":" + category + ":" + message);
        });

    security_log(SecurityLogLevel::Error, "security", "failed");
    REQUIRE(messages.size() == 1);
    CHECK(messages.front().find("security:failed") != std::string::npos);

    set_security_log_callback({});
}

TEST_CASE("security log falls back when callbacks are unset", "[unit][security_log]") {
    set_security_log_callback({});
    set_security_stdout_callback({});
    set_security_diagnostic_callback({});
    set_security_flush_callback({});

    CHECK_NOTHROW(security_log(SecurityLogLevel::Info, "security", "noop"));
    CHECK_NOTHROW(security_log_stdout("noop"));
    CHECK_NOTHROW(security_log_diagnostic("security", "noop", "hint"));
    CHECK_NOTHROW(security_flush());
}

TEST_CASE("security log uses default stdout and diagnostic fallbacks", "[unit][security_log]") {
    set_security_stdout_callback({});
    set_security_diagnostic_callback({});
    set_security_flush_callback({});

    CHECK_NOTHROW(security_log_stdout("stdout fallback"));
    CHECK_NOTHROW(security_log_diagnostic("security", "stderr fallback", "hint"));
    CHECK_NOTHROW(security_flush());
}

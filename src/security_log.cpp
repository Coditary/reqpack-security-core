#include "rqp/security/security_log.h"

#include <iostream>

namespace {

SecurityLogCallback g_logCallback;
SecurityStdoutCallback g_stdoutCallback;
SecurityDiagnosticCallback g_diagnosticCallback;
SecurityFlushCallback g_flushCallback;

void default_stdout(const std::string& message) {
    std::cout << message << std::endl;
}

void default_flush() {
    std::cout.flush();
    std::cerr.flush();
}

} // namespace

void set_security_log_callback(SecurityLogCallback callback) {
    g_logCallback = std::move(callback);
}

void set_security_stdout_callback(SecurityStdoutCallback callback) {
    g_stdoutCallback = std::move(callback);
}

void set_security_diagnostic_callback(SecurityDiagnosticCallback callback) {
    g_diagnosticCallback = std::move(callback);
}

void set_security_flush_callback(SecurityFlushCallback callback) {
    g_flushCallback = std::move(callback);
}

void security_log(SecurityLogLevel level, const std::string& category, const std::string& message) {
    if (g_logCallback) {
        g_logCallback(level, category, message);
    }
}

void security_log_stdout(const std::string& message) {
    if (g_stdoutCallback) {
        g_stdoutCallback(message);
    } else {
        default_stdout(message);
    }
}

void security_log_diagnostic(const std::string& category, const std::string& message, const std::string& hint) {
    if (g_diagnosticCallback) {
        g_diagnosticCallback(category, message, hint);
        return;
    }

    std::cerr << category << ": " << message;
    if (!hint.empty()) {
        std::cerr << " (" << hint << ")";
    }
    std::cerr << std::endl;
}

void security_flush() {
    if (g_flushCallback) {
        g_flushCallback();
    } else {
        default_flush();
    }
}

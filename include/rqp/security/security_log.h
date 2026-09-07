#pragma once

#include <functional>
#include <string>

enum class SecurityLogLevel { Info, Warn, Error, Debug };

using SecurityLogCallback =
    std::function<void(SecurityLogLevel level, const std::string& category, const std::string& message)>;
using SecurityStdoutCallback = std::function<void(const std::string& message)>;
using SecurityDiagnosticCallback =
    std::function<void(const std::string& category, const std::string& message, const std::string& hint)>;
using SecurityFlushCallback = std::function<void()>;

void set_security_log_callback(SecurityLogCallback callback);
void set_security_stdout_callback(SecurityStdoutCallback callback);
void set_security_diagnostic_callback(SecurityDiagnosticCallback callback);
void set_security_flush_callback(SecurityFlushCallback callback);

void security_log(SecurityLogLevel level, const std::string& category, const std::string& message);
void security_log_stdout(const std::string& message);
void security_log_diagnostic(const std::string& category, const std::string& message, const std::string& hint);
void security_flush();

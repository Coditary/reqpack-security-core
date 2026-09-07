#pragma once

#include "rqp/security/security_log.h"
#include "rqp/security/security_settings.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

inline SecuritySettings test_security_settings() {
    SecuritySettings settings = default_security_settings();
    settings.security.enabled = true;
    return settings;
}

class TempDir {
  public:
    explicit TempDir(const std::string& prefix)
        : path_(std::filesystem::temp_directory_path() /
                (prefix + "-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))) {
        std::filesystem::create_directories(path_);
    }

    ~TempDir() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& path() const {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

inline void write_file(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    if (!output.is_open()) {
        throw std::runtime_error("failed to open test file: " + path.string());
    }
    output << content;
}

#if defined(_WIN32)
#include <stdlib.h>
#endif

inline void set_test_environment_value(const std::string& name, const std::optional<std::string>& value) {
#if defined(_WIN32)
    _putenv_s(name.c_str(), value.has_value() ? value->c_str() : "");
#else
    if (value.has_value()) {
        ::setenv(name.c_str(), value->c_str(), 1);
    } else {
        ::unsetenv(name.c_str());
    }
#endif
}

class ScopedEnvVar {
  public:
    explicit ScopedEnvVar(std::string name) : name_(std::move(name)) {
        if (const char* existing = std::getenv(name_.c_str())) {
            previous_ = std::string(existing);
        }
    }

    ScopedEnvVar(std::string name, std::string value) : ScopedEnvVar(std::move(name)) {
        set_test_environment_value(name_, value);
    }

    ScopedEnvVar(const char* name, const char* value) : name_(name) {
        if (const char* existing = std::getenv(name_.c_str())) {
            previous_ = std::string(existing);
        }
        if (value != nullptr) {
            set_test_environment_value(name_, std::string(value));
        } else {
            set_test_environment_value(name_, std::nullopt);
        }
    }

    ~ScopedEnvVar() {
        if (previous_.has_value()) {
            set_test_environment_value(name_, previous_);
        } else {
            set_test_environment_value(name_, std::nullopt);
        }
    }

  private:
    std::string name_;
    std::optional<std::string> previous_;
};

class ScopedSecurityLogCapture {
  public:
    ScopedSecurityLogCapture() {
        set_security_stdout_callback([this](const std::string& message) { stdoutMessages.push_back(message); });
        set_security_diagnostic_callback(
            [this](const std::string& category, const std::string& message, const std::string& hint) {
                diagnosticMessages.push_back(category + ": " + message + " (" + hint + ")");
            });
        set_security_flush_callback([]() {});
    }

    ~ScopedSecurityLogCapture() {
        set_security_stdout_callback({});
        set_security_diagnostic_callback({});
        set_security_flush_callback({});
    }

    std::vector<std::string> stdoutMessages;
    std::vector<std::string> diagnosticMessages;
};

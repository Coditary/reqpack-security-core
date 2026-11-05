#pragma once

#include <filesystem>
#include <string>
#include <vector>

struct RqpSecurityProcessResult {
    int exitCode{1};
    std::string stdoutText;
    std::string stderrText;

    bool success() const {
        return exitCode == 0;
    }
};

bool rqp_security_run_process(const std::vector<std::string>& arguments,
                              const std::filesystem::path& workingDirectory = {});

RqpSecurityProcessResult rqp_security_run_process_capture(const std::vector<std::string>& arguments,
                                                          const std::filesystem::path& workingDirectory = {});

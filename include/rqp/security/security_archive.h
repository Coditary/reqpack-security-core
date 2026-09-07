#pragma once

#include <filesystem>
#include <functional>
#include <vector>

struct SecurityArchiveResolution {
    std::filesystem::path installPath;
    std::vector<std::filesystem::path> cleanupPaths;
};

struct SecurityArchiveConfig {
    std::function<SecurityArchiveResolution(const std::filesystem::path&)> extractToTemp;
};

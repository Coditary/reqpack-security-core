#include "rqp/security/security_paths.h"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>

#if !defined(_WIN32)
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace {

#if !defined(_WIN32)

std::optional<std::filesystem::path> passwd_home_from_user(const std::string& username) {
    if (username.empty()) {
        return std::nullopt;
    }

    if (passwd* entry = getpwnam(username.c_str())) {
        if (entry->pw_dir != nullptr && std::string(entry->pw_dir).size() > 0) {
            return std::filesystem::path(entry->pw_dir);
        }
    }

    return std::nullopt;
}

std::optional<std::filesystem::path> passwd_home_from_uid(uid_t uid) {
    if (passwd* entry = getpwuid(uid)) {
        if (entry->pw_dir != nullptr && std::string(entry->pw_dir).size() > 0) {
            return std::filesystem::path(entry->pw_dir);
        }
    }

    return std::nullopt;
}

#endif

std::filesystem::path invoking_user_home_directory() {
#if defined(_WIN32)
    const char* userProfile = std::getenv("USERPROFILE");
    if (userProfile != nullptr && std::string(userProfile).size() > 0) {
        return std::filesystem::path(userProfile);
    }

    const char* home = std::getenv("HOME");
    if (home != nullptr && std::string(home).size() > 0) {
        return std::filesystem::path(home);
    }

    return std::filesystem::current_path();
#else
    const char* sudoUser = std::getenv("SUDO_USER");
    if (sudoUser != nullptr && std::string(sudoUser).size() > 0) {
        if (const auto home = passwd_home_from_user(sudoUser)) {
            return home.value();
        }
    }

    const char* sudoUid = std::getenv("SUDO_UID");
    if (sudoUid != nullptr && std::string(sudoUid).size() > 0) {
        try {
            const uid_t uid = static_cast<uid_t>(std::stoul(sudoUid));
            if (const auto home = passwd_home_from_uid(uid)) {
                return home.value();
            }
        } catch (...) {
        }
    }

    const char* home = std::getenv("HOME");
    if (home != nullptr && std::string(home).size() > 0) {
        return std::filesystem::path(home);
    }

    return std::filesystem::current_path();
#endif
}

std::filesystem::path xdg_directory(const char* envName, const std::filesystem::path& fallback) {
    const char* value = std::getenv(envName);
    if (value != nullptr && std::string(value).size() > 0) {
        return std::filesystem::path(value) / "reqpack";
    }
    return fallback / "reqpack";
}

} // namespace

std::filesystem::path default_security_data_directory() {
    return xdg_directory("XDG_DATA_HOME", invoking_user_home_directory() / ".local" / "share");
}

std::filesystem::path default_security_cache_directory() {
    return xdg_directory("XDG_CACHE_HOME", invoking_user_home_directory() / ".cache");
}

std::filesystem::path default_security_cache_path() {
    return default_security_cache_directory() / "security" / "cache";
}

std::filesystem::path default_security_index_path() {
    return default_security_data_directory() / "security" / "index";
}

std::filesystem::path default_osv_database_path() {
    return default_security_data_directory() / "security" / "osv";
}

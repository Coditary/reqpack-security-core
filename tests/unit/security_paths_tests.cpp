#include <catch2/catch.hpp>

#include "rqp/security/security_paths.h"
#include "test_helpers.h"

TEST_CASE("security paths honor XDG environment overrides", "[unit][security_paths]") {
    TempDir tempDir{"security-paths-xdg"};
    const std::filesystem::path dataRoot = tempDir.path() / "data";
    const std::filesystem::path cacheRoot = tempDir.path() / "cache";

    ScopedEnvVar dataHome{"XDG_DATA_HOME", dataRoot.string()};
    ScopedEnvVar cacheHome{"XDG_CACHE_HOME", cacheRoot.string()};

    CHECK(default_security_data_directory() == dataRoot / "reqpack");
    CHECK(default_security_cache_directory() == cacheRoot / "reqpack");
    CHECK(default_security_index_path() == dataRoot / "reqpack" / "security" / "index");
    CHECK(default_osv_database_path() == dataRoot / "reqpack" / "security" / "osv");
    CHECK(default_security_cache_path() == cacheRoot / "reqpack" / "security" / "cache");
}

TEST_CASE("security paths fall back to home directory layout", "[unit][security_paths]") {
    TempDir tempDir{"security-paths-home"};
    ScopedEnvVar unsetData{"XDG_DATA_HOME", nullptr};
    ScopedEnvVar unsetCache{"XDG_CACHE_HOME", nullptr};
    ScopedEnvVar home{"HOME", tempDir.path().string()};

    CHECK(default_security_data_directory() == tempDir.path() / ".local" / "share" / "reqpack");
    CHECK(default_security_cache_directory() == tempDir.path() / ".cache" / "reqpack");
}

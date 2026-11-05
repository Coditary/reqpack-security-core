#include "sync/trivy/trivy_sync_internal.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0 || size > (1U << 16)) {
        return 0;
    }

    const std::filesystem::path path =
        std::filesystem::temp_directory_path() / "reqpack-security-fuzz-trivy-metadata.json";
    {
        std::ofstream output(path, std::ios::binary);
        output.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    }

    (void)trivy_sync_internal::load_trivy_metadata(path);

    std::error_code error;
    std::filesystem::remove(path, error);
    return 0;
}

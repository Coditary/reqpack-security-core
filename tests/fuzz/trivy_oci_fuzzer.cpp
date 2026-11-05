#include "sync/trivy/trivy_sync_internal.h"

#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0 || size > (1U << 14)) {
        return 0;
    }

    const std::string input(reinterpret_cast<const char*>(data), size);
    (void)trivy_sync_internal::parse_oci_reference(input);

    const std::size_t split = input.find('\0');
    if (split != std::string::npos && split + 1 < input.size()) {
        (void)trivy_sync_internal::parse_bearer_challenge(input.substr(split + 1));
    } else {
        (void)trivy_sync_internal::parse_bearer_challenge(input);
    }

    return 0;
}

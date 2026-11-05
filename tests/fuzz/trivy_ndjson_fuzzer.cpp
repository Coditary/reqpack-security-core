#include "sync/trivy/trivy_sync_internal.h"

#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0 || size > (1U << 18)) {
        return 0;
    }

    const std::string output(reinterpret_cast<const char*>(data), size);
    (void)trivy_sync_internal::load_helper_records(output);
    return 0;
}

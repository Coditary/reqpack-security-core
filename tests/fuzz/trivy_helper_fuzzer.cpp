#include <cstddef>
#include <cstdint>
#include <string>

#include "sync/trivy/trivy_vulnerability_sync_service.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0 || size > (1U << 18)) {
        return 0;
    }

    const std::string line(reinterpret_cast<const char*>(data), size);
    (void)trivy_parse_helper_record(line);
    return 0;
}

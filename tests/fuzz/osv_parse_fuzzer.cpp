#include <cstddef>
#include <cstdint>
#include <string>

#include "rqp/security/osv_core.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0 || size > (1U << 20)) {
        return 0;
    }

    const std::string json(reinterpret_cast<const char*>(data), size);
    const auto advisory = osv_parse_advisory(json);
    if (advisory.has_value()) {
        (void)osv_collect_package_keys(advisory.value());
        (void)osv_match_package(advisory.value(), "npm", "example", "1.0.0");
    }

    return 0;
}

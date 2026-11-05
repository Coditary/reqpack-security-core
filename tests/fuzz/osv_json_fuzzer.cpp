#include "rqp/security/osv_core.h"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > 65536) {
        return 0;
    }
    const std::string payload(reinterpret_cast<const char*>(data), size);
    (void)osv_parse_advisory(payload);
    return 0;
}

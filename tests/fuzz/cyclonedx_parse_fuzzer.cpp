#include "cyclonedx/cyclonedx_ffi.h"

#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > 262144) {
        return 0;
    }

    const std::string input(reinterpret_cast<const char*>(data), size);
    char* output = nullptr;
    const int status = rqp_cyclonedx_parse_inventory_json(input.c_str(), &output);
    if (output != nullptr) {
        (void)status;
        rqp_cyclonedx_free(output);
    }
    return 0;
}

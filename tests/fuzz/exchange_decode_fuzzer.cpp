#include "rqp/security/exchange_view.h"

#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0 || size > (1U << 18)) {
        return 0;
    }

    const std::string payload(reinterpret_cast<const char*>(data), size);

    (void)decode_to_view(payload, WireFormat::AUTO);

    const WireFormat formats[] = {
        WireFormat::CYCLONEDX,
        WireFormat::SPDX,
        WireFormat::REQPACK_SBOM_JSON,
    };
    for (const WireFormat format : formats) {
        (void)decode_to_view(payload, format);
    }

    return 0;
}

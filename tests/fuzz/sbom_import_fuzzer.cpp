#include "rqp/security/sbom_inventory.h"

#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0 || size > (1U << 18)) {
        return 0;
    }

    const std::string payload(reinterpret_cast<const char*>(data), size);
    const SecuritySettings config = default_security_settings();

    (void)import_sbom_from_json(payload, config, SbomInventoryFormat::AUTO);

    const SbomInventoryFormat explicitFormats[] = {
        SbomInventoryFormat::CYCLONEDX,
        SbomInventoryFormat::SPDX,
        SbomInventoryFormat::REQPACK_JSON,
    };
    for (const SbomInventoryFormat format : explicitFormats) {
        (void)import_sbom_from_json(payload, config, format);
    }

    return 0;
}

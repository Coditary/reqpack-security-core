#include <cstddef>
#include <cstdint>
#include <string>

#include "rqp/security/version_compare.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == nullptr || size < 2 || size > (1U << 16)) {
        return 0;
    }

    const std::string input(reinterpret_cast<const char*>(data), size);
    const std::size_t split = input.find('\0');
    if (split == std::string::npos || split == 0 || split + 1 >= input.size()) {
        return 0;
    }

    const std::string left = input.substr(0, split);
    const std::string right = input.substr(split + 1);

    const VersionComparatorSpec profiles[] = {
        {.profile = "semver"},
        {.profile = "rpm-evr"},
        {.profile = "pep440"},
        {.profile = "maven-comparable"},
        {.profile = "lexicographic"},
        {.profile = "raw"},
        {.profile = "unknown-profile", .tokenPattern = "[0-9]+|[A-Za-z]+", .caseInsensitive = true},
    };

    for (const VersionComparatorSpec& spec : profiles) {
        (void)version_compare_values(left, right, spec);
        (void)version_less_equal(left, right, spec);
        (void)version_greater_equal(left, right, spec);
    }

    return 0;
}

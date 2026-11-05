#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "sync/snyk/snyk_vulnerability_sync_service.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0 || size > (1U << 18)) {
        return 0;
    }

    const std::string line(reinterpret_cast<const char*>(data), size);
    const std::vector<std::string> values = snyk_parse_csv_line(line);
    if (values.size() >= 2) {
        const std::vector<std::string> header = {
            "PROBLEM_ID",
            "PROBLEM_TITLE",
            "CVE",
            "PACKAGE_NAME_AND_VERSION",
            "SEMVER_VULNERABLE_RANGE",
            "ISSUE_SEVERITY",
            "NVD_SCORE",
            "SNYK_CVSS_SCORE",
            "UPDATED_AT",
            "FIXED_IN_VERSION",
            "PRODUCT_NAME",
        };
        (void)snyk_parse_export_row(header, values);
    }

    (void)snyk_parse_maven_package_name_and_version(line);
    (void)snyk_normalize_severity(line, 0.0);

    return 0;
}

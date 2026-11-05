#include "rqp/security/osv_core.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace {

std::string field_before_delim(const std::string& input, std::size_t start, char delim, std::size_t& end) {
    end = input.find(delim, start);
    if (end == std::string::npos) {
        end = input.size();
    }
    if (end <= start || end - start > 256) {
        return {};
    }
    return input.substr(start, end - start);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0 || size > (1U << 20)) {
        return 0;
    }

    const std::string input(reinterpret_cast<const char*>(data), size);

    std::size_t cursor = 0;
    const std::string json = field_before_delim(input, cursor, '\0', cursor);
    const std::string jsonPayload = json.empty() ? input : json;

    const auto advisory = osv_parse_advisory(jsonPayload);
    if (!advisory.has_value()) {
        return 0;
    }

    (void)osv_collect_package_keys(advisory.value());

    std::size_t fieldEnd = cursor;
    if (cursor < input.size() && input[cursor] == '\0') {
        ++cursor;
    }
    const std::string ecosystem = field_before_delim(input, cursor, '\0', fieldEnd);
    if (fieldEnd < input.size() && input[fieldEnd] == '\0') {
        cursor = fieldEnd + 1;
    } else {
        cursor = fieldEnd;
    }
    fieldEnd = cursor;
    const std::string name = field_before_delim(input, cursor, '\0', fieldEnd);
    if (fieldEnd < input.size() && input[fieldEnd] == '\0') {
        cursor = fieldEnd + 1;
    } else {
        cursor = fieldEnd;
    }
    const std::string version =
        cursor < input.size() ? field_before_delim(input, cursor, '\0', fieldEnd) : std::string{};

    if (!ecosystem.empty() && !name.empty()) {
        (void)osv_match_package(advisory.value(), ecosystem, name, version);
    }

    for (const OsvAffectedPackage& affected : advisory.value().affected) {
        (void)osv_match_package(advisory.value(), affected.ecosystem, affected.name,
                                affected.versions.empty() ? version : affected.versions.front());
    }

    return 0;
}

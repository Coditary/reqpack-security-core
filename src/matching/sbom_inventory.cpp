#include "rqp/security/sbom_inventory.h"

#include <boost/graph/adjacency_list.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <fstream>
#include <set>
#include <sstream>

namespace {

using boost::property_tree::ptree;

struct ParsedComponent {
    std::string system;
    std::string name;
    std::string version;
};

std::string trim_copy(const std::string& value) {
    const std::size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const std::size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::optional<std::string> property_value(const ptree& node, const std::string& propertyName) {
    if (!node.count("properties")) {
        return std::nullopt;
    }
    for (const auto& [_, property] : node.get_child("properties")) {
        const boost::optional<std::string> name = property.get_optional<std::string>("name");
        const boost::optional<std::string> value = property.get_optional<std::string>("value");
        if (name.has_value() && value.has_value() && name.value() == propertyName) {
            return value.value();
        }
    }
    return std::nullopt;
}

std::string default_system_for_purl_type(const std::string& purlType) {
    const std::string normalized = purlType;
    if (normalized == "pypi") {
        return "pip";
    }
    if (normalized == "golang") {
        return "go";
    }
    if (normalized == "gem") {
        return "rubygems";
    }
    return normalized;
}

std::optional<ParsedComponent> parse_purl(const std::string& purl) {
    const std::string trimmed = trim_copy(purl);
    if (!trimmed.starts_with("pkg:")) {
        return std::nullopt;
    }

    const std::string body = trimmed.substr(4);
    const std::size_t at = body.rfind('@');
    const std::string typeAndName = at == std::string::npos ? body : body.substr(0, at);
    const std::string version = at == std::string::npos ? std::string{} : body.substr(at + 1);

    const std::size_t slash = typeAndName.find('/');
    if (slash == std::string::npos || slash == 0) {
        return std::nullopt;
    }

    const std::string purlType = typeAndName.substr(0, slash);
    const std::string remainder = typeAndName.substr(slash + 1);
    if (remainder.empty()) {
        return std::nullopt;
    }

    ParsedComponent component;
    component.system = default_system_for_purl_type(purlType);
    component.version = version;

    if (purlType == "maven") {
        const std::size_t nameSlash = remainder.rfind('/');
        if (nameSlash == std::string::npos || nameSlash == 0 || nameSlash == remainder.size() - 1) {
            return std::nullopt;
        }
        component.name = remainder.substr(0, nameSlash) + ":" + remainder.substr(nameSlash + 1);
    } else {
        component.name = remainder;
    }

    return component;
}

std::string package_dedupe_key(const Package& package) {
    return package.system + '\n' + package.name + '\n' + package.version;
}

void append_package(Graph& graph, std::set<std::string>& seen, Package package,
                    std::vector<SbomImportWarning>& warnings, const std::string& context) {
    package.action = ActionType::AUDIT;
    if (package.system.empty() || package.name.empty()) {
        warnings.push_back(SbomImportWarning{.message = "skipped component with missing system or name: " + context});
        return;
    }

    const std::string key = package_dedupe_key(package);
    if (seen.contains(key)) {
        return;
    }
    seen.insert(key);
    boost::add_vertex(package, graph);
}

std::optional<ParsedComponent> parse_cyclonedx_component(const ptree& component) {
    ParsedComponent parsed;

    if (const auto reqpackSystem = property_value(component, "reqpack:system"); reqpackSystem.has_value()) {
        parsed.system = reqpackSystem.value();
    }

    if (const auto purl = component.get_optional<std::string>("purl"); purl.has_value() && !purl->empty()) {
        if (const auto fromPurl = parse_purl(purl.value()); fromPurl.has_value()) {
            if (parsed.system.empty()) {
                parsed.system = fromPurl->system;
            }
            parsed.name = fromPurl->name;
            if (parsed.version.empty()) {
                parsed.version = fromPurl->version;
            }
        }
    }

    if (parsed.name.empty()) {
        if (const auto name = component.get_optional<std::string>("name"); name.has_value()) {
            parsed.name = name.value();
        }
    }
    if (parsed.version.empty()) {
        if (const auto version = component.get_optional<std::string>("version"); version.has_value()) {
            parsed.version = version.value();
        }
    }
    if (parsed.system.empty()) {
        if (const auto componentType = component.get_optional<std::string>("type"); componentType.has_value()) {
            parsed.system = componentType.value();
        }
    }

    if (parsed.name.empty()) {
        return std::nullopt;
    }
    return parsed;
}

SbomImportResult import_cyclonedx(const ptree& root) {
    SbomImportResult result;
    result.detectedFormat = "cyclonedx";

    if (!root.count("components")) {
        result.error = "cyclonedx document has no components array";
        return result;
    }

    std::set<std::string> seen;
    for (const auto& [_, componentNode] : root.get_child("components")) {
        const std::optional<ParsedComponent> parsedComponent = parse_cyclonedx_component(componentNode);
        if (!parsedComponent.has_value()) {
            result.warnings.push_back(SbomImportWarning{.message = "skipped unparseable cyclonedx component"});
            continue;
        }
        const ParsedComponent parsed = parsedComponent.value();
        append_package(result.graph, seen,
                       Package{.system = parsed.system, .name = parsed.name, .version = parsed.version},
                       result.warnings, parsed.name);
    }

    if (boost::num_vertices(result.graph) == 0) {
        result.error = "cyclonedx document contained no usable components";
    }
    return result;
}

std::optional<ParsedComponent> parse_spdx_package(const ptree& package) {
    ParsedComponent parsed;
    if (const auto name = package.get_optional<std::string>("name"); name.has_value()) {
        parsed.name = name.value();
    }
    if (const auto version = package.get_optional<std::string>("versionInfo"); version.has_value()) {
        parsed.version = version.value();
    }

    if (package.count("externalRefs")) {
        for (const auto& [_, refNode] : package.get_child("externalRefs")) {
            const auto refType = refNode.get_optional<std::string>("referenceType");
            const auto locator = refNode.get_optional<std::string>("referenceLocator");
            if (!refType.has_value() || !locator.has_value()) {
                continue;
            }
            if (refType.value() != "purl") {
                continue;
            }
            if (const auto fromPurl = parse_purl(locator.value()); fromPurl.has_value()) {
                parsed.system = fromPurl->system;
                parsed.name = fromPurl->name;
                if (!fromPurl->version.empty()) {
                    parsed.version = fromPurl->version;
                }
                return parsed;
            }
        }
    }

    if (parsed.name.empty()) {
        return std::nullopt;
    }
    if (parsed.system.empty()) {
        parsed.system = "unknown";
    }
    return parsed;
}

SbomImportResult import_spdx(const ptree& root) {
    SbomImportResult result;
    result.detectedFormat = "spdx";

    if (!root.count("packages")) {
        result.error = "spdx document has no packages array";
        return result;
    }

    std::set<std::string> seen;
    for (const auto& [_, packageNode] : root.get_child("packages")) {
        const std::optional<ParsedComponent> parsedPackage = parse_spdx_package(packageNode);
        if (!parsedPackage.has_value()) {
            result.warnings.push_back(SbomImportWarning{.message = "skipped unparseable spdx package"});
            continue;
        }
        const ParsedComponent parsed = parsedPackage.value();
        append_package(result.graph, seen,
                       Package{.system = parsed.system, .name = parsed.name, .version = parsed.version},
                       result.warnings, parsed.name);
    }

    if (boost::num_vertices(result.graph) == 0) {
        result.error = "spdx document contained no usable packages";
    }
    return result;
}

SbomImportResult import_reqpack_json(const ptree& root) {
    SbomImportResult result;
    result.detectedFormat = "reqpack-json";

    if (!root.count("packages")) {
        result.error = "reqpack sbom json has no packages array";
        return result;
    }

    std::set<std::string> seen;
    for (const auto& [_, packageNode] : root.get_child("packages")) {
        Package package;
        if (const auto system = packageNode.get_optional<std::string>("system"); system.has_value()) {
            package.system = system.value();
        }
        if (const auto name = packageNode.get_optional<std::string>("name"); name.has_value()) {
            package.name = name.value();
        }
        if (const auto version = packageNode.get_optional<std::string>("version"); version.has_value()) {
            package.version = version.value();
        }
        if (const auto sourcePath = packageNode.get_optional<std::string>("sourcePath"); sourcePath.has_value()) {
            package.sourcePath = sourcePath.value();
        }
        if (const auto localTarget = packageNode.get_optional<bool>("localTarget"); localTarget.has_value()) {
            package.localTarget = localTarget.value();
        }
        append_package(result.graph, seen, package, result.warnings, package.name);
    }

    if (boost::num_vertices(result.graph) == 0) {
        result.error = "reqpack sbom json contained no usable packages";
    }
    return result;
}

SbomInventoryFormat detect_format(const ptree& root) {
    if (root.get_optional<std::string>("bomFormat").has_value()) {
        return SbomInventoryFormat::CYCLONEDX;
    }
    if (root.get_optional<std::string>("spdxVersion").has_value()) {
        return SbomInventoryFormat::SPDX;
    }
    if (root.count("packages")) {
        return SbomInventoryFormat::REQPACK_JSON;
    }
    return SbomInventoryFormat::AUTO;
}

SbomImportResult import_root(const ptree& root, SbomInventoryFormat format) {
    const SbomInventoryFormat resolved = format == SbomInventoryFormat::AUTO ? detect_format(root) : format;
    if (resolved == SbomInventoryFormat::CYCLONEDX) {
        return import_cyclonedx(root);
    }
    if (resolved == SbomInventoryFormat::SPDX) {
        return import_spdx(root);
    }
    if (resolved == SbomInventoryFormat::REQPACK_JSON) {
        return import_reqpack_json(root);
    }

    SbomImportResult result;
    result.error = "unable to detect sbom format; specify cyclonedx, spdx, or reqpack-json";
    return result;
}

} // namespace

SbomImportResult import_sbom_from_json(const std::string& json, const SecuritySettings& config,
                                       SbomInventoryFormat format) {
    (void)config;

    SbomImportResult result;
    if (json.empty()) {
        result.error = "sbom json payload is empty";
        return result;
    }

    std::istringstream input(json);
    ptree root;
    try {
        boost::property_tree::read_json(input, root);
    } catch (const std::exception& exception) {
        result.error = std::string("failed to parse sbom json: ") + exception.what();
        return result;
    }

    return import_root(root, format);
}

SbomImportResult import_sbom_from_path(const std::filesystem::path& path, const SecuritySettings& config,
                                       SbomInventoryFormat format) {
    SbomImportResult result;
    std::ifstream input(path);
    if (!input.is_open()) {
        result.error = "failed to open sbom file: " + path.string();
        return result;
    }

    ptree root;
    try {
        boost::property_tree::read_json(input, root);
    } catch (const std::exception& exception) {
        result.error = std::string("failed to parse sbom json: ") + exception.what();
        return result;
    }

    return import_root(root, format);
}

#include "rqp/security/json_util.h"

#include "detail/sync_common.h"

#include <optional>

std::string rqp_json_escape(const std::string& value) {
    return rqp_security_detail::json_escape(value);
}

bool rqp_parse_json_tree(const std::string& json, boost::property_tree::ptree& tree) {
    return rqp_security_detail::parse_json_tree(json, tree);
}

std::optional<boost::property_tree::ptree> rqp_try_parse_json_tree(const std::string& json) {
    if (json.empty()) {
        return std::nullopt;
    }

    boost::property_tree::ptree tree;
    if (!rqp_parse_json_tree(json, tree)) {
        return std::nullopt;
    }
    return tree;
}

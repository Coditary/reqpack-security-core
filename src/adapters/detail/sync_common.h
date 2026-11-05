#pragma once

#include <boost/property_tree/ptree.hpp>
#include <set>
#include <string>

namespace rqp_security_detail {

std::string trim_copy(const std::string& value);
std::string to_lower_copy(std::string value);
bool starts_with(const std::string& value, const std::string& prefix);
std::string json_escape(const std::string& value);

std::string now_epoch_seconds();
std::string join_scope_key(const std::set<std::string>& ecosystems);

bool parse_json_tree(const std::string& json, boost::property_tree::ptree& tree);

int severity_rank(const std::string& severity);
std::string severity_from_score(double score);

} // namespace rqp_security_detail

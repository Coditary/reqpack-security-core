#pragma once

#include <boost/property_tree/ptree.hpp>

#include <optional>
#include <string>

std::string rqp_json_escape(const std::string& value);

bool rqp_parse_json_tree(const std::string& json, boost::property_tree::ptree& tree);

std::optional<boost::property_tree::ptree> rqp_try_parse_json_tree(const std::string& json);

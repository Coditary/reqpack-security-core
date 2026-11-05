#pragma once

#include <curl/curl.h>

#include <string>
#include <vector>

std::string rqp_security_ca_bundle_path();
void rqp_security_apply_curl_ca_bundle(CURL* curl);
std::vector<std::string> rqp_security_sanitized_process_environment();

#include <catch2/catch.hpp>

#include <curl/curl.h>

#include "infra/security_network.h"
#include "test_helpers.h"

TEST_CASE("security network resolves ca bundle from env or system paths", "[unit][security_network]") {
    TempDir tempDir{"security-network"};
    const std::filesystem::path certPath = tempDir.path() / "ca.pem";
    write_file(certPath, "dummy-ca-bundle");

    ScopedEnvVar sslCert{"SSL_CERT_FILE", certPath.string().c_str()};
    CHECK(rqp_security_ca_bundle_path() == certPath.string());

    CURL* curl = curl_easy_init();
    REQUIRE(curl != nullptr);
    CHECK_NOTHROW(rqp_security_apply_curl_ca_bundle(curl));
    curl_easy_cleanup(curl);
}

TEST_CASE("security network sanitizes process environment", "[unit][security_network]") {
    TempDir tempDir{"security-network-env"};
    const std::filesystem::path certPath = tempDir.path() / "ca.pem";
    write_file(certPath, "dummy-ca-bundle");
    ScopedEnvVar sslCert{"SSL_CERT_FILE", certPath.string().c_str()};
    ScopedEnvVar ldPath{"LD_LIBRARY_PATH", "/tmp/evil"};

    const std::vector<std::string> environment = rqp_security_sanitized_process_environment();
    CHECK(std::none_of(environment.begin(), environment.end(),
                       [](const std::string& entry) { return entry.rfind("LD_LIBRARY_PATH=", 0) == 0; }));
    CHECK(std::any_of(environment.begin(), environment.end(),
                      [&](const std::string& entry) { return entry == "SSL_CERT_FILE=" + certPath.string(); }));
}

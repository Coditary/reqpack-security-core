cmake_minimum_required(VERSION 3.15)
project(ReqPackSecurityCore LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(RQP_SECURITY_CORE_STANDALONE TRUE)
else()
    set(RQP_SECURITY_CORE_STANDALONE FALSE)
endif()

option(RQP_SECURITY_CORE_BUILD_TESTS
    "Build and register security-core unit tests with CTest"
    ${RQP_SECURITY_CORE_STANDALONE}
)

option(RQP_SECURITY_CORE_ENABLE_COVERAGE
    "Enable gcov coverage instrumentation for library and tests"
    OFF
)

option(RQP_SECURITY_CORE_BUILD_FUZZERS
    "Build libFuzzer targets (requires Clang + -fsanitize=fuzzer)"
    OFF
)

option(RQP_SECURITY_CORE_BUILD_STRESS_TESTS
    "Build performance stress harness (ctest label stress; not run with default unit discovery)"
    ${RQP_SECURITY_CORE_BUILD_TESTS}
)

option(RQP_SECURITY_BACKEND_OSV "Register OSV vulnerability sync backend" ON)
option(RQP_SECURITY_BACKEND_GH_ADVISORY "Register GitHub Advisory sync backend" ON)
option(RQP_SECURITY_BACKEND_SNYK "Register Snyk sync backend" ON)
option(RQP_SECURITY_BACKEND_TRIVY "Register Trivy DB sync backend" ON)

find_package(CURL REQUIRED)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_library(RQP_SECURITY_ZSTD_LIBRARY NAMES zstd REQUIRED)

find_program(RQP_RUSTC rustc)
if(NOT RQP_RUSTC)
    message(FATAL_ERROR "rustc is required to build reqpack-security-core (CycloneDX via rust/cyclonedx_ffi)")
endif()

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.5.1
)
FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(
    MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/rust/cyclonedx_ffi/Cargo.toml
    CRATES rqp_cyclonedx_ffi
)

if(NOT TARGET rqp_cyclonedx_ffi)
    message(FATAL_ERROR "Failed to import rqp_cyclonedx_ffi Rust crate")
endif()

if(NOT TARGET lmdb)
    FetchContent_Declare(
        lmdb
        GIT_REPOSITORY https://github.com/LMDB/lmdb.git
        GIT_TAG LMDB_0.9.33
    )
    FetchContent_GetProperties(lmdb)
    if(NOT lmdb_POPULATED)
        FetchContent_Populate(lmdb)
    endif()
    add_library(lmdb STATIC
        ${lmdb_SOURCE_DIR}/libraries/liblmdb/mdb.c
        ${lmdb_SOURCE_DIR}/libraries/liblmdb/midl.c
    )
    set_target_properties(lmdb PROPERTIES LINKER_LANGUAGE C)
    target_include_directories(lmdb PUBLIC ${lmdb_SOURCE_DIR}/libraries/liblmdb)
endif()

set(RQP_SEC_DOMAIN_SOURCES
    src/domain/json_util.cpp
    src/domain/version/version_compare.cpp
    src/domain/osv/osv_core.cpp
    src/domain/policy/validator_core.cpp
    src/domain/matching/vulnerability_matcher.cpp
)

set(RQP_SEC_APP_SOURCES
    src/app/scan_service.cpp
    src/app/policy_decision_console.cpp
    src/app/sync_gateway_backend_run.cpp
    src/gateway/security_gateway_service.cpp
    src/validator/validator.cpp
    src/validator/validator_prepare.cpp
    src/validator/validator_prompt.cpp
    src/validator/validator_disposition.cpp
    src/matching/sbom_inventory.cpp
    src/exchange/pipeline.cpp
    src/exchange/registry.cpp
    src/exchange/transform_identity.cpp
    src/exchange/transform_scan.cpp
)

set(RQP_SEC_ADAPTER_SOURCES
    src/adapters/detail/sync_common.cpp
    src/adapters/detail/sync_refresh.cpp
    src/adapters/infra/security_paths.cpp
    src/adapters/infra/security_log.cpp
    src/adapters/infra/security_settings.cpp
    src/adapters/infra/security_status.cpp
    src/adapters/infra/security_network.cpp
    src/adapters/infra/security_process.cpp
    src/adapters/infra/pipe_helpers.cpp
    src/adapters/infra/curl_http_client.cpp
    src/adapters/infra/http_util.cpp
    src/adapters/infra/http_download.cpp
    src/adapters/infra/settings_archive_extractor.cpp
    src/adapters/matching/lmdb_ecosystem_advisory_resolver.cpp
    src/adapters/sync/sync_backend_registry.cpp
    src/adapters/sync/sync_backend_support.cpp
    src/adapters/sync/backends/register_builtin_backends.cpp
    src/adapters/database/vulnerability_database_storage.cpp
    src/adapters/database/vulnerability_database.cpp
    src/adapters/sync/vulnerability_sync_service.cpp
    src/exchange/codec_sbom.cpp
    src/exchange/envelope.cpp
    src/adapters/cyclonedx/cyclonedx_service.cpp
)

if(RQP_SECURITY_BACKEND_OSV)
    list(APPEND RQP_SEC_ADAPTER_SOURCES src/adapters/sync/backends/register_osv.cpp)
else()
    message(FATAL_ERROR "RQP_SECURITY_BACKEND_OSV=OFF is not supported (OSV is the default data source)")
endif()

if(RQP_SECURITY_BACKEND_GH_ADVISORY)
    list(APPEND RQP_SEC_ADAPTER_SOURCES
        src/adapters/sync/gh_advisory_vulnerability_sync_service.cpp
        src/adapters/sync/backends/register_gh_advisory.cpp
    )
    list(APPEND RQP_SECURITY_BACKEND_DEFINES RQP_SECURITY_HAVE_BACKEND_GH_ADVISORY)
endif()

if(RQP_SECURITY_BACKEND_SNYK)
    list(APPEND RQP_SEC_ADAPTER_SOURCES
        src/adapters/sync/snyk/snyk_sync_http.cpp
        src/adapters/sync/snyk/snyk_sync_csv.cpp
        src/adapters/sync/snyk/snyk_sync_export.cpp
        src/adapters/sync/snyk/snyk_sync_import.cpp
        src/adapters/sync/snyk/snyk_vulnerability_sync_service.cpp
        src/adapters/sync/backends/register_snyk.cpp
    )
    list(APPEND RQP_SECURITY_BACKEND_DEFINES RQP_SECURITY_HAVE_BACKEND_SNYK)
endif()

if(RQP_SECURITY_BACKEND_TRIVY)
    list(APPEND RQP_SEC_ADAPTER_SOURCES
        src/adapters/sync/trivy/trivy_sync_misc.cpp
        src/adapters/sync/trivy/trivy_sync_http.cpp
        src/adapters/sync/trivy/trivy_sync_oci.cpp
        src/adapters/sync/trivy/trivy_sync_runtime.cpp
        src/adapters/sync/trivy/trivy_sync_import.cpp
        src/adapters/sync/trivy/trivy_vulnerability_sync_service.cpp
        src/adapters/sync/backends/register_trivy.cpp
    )
    list(APPEND RQP_SECURITY_BACKEND_DEFINES RQP_SECURITY_HAVE_BACKEND_TRIVY)
endif()

add_library(rqp_sec_domain OBJECT ${RQP_SEC_DOMAIN_SOURCES})
add_library(rqp_sec_adapters OBJECT ${RQP_SEC_ADAPTER_SOURCES})
add_library(rqp_sec_app OBJECT ${RQP_SEC_APP_SOURCES})

foreach(rqp_sec_layer IN ITEMS rqp_sec_domain rqp_sec_adapters rqp_sec_app)
    target_include_directories(${rqp_sec_layer}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/src/adapters
            ${CMAKE_CURRENT_SOURCE_DIR}/src/validator
    )
    target_compile_definitions(${rqp_sec_layer} PRIVATE ${RQP_SECURITY_BACKEND_DEFINES})
    if(RQP_SECURITY_CORE_ENABLE_COVERAGE OR REQPACK_ENABLE_COVERAGE)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${rqp_sec_layer} PRIVATE -O0 -g --coverage)
            target_link_options(${rqp_sec_layer} PRIVATE --coverage)
        endif()
    endif()
endforeach()

target_link_libraries(rqp_sec_domain PUBLIC Boost::boost)
target_link_libraries(rqp_sec_adapters PUBLIC Boost::boost rqp_sec_domain PRIVATE lmdb)
target_link_libraries(rqp_sec_app PUBLIC Boost::boost rqp_sec_domain rqp_sec_adapters)

add_library(reqpack_security_core STATIC
    $<TARGET_OBJECTS:rqp_sec_domain>
    $<TARGET_OBJECTS:rqp_sec_adapters>
    $<TARGET_OBJECTS:rqp_sec_app>
)
add_library(ReqPack::SecurityCore ALIAS reqpack_security_core)

target_include_directories(reqpack_security_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/adapters
        ${CMAKE_CURRENT_SOURCE_DIR}/src/validator
)

target_link_libraries(reqpack_security_core
    PUBLIC
        CURL::libcurl
        Boost::boost
        OpenSSL::SSL
        OpenSSL::Crypto
        ${RQP_SECURITY_ZSTD_LIBRARY}
        lmdb
    PRIVATE
        rqp_cyclonedx_ffi
)

target_compile_definitions(reqpack_security_core
    PUBLIC
        RQP_SECURITY_CORE_BUILD
    PRIVATE
        ${RQP_SECURITY_BACKEND_DEFINES}
)

if(RQP_SECURITY_CORE_ENABLE_COVERAGE OR REQPACK_ENABLE_COVERAGE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(reqpack_security_core PRIVATE -O0 -g --coverage)
        target_link_options(reqpack_security_core PRIVATE --coverage)
    endif()
endif()

if(RQP_SECURITY_CORE_BUILD_TESTS)
    enable_testing()

    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v2.13.10
    )
    FetchContent_MakeAvailable(Catch2)

    set(RQP_SECURITY_CORE_TEST_SOURCES
        tests/unit/backend_sync_service_tests.cpp
        tests/unit/gh_advisory_vulnerability_sync_service_tests.cpp
        tests/unit/osv_core_tests.cpp
        tests/unit/security_gateway_service_tests.cpp
        tests/unit/security_log_tests.cpp
        tests/unit/security_network_tests.cpp
        tests/unit/security_paths_tests.cpp
        tests/unit/security_settings_tests.cpp
        tests/unit/snyk_sync_service_tests.cpp
        tests/unit/snyk_vulnerability_sync_service_tests.cpp
        tests/unit/trivy_vulnerability_sync_service_tests.cpp
        tests/unit/validator_policy_tests.cpp
        tests/unit/validator_validate_tests.cpp
        tests/unit/version_compare_tests.cpp
        tests/unit/vulnerability_database_tests.cpp
        tests/unit/vulnerability_sync_service_tests.cpp
        tests/unit/sbom_inventory_tests.cpp
        tests/unit/exchange_pipeline_tests.cpp
        tests/unit/matcher_in_memory_tests.cpp
        tests/unit/http_client_sync_port_tests.cpp
    )

    add_executable(security_core_unit_tests
        tests/cpp/test_main.cpp
        ${RQP_SECURITY_CORE_TEST_SOURCES}
    )

    target_include_directories(security_core_unit_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/adapters
    )

    target_link_libraries(security_core_unit_tests PRIVATE
        Catch2::Catch2
        reqpack_security_core
    )

    if(RQP_SECURITY_CORE_ENABLE_COVERAGE OR REQPACK_ENABLE_COVERAGE)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(security_core_unit_tests PRIVATE -O0 -g --coverage)
            target_link_options(security_core_unit_tests PRIVATE --coverage)
        endif()
    endif()

    add_custom_target(security_core_test_targets
        DEPENDS security_core_unit_tests
    )

    include(${catch2_SOURCE_DIR}/contrib/Catch.cmake)
    catch_discover_tests(security_core_unit_tests TEST_PREFIX "security::")

    if(RQP_SECURITY_CORE_BUILD_STRESS_TESTS)
        add_executable(security_core_stress_tests
            tests/stress/stress_main.cpp
            tests/stress/stress_perf_tests.cpp
        )

        target_include_directories(security_core_stress_tests PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/stress
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/src/adapters
        )

        target_link_libraries(security_core_stress_tests PRIVATE
            Catch2::Catch2
            reqpack_security_core
        )

        if(RQP_SECURITY_CORE_ENABLE_COVERAGE OR REQPACK_ENABLE_COVERAGE)
            if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
                target_compile_options(security_core_stress_tests PRIVATE -O0 -g --coverage)
                target_link_options(security_core_stress_tests PRIVATE --coverage)
            endif()
        endif()

        add_dependencies(security_core_test_targets security_core_stress_tests)

        add_test(
            NAME security_stress_perf
            COMMAND security_core_stress_tests
        )
        set_tests_properties(security_stress_perf PROPERTIES
            LABELS "stress"
            TIMEOUT 900
        )
    endif()
endif()

if(RQP_SECURITY_CORE_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "RQP_SECURITY_CORE_BUILD_FUZZERS requires Clang (libFuzzer)")
    endif()

    set(RQP_SECURITY_CORE_FUZZ_TARGETS
        osv_parse_fuzzer
        sbom_import_fuzzer
        exchange_decode_fuzzer
        cyclonedx_emit_fuzzer
        cyclonedx_parse_fuzzer
        snyk_csv_fuzzer
        snyk_export_fuzzer
        trivy_helper_fuzzer
        trivy_ndjson_fuzzer
        trivy_metadata_fuzzer
        trivy_oci_fuzzer
        version_compare_fuzzer
    )

    set(RQP_SECURITY_FUZZ_FLAGS -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g -O1)

    foreach(fuzzer IN LISTS RQP_SECURITY_CORE_FUZZ_TARGETS)
        add_executable(${fuzzer} tests/fuzz/${fuzzer}.cpp)
        target_link_libraries(${fuzzer} PRIVATE reqpack_security_core)
        target_include_directories(${fuzzer} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}/src/adapters
        )
        target_compile_options(${fuzzer} PRIVATE ${RQP_SECURITY_FUZZ_FLAGS})
        target_link_options(${fuzzer} PRIVATE ${RQP_SECURITY_FUZZ_FLAGS})

        string(REGEX REPLACE "_fuzzer$" "" fuzzer_corpus "${fuzzer}")
        set(corpus_dir ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/corpus/${fuzzer_corpus})
        if(EXISTS ${corpus_dir})
            add_test(
                NAME security_fuzz_${fuzzer}
                COMMAND ${fuzzer} -runs=4096 -max_total_time=20 -timeout=5 -rss_limit_mb=512 ${corpus_dir}
            )
        else()
            add_test(
                NAME security_fuzz_${fuzzer}
                COMMAND ${fuzzer} -runs=4096 -max_total_time=20 -timeout=5 -rss_limit_mb=512
            )
        endif()
    endforeach()
endif()

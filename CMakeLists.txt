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

find_package(CURL REQUIRED)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_library(RQP_SECURITY_ZSTD_LIBRARY NAMES zstd REQUIRED)

if(NOT TARGET lmdb)
    include(FetchContent)
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

set(RQP_SECURITY_CORE_SOURCES
    src/security_paths.cpp
    src/security_log.cpp
    src/security_settings.cpp
    src/security_network.cpp
    src/security_process.cpp
    src/pipe_helpers.cpp
    src/version_compare.cpp
    src/gh_advisory_vulnerability_sync_service.cpp
    src/osv_core.cpp
    src/snyk_vulnerability_sync_service.cpp
    src/trivy_vulnerability_sync_service.cpp
    src/security_gateway_service.cpp
    src/validator.cpp
    src/validator_prepare.cpp
    src/validator_prompt.cpp
    src/validator_core.cpp
    src/vulnerability_database.cpp
    src/vulnerability_matcher.cpp
    src/vulnerability_sync_service.cpp
)

add_library(reqpack_security_core STATIC ${RQP_SECURITY_CORE_SOURCES})
add_library(ReqPack::SecurityCore ALIAS reqpack_security_core)

target_include_directories(reqpack_security_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(reqpack_security_core
    PUBLIC
        CURL::libcurl
        Boost::boost
        OpenSSL::SSL
        OpenSSL::Crypto
        ${RQP_SECURITY_ZSTD_LIBRARY}
        lmdb
)

target_compile_definitions(reqpack_security_core
    PUBLIC
        RQP_SECURITY_CORE_BUILD
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
    )

    add_executable(security_core_unit_tests
        tests/cpp/test_main.cpp
        ${RQP_SECURITY_CORE_TEST_SOURCES}
    )

    target_include_directories(security_core_unit_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp
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
endif()

if(RQP_SECURITY_CORE_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "RQP_SECURITY_CORE_BUILD_FUZZERS requires Clang (libFuzzer)")
    endif()

    set(RQP_SECURITY_CORE_FUZZ_TARGETS
        osv_parse_fuzzer
        snyk_csv_fuzzer
        trivy_helper_fuzzer
        version_compare_fuzzer
    )

    set(RQP_SECURITY_FUZZ_FLAGS -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g -O1)

    foreach(fuzzer IN LISTS RQP_SECURITY_CORE_FUZZ_TARGETS)
        add_executable(${fuzzer} tests/fuzz/${fuzzer}.cpp)
        target_link_libraries(${fuzzer} PRIVATE reqpack_security_core)
        target_compile_options(${fuzzer} PRIVATE ${RQP_SECURITY_FUZZ_FLAGS})
        target_link_options(${fuzzer} PRIVATE ${RQP_SECURITY_FUZZ_FLAGS})

        set(corpus_dir ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/corpus/${fuzzer})
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

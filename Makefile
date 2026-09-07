.PHONY: all build test test-unit clean coverage-build test-coverage \
	format format-check lint lint-build fuzz fuzz-build qa

NPROC := $(shell command -v nproc >/dev/null 2>&1 && nproc || sysctl -n hw.ncpu 2>/dev/null || echo 2)
JOBS := $(shell expr $(NPROC) / 4)
COVERAGE_BUILD_DIR := build/coverage
LINT_BUILD_DIR := build/lint
FUZZ_BUILD_DIR := build/fuzz
PYTHON := python3
BADGE_JSON := .github/badges/coverage.json
CLANGXX ?= clang++
FUZZ_RUNS ?= 4096
FUZZ_MAX_TIME ?= 20

all: build

build:
	cmake -S . -B build -DRQP_SECURITY_CORE_BUILD_TESTS=ON
	cmake --build build -j$(JOBS)

test: build
	@ctest --test-dir build --output-on-failure

test-unit: build
	@ctest --test-dir build --output-on-failure -R "^security::"

coverage-build:
	cmake -S . -B $(COVERAGE_BUILD_DIR) \
		-DCMAKE_BUILD_TYPE=Debug \
		-DRQP_SECURITY_CORE_BUILD_TESTS=ON \
		-DRQP_SECURITY_CORE_ENABLE_COVERAGE=ON
	cmake --build $(COVERAGE_BUILD_DIR) -j$(JOBS)

test-coverage: coverage-build
	@ctest --test-dir $(COVERAGE_BUILD_DIR) --output-on-failure
	@$(PYTHON) tests/coverage_summary.py $(COVERAGE_BUILD_DIR) . \
		--badge-json $(BADGE_JSON) | tee coverage-summary.txt

format-check:
	@./scripts/check_clang_format.sh

format:
	@./scripts/format_sources.sh

lint-build:
	cmake -S . -B $(LINT_BUILD_DIR) \
		-DCMAKE_BUILD_TYPE=Debug \
		-DRQP_SECURITY_CORE_BUILD_TESTS=ON \
		-DCMAKE_CXX_COMPILER=$(CLANGXX)
	cmake --build $(LINT_BUILD_DIR) -j$(JOBS) --target reqpack_security_core security_core_unit_tests

lint: lint-build
	@./scripts/run_clang_tidy.sh $(LINT_BUILD_DIR)

fuzz-build:
	cmake -S . -B $(FUZZ_BUILD_DIR) \
		-DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DRQP_SECURITY_CORE_BUILD_TESTS=ON \
		-DRQP_SECURITY_CORE_BUILD_FUZZERS=ON \
		-DCMAKE_CXX_COMPILER=$(CLANGXX)
	cmake --build $(FUZZ_BUILD_DIR) -j$(JOBS)

fuzz: fuzz-build
	@FUZZ_RUNS=$(FUZZ_RUNS) FUZZ_MAX_TIME=$(FUZZ_MAX_TIME) ./scripts/run_fuzzers.sh $(FUZZ_BUILD_DIR)

qa: format-check lint test fuzz

clean:
	@rm -rf build $(COVERAGE_BUILD_DIR) $(LINT_BUILD_DIR) $(FUZZ_BUILD_DIR) coverage-summary.txt

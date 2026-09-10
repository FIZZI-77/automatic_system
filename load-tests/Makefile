REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
POWERSHELL ?= powershell.exe
PS_FLAGS := -NoProfile -ExecutionPolicy Bypass -File

SCENARIO ?= gateway
RATES ?= 10,25,50
BASE_URL ?= http://host.docker.internal:18081
WARMUP ?= 5s
MEASUREMENT ?= 20s
STABILIZATION ?= 5s
NAMESPACE ?= automatic-system
SCENARIO_FILTER ?=

.PHONY: help test vet prepare load load-gateway load-gateway-auth load-auth-login load-auth-refresh load-ticket load-location load-dispatch load-analytics load-services-parallel load-full load-suite load-suite-readonly

help:
	@echo "make -f load-tests/Makefile load SCENARIO=ticket-read RATES=10,25,50"
	@echo "make -f load-tests/Makefile load-suite          # all scenarios, local writes allowed"
	@echo "make -f load-tests/Makefile load-suite-readonly # excludes location writes"
	@echo "make -f load-tests/Makefile load-suite-readonly SCENARIO_FILTER=gateway,analytics"
	@echo "Variables: RATES BASE_URL WARMUP MEASUREMENT STABILIZATION NAMESPACE SCENARIO_FILTER"

test:
	cd "$(REPO_ROOT)" && go test ./load-tests/...

vet:
	cd "$(REPO_ROOT)" && go vet ./load-tests/...

prepare:
	cd "$(REPO_ROOT)" && node load-tests/data/generators/generate.js 77 100

load:
	cd "$(REPO_ROOT)" && $(POWERSHELL) $(PS_FLAGS) load-tests/scripts/run.ps1 -Scenario "$(SCENARIO)" -Rates "$(RATES)" -BaseUrl "$(BASE_URL)" -Warmup "$(WARMUP)" -Measurement "$(MEASUREMENT)" -Stabilization "$(STABILIZATION)" -AllowWrites

load-gateway:
	$(MAKE) -f "$(REPO_ROOT)/load-tests/Makefile" load SCENARIO=gateway RATES="$(RATES)"

load-gateway-auth:
	$(MAKE) -f "$(REPO_ROOT)/load-tests/Makefile" load SCENARIO=gateway-authenticated-read RATES="$(RATES)"

load-auth-login:
	$(MAKE) -f "$(REPO_ROOT)/load-tests/Makefile" load SCENARIO=auth-login RATES="$(RATES)"

load-auth-refresh:
	$(MAKE) -f "$(REPO_ROOT)/load-tests/Makefile" load SCENARIO=auth-refresh RATES="$(RATES)"

load-ticket:
	$(MAKE) -f "$(REPO_ROOT)/load-tests/Makefile" load SCENARIO=ticket-read RATES="$(RATES)"

load-location:
	$(MAKE) -f "$(REPO_ROOT)/load-tests/Makefile" load SCENARIO=location RATES="$(RATES)"

load-dispatch:
	$(MAKE) -f "$(REPO_ROOT)/load-tests/Makefile" load SCENARIO=dispatch-preview RATES="$(RATES)"

load-analytics:
	$(MAKE) -f "$(REPO_ROOT)/load-tests/Makefile" load SCENARIO=analytics RATES="$(RATES)"

load-services-parallel:
	$(MAKE) -f "$(REPO_ROOT)/load-tests/Makefile" load SCENARIO=services-parallel RATES="$(RATES)"

load-full:
	$(MAKE) -f "$(REPO_ROOT)/load-tests/Makefile" load SCENARIO=full RATES="$(RATES)"

load-suite:
	cd "$(REPO_ROOT)" && $(POWERSHELL) $(PS_FLAGS) load-tests/scripts/run-local-suite.ps1 -Namespace "$(NAMESPACE)" -Warmup "$(WARMUP)" -Measurement "$(MEASUREMENT)" -Stabilization "$(STABILIZATION)" -ScenarioFilter "$(SCENARIO_FILTER)" -ParallelRates "$(RATES)" -AllowWrites

load-suite-readonly:
	cd "$(REPO_ROOT)" && $(POWERSHELL) $(PS_FLAGS) load-tests/scripts/run-local-suite.ps1 -Namespace "$(NAMESPACE)" -Warmup "$(WARMUP)" -Measurement "$(MEASUREMENT)" -Stabilization "$(STABILIZATION)" -ScenarioFilter "$(SCENARIO_FILTER)" -ParallelRates "$(RATES)"

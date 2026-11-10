# Commands are implemented in scripts/project.ps1; no Bash/WSL is required.
.DEFAULT_GOAL := help
.NOTPARALLEL:

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ifeq ($(OS),Windows_NT)
SHELL := cmd.exe
POWERSHELL ?= pwsh.exe
else
POWERSHELL ?= pwsh
endif

ENV ?= local
SERVICE ?= all
NAMESPACE ?=
CONTEXT ?=
DRY_RUN ?= 0
IMAGE_TAG ?=
MIGRATOR_TAG ?=
SKIP_BUILD ?= 0
SKIP_IMPORT ?= 0
SKIP_MIGRATIONS ?= 0
SKIP_SEED ?= 1
HEADED ?= 0
INCLUDE_SMTP ?= 0
FOLLOW ?= 0
TAIL ?= 100
TEST_FILE ?=
GATEWAY_URL ?=
BASE_URL ?= http://localhost:8081
PUBLIC_URL ?= https://fizzi.tail2c9430.ts.net
USERNAME ?= admin
SCALE ?= 1000
SCENARIO ?= gateway
RATES ?= 10,25,50
WARMUP ?= 5s
MEASUREMENT ?= 20s
STABILIZATION ?= 5s
SCENARIO_FILTER ?=
ALLOW_WRITES ?= 0
EXECUTE ?= 0
RACE ?= 0
TEST_RUN ?=

# Values travel through the environment, not through shell command strings.
OPTIONS := ENV SERVICE NAMESPACE CONTEXT DRY_RUN IMAGE_TAG MIGRATOR_TAG \
 SKIP_BUILD SKIP_IMPORT SKIP_MIGRATIONS SKIP_SEED HEADED INCLUDE_SMTP FOLLOW \
 TAIL TEST_FILE GATEWAY_URL BASE_URL PUBLIC_URL USERNAME SCALE SCENARIO RATES \
 WARMUP MEASUREMENT STABILIZATION SCENARIO_FILTER ALLOW_WRITES EXECUTE RACE TEST_RUN
$(foreach option,$(OPTIONS),$(eval export ACS_$(option) = $$($(option))))

TASKS := help doctor bootstrap deps-go deps-frontend go-build fmt fmt-check vet test \
 test-unit test-integration test-compile test-tools lint check frontend-dev frontend-build \
 frontend-test frontend-lint frontend-typecheck test-inventory test-api test-ui \
 test-ui-ha test-report up down compose-config compose-status compose-logs \
 simulation-up build deploy deploy-local deploy-ha deploy-infra deploy-apps \
 cluster-check cluster-status status logs rollout-status cluster-verify \
 cluster-delete mesh-install metrics-install ingress-setup flux-install \
 flux-sync flux-status observability observability-password pgadmin-setup \
 funnel-setup dashboards-generate dashboards-import kibana-setup transponders-apply \
 seed seed-analytics openapi openapi-check manifests-render helm-check \
 docs-context load-prepare load load-suite test-chaos test-k6-chaos

.PHONY: $(TASKS)
deploy-local: ENV=local
deploy-ha deploy-infra test-ui-ha test-chaos test-k6-chaos: ENV=local-ha
$(TASKS):
	@"$(POWERSHELL)" -NoProfile -ExecutionPolicy Bypass -File "$(ROOT)/scripts/project.ps1" -Task "$@"

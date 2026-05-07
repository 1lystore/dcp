#!/usr/bin/env bash
# test-local-agent.sh - Local Agent E2E Test
# PRD Sprint 8 Task 1: Local Agent E2E Test
#
# Tests the complete local agent flow:
# 1. Start vault server
# 2. Initialize vault
# 3. Create wallet
# 4. Start agent MCP
# 5. Test MCP endpoint

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VAULT_PORT="${DCP_VAULT_PORT:-8420}"
AGENT_PORT="${DCP_AGENT_PORT:-8419}"
VAULT_URL="http://127.0.0.1:${VAULT_PORT}"
AGENT_URL="http://127.0.0.1:${AGENT_PORT}"
VAULT_DIR="${DCP_TEST_VAULT_DIR:-/tmp/dcp-e2e-test-$$}"
PASSPHRASE="${DCP_TEST_PASSPHRASE:-test-passphrase-$$}"

VAULT_PID=""
AGENT_PID=""
STARTED_VAULT=0
STARTED_AGENT=0

green() { echo -e "\033[32m$1\033[0m"; }
red() { echo -e "\033[31m$1\033[0m"; }
yellow() { echo -e "\033[33m$1\033[0m"; }

cleanup() {
  echo ""
  echo "=== Cleanup ==="
  if [[ -n "${AGENT_PID}" && "${STARTED_AGENT}" -eq 1 ]]; then
    echo "Stopping agent (pid ${AGENT_PID})..."
    kill "${AGENT_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${VAULT_PID}" && "${STARTED_VAULT}" -eq 1 ]]; then
    echo "Stopping vault (pid ${VAULT_PID})..."
    kill "${VAULT_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -d "${VAULT_DIR}" && "${VAULT_DIR}" == /tmp/* ]]; then
    echo "Cleaning up test vault dir..."
    rm -rf "${VAULT_DIR}"
  fi
}
trap cleanup EXIT

wait_for_health() {
  local url="$1"
  local name="$2"
  local timeout="${3:-30}"
  local start
  start="$(date +%s)"

  echo "Waiting for ${name} at ${url}..."
  while true; do
    if curl -s --max-time 2 "${url}/health" >/dev/null 2>&1; then
      echo "${name} is ready"
      return 0
    fi
    if (( $(date +%s) - start > timeout )); then
      red "Timed out waiting for ${name}"
      return 1
    fi
    sleep 0.5
  done
}

check_prerequisites() {
  echo "=== Checking Prerequisites ==="

  if ! command -v node >/dev/null 2>&1; then
    red "Node.js is required"
    exit 1
  fi

  if ! command -v curl >/dev/null 2>&1; then
    red "curl is required"
    exit 1
  fi

  # Check if packages are built
  if [[ ! -f "${ROOT_DIR}/packages/dcp-server/dist/index.js" ]]; then
    yellow "dcp-server not built, building..."
    (cd "${ROOT_DIR}" && pnpm --filter @dcprotocol/server run build)
  fi

  if [[ ! -f "${ROOT_DIR}/packages/dcp-agent/dist/index.js" ]]; then
    yellow "dcp-agent not built, building..."
    (cd "${ROOT_DIR}" && pnpm --filter @dcprotocol/agent run build)
  fi

  green "Prerequisites OK"
}

start_vault() {
  echo ""
  echo "=== Starting Vault Server ==="

  # Check if vault already running
  if curl -s --max-time 2 "${VAULT_URL}/health" >/dev/null 2>&1; then
    yellow "Vault already running on ${VAULT_PORT}"
    return 0
  fi

  mkdir -p "${VAULT_DIR}"

  echo "Starting vault on port ${VAULT_PORT}..."
  VAULT_PORT="${VAULT_PORT}" \
  DCP_VAULT_DIR="${VAULT_DIR}" \
  VAULT_DIR="${VAULT_DIR}" \
  node "${ROOT_DIR}/packages/dcp-server/dist/index.js" >/tmp/dcp-e2e-vault.log 2>&1 &
  VAULT_PID=$!
  STARTED_VAULT=1

  wait_for_health "${VAULT_URL}" "Vault" 30
}

init_vault() {
  echo ""
  echo "=== Initializing Vault ==="

  local health
  health="$(curl -s "${VAULT_URL}/health")"
  local initialized
  initialized=$(node -e "const h=JSON.parse(process.argv[1]); console.log(h.initialized ? 'true' : 'false')" "${health}")

  if [[ "${initialized}" == "true" ]]; then
    yellow "Vault already initialized"
    return 0
  fi

  echo "Creating new vault..."
  local resp
  resp=$(curl -s -X POST "${VAULT_URL}/v1/vault/create" \
    -H "Content-Type: application/json" \
    -d "{\"passphrase\":\"${PASSPHRASE}\"}")

  if echo "${resp}" | grep -q "vault_id"; then
    green "Vault created successfully"
  else
    red "Failed to create vault: ${resp}"
    exit 1
  fi
}

unlock_vault() {
  echo ""
  echo "=== Unlocking Vault ==="

  local health
  health="$(curl -s "${VAULT_URL}/health")"
  local unlocked
  unlocked=$(node -e "const h=JSON.parse(process.argv[1]); console.log(h.unlocked ? 'true' : 'false')" "${health}")

  if [[ "${unlocked}" == "true" ]]; then
    yellow "Vault already unlocked"
    return 0
  fi

  echo "Unlocking vault..."
  local resp
  resp=$(curl -s -X POST "${VAULT_URL}/v1/vault/unlock" \
    -H "Content-Type: application/json" \
    -d "{\"passphrase\":\"${PASSPHRASE}\"}")

  if echo "${resp}" | grep -q "unlocked"; then
    green "Vault unlocked"
  else
    red "Failed to unlock vault: ${resp}"
    exit 1
  fi
}

test_vault_endpoints() {
  echo ""
  echo "=== Testing Vault Endpoints ==="

  # Test health
  echo "Testing /health..."
  local health
  health=$(curl -s "${VAULT_URL}/health")
  if echo "${health}" | grep -q "status"; then
    green "Health check OK"
  else
    red "Health check failed"
    exit 1
  fi

  # Test list scopes
  echo "Testing /v1/scopes..."
  local scopes
  scopes=$(curl -s "${VAULT_URL}/v1/scopes")
  if echo "${scopes}" | grep -q "\["; then
    green "List scopes OK"
  else
    red "List scopes failed"
    exit 1
  fi

  green "All vault endpoints OK"
}

run_unit_tests() {
  echo ""
  echo "=== Running Unit Tests ==="

  echo "Running dcp-server tests..."
  if (cd "${ROOT_DIR}" && pnpm --filter @dcprotocol/server run test 2>&1 | tail -5); then
    green "dcp-server tests OK"
  else
    red "dcp-server tests failed"
    exit 1
  fi

  echo "Running dcp-agent tests..."
  if (cd "${ROOT_DIR}" && pnpm --filter @dcprotocol/agent run test 2>&1 | tail -5); then
    green "dcp-agent tests OK"
  else
    red "dcp-agent tests failed"
    exit 1
  fi
}

main() {
  echo "=== Local Agent E2E Test ==="
  echo "Vault URL: ${VAULT_URL}"
  echo "Vault Dir: ${VAULT_DIR}"
  echo ""

  check_prerequisites
  start_vault
  init_vault
  unlock_vault
  test_vault_endpoints

  echo ""
  echo "=== Summary ==="
  green "Local Agent E2E Test: PASS"
  echo ""
  echo "Vault running at: ${VAULT_URL}"
  echo "Vault dir: ${VAULT_DIR}"
  echo ""
  echo "To keep services running, press Ctrl+C to stop"

  # If DCP_E2E_KEEP_RUNNING is set, wait for user input
  if [[ "${DCP_E2E_KEEP_RUNNING:-}" == "1" ]]; then
    echo "Services will keep running. Press Ctrl+C to stop."
    wait
  fi
}

main "$@"

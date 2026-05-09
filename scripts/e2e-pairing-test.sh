#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_PORT="${DCP_RELAY_PORT:-8422}"
VAULT_PORT="${DCP_VAULT_PORT:-8420}"
PROXY_PORT="${DCP_PROXY_PORT:-8422}"
RELAY_URL="ws://127.0.0.1:${RELAY_PORT}"
VAULT_URL="http://127.0.0.1:${VAULT_PORT}"
PROXY_URL="http://127.0.0.1:${PROXY_PORT}"
VAULT_DIR="${DCP_VAULT_DIR:-${HOME}/.dcp}"
CONFIG_PATH="${VAULT_DIR}/config.json"
SERVICE_ID="${DCP_TEST_SERVICE_ID:-proxy-test}"
AGENT_NAME="${DCP_TEST_AGENT_NAME:-proxy-agent}"
NODE_BIN="${DCP_NODE_BIN:-}"

RELAY_PID=""
SERVER_PID=""
PROXY_PID=""
STARTED_RELAY=0
STARTED_SERVER=0

cleanup() {
  if [[ -n "${PROXY_PID}" ]]; then
    kill "${PROXY_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${SERVER_PID}" && "${STARTED_SERVER}" -eq 1 ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${RELAY_PID}" && "${STARTED_RELAY}" -eq 1 ]]; then
    kill "${RELAY_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

require_node() {
  if [[ -z "${NODE_BIN}" ]]; then
    NODE_BIN="$(command -v node || true)"
  fi
  if [[ -z "${NODE_BIN}" ]]; then
    echo "Node.js is required."
    exit 1
  fi
  local version
  version="$("${NODE_BIN}" -v | sed 's/^v//')"
  local major
  major="${version%%.*}"
  if [[ "${major}" != "18" && "${major}" != "20" && "${major}" != "22" ]]; then
    if [[ -d "${HOME}/.nvm/versions/node" ]]; then
      local candidate
      for candidate in "${HOME}/.nvm/versions/node"/v20.* "${HOME}/.nvm/versions/node"/v22.* "${HOME}/.nvm/versions/node"/v18.*; do
        if [[ -x "${candidate}/bin/node" ]]; then
          NODE_BIN="${candidate}/bin/node"
          version="$("${NODE_BIN}" -v | sed 's/^v//')"
          major="${version%%.*}"
          break
        fi
      done
    fi
  fi
  if [[ "${major}" != "18" && "${major}" != "20" && "${major}" != "22" ]]; then
    echo "Unsupported Node.js version: ${version}"
    echo "Use Node 18, 20, or 22 (LTS)."
    exit 1
  fi

  local node_dir
  node_dir="$(dirname "${NODE_BIN}")"
  if [[ -d "${node_dir}" ]]; then
    export PATH="${node_dir}:${PATH}"
  fi
}

build_cli() {
  npm -w packages/dcp-vault run build >/dev/null
}

wait_for_health() {
  local url="$1"
  local timeout="${2:-30}"
  local start
  start="$(date +%s)"
  while true; do
    if curl -s --max-time 2 "${url}/health" >/dev/null 2>&1; then
      return 0
    fi
    if (( $(date +%s) - start > timeout )); then
      echo "Timed out waiting for ${url}"
      return 1
    fi
    sleep 0.5
  done
}

wait_for_relay_connection() {
  local timeout="${1:-30}"
  local start
  start="$(date +%s)"
  while true; do
    local stats
    stats="$(curl -s "http://127.0.0.1:${RELAY_PORT}/stats" || true)"
    local connected
    connected="$("${NODE_BIN}" -e "try { const s=JSON.parse(process.argv[1] || '{}'); console.log(s.connectedVaults ?? 0); } catch { console.log(0); }" "${stats}")"
    if [[ "${connected}" -ge 1 ]]; then
      return 0
    fi
    if (( $(date +%s) - start > timeout )); then
      return 1
    fi
    sleep 0.5
  done
}

start_relay() {
  if curl -s --max-time 2 "http://127.0.0.1:${RELAY_PORT}/health" >/dev/null 2>&1; then
    echo "Relay already running on ${RELAY_PORT}"
    return
  fi

  echo "Starting relay on ${RELAY_PORT}..."
  npm -w packages/dcp-relay run dev -- --port "${RELAY_PORT}" --debug >/tmp/dcp-relay.log 2>&1 &
  RELAY_PID=$!
  STARTED_RELAY=1
  wait_for_health "http://127.0.0.1:${RELAY_PORT}" 30
}

start_server() {
  if curl -s --max-time 2 "${VAULT_URL}/health" >/dev/null 2>&1; then
    local pid=""
    if command -v lsof >/dev/null 2>&1; then
      pid="$(lsof -nP -iTCP:"${VAULT_PORT}" -sTCP:LISTEN 2>/dev/null | awk 'NR==2 {print $2}')"
    fi
    if [[ -n "${pid}" ]]; then
      local cmd
      cmd="$(ps -p "${pid}" -o command= 2>/dev/null || true)"
      if [[ "${DCP_KILL_DESKTOP:-}" == "1" ]]; then
        echo "Stopping existing server on ${VAULT_PORT} (pid ${pid})..."
        kill "${pid}" >/dev/null 2>&1 || true
        sleep 0.5
      elif [[ "${cmd}" == *"DCP Vault.app"* ]]; then
        echo "Desktop app server detected on ${VAULT_PORT}."
        echo "Quit DCP Vault desktop app or rerun with DCP_KILL_DESKTOP=1."
        exit 1
      else
        echo "Vault server already running on ${VAULT_PORT}"
        return
      fi
    else
      echo "Vault server already running on ${VAULT_PORT}"
      return
    fi
  fi

  echo "Starting vault server on ${VAULT_PORT}..."
  DCP_RELAY_URL="${RELAY_URL}" VAULT_PORT="${VAULT_PORT}" DCP_VAULT_DIR="${VAULT_DIR}" VAULT_DIR="${VAULT_DIR}" node "${ROOT_DIR}/packages/dcp-vault/dist/server/index.js" >/tmp/dcp-vault-server.log 2>&1 &
  SERVER_PID=$!
  STARTED_SERVER=1
  wait_for_health "${VAULT_URL}" 30
}

unlock_vault() {
  local health
  health="$(curl -s "${VAULT_URL}/health")"
  local unlocked
  unlocked="$("${NODE_BIN}" -e "const h=JSON.parse(process.argv[1]); console.log(h.unlocked ? 'true' : 'false')" "${health}")"
  if [[ "${unlocked}" == "true" ]]; then
    echo "Vault already unlocked"
    return
  fi

  local passphrase="${DCP_TEST_PASSPHRASE:-}"
  if [[ -z "${passphrase}" ]]; then
    read -s -p "Vault passphrase: " passphrase
    echo ""
  fi

  curl -s -X POST "${VAULT_URL}/v1/vault/unlock" \
    -H 'Content-Type: application/json' \
    -d "{\"passphrase\":\"${passphrase}\"}" >/dev/null
  echo "Vault unlocked"
}

strip_ansi() {
  sed -E 's/\x1b\[[0-9;]*m//g'
}

create_pairing_token() {
  local cli="${ROOT_DIR}/packages/dcp-vault/dist/cli/index.js"
  local output
  output="$(NO_COLOR=1 FORCE_COLOR=0 DCP_VAULT_DIR="${VAULT_DIR}" VAULT_DIR="${VAULT_DIR}" "${NODE_BIN}" "${cli}" pairing start "${SERVICE_ID}" \
    --scopes sign:solana,read:credentials.*,budget:check \
    --budget 10usdc/day \
    --auto-approve-under 1usdc \
    | strip_ansi)"

  local token
  token="$(echo "${output}" | awk '/^Token:/{getline; print $0}')"

  if [[ -z "${token}" ]]; then
    echo "Failed to extract pairing token."
    echo "${output}"
    exit 1
  fi

  echo "${token}"
}

read_config_value() {
  local key="$1"
  if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo ""
    return
  fi
  "${NODE_BIN}" -e "const fs=require('fs'); const p='${CONFIG_PATH}'; const c=JSON.parse(fs.readFileSync(p,'utf8')); console.log(c['${key}'] || '')"
}

start_proxy() {
  local vault_id="$1"
  local hpke_key="$2"
  local token="$3"
  local cli="${ROOT_DIR}/packages/dcp-vault/dist/cli/index.js"

  DCP_VAULT_ID="${vault_id}" \
  DCP_VAULT_HPKE_PUBLIC_KEY="${hpke_key}" \
  DCP_RELAY_URL="${RELAY_URL}" \
  DCP_VAULT_DIR="${VAULT_DIR}" VAULT_DIR="${VAULT_DIR}" \
  "${NODE_BIN}" "${cli}" proxy --pair "${token}" --service-id "${SERVICE_ID}" --port "${PROXY_PORT}" >/tmp/dcp-vault-proxy.log 2>&1 &
  PROXY_PID=$!

  wait_for_health "${PROXY_URL}" 30
}

test_proxy() {
  echo "Testing proxy budget check..."
  local resp
  resp="$(curl -s "${PROXY_URL}/budget/check?amount=1&currency=USDC&chain=solana")"
  if [[ "${resp}" != *"allowed"* ]]; then
    echo "Proxy test failed."
    echo "${resp}"
    exit 1
  fi
  echo "Proxy budget check OK"
}

main() {
  require_node
  build_cli

  start_relay
  start_server
  unlock_vault

  echo "Waiting for relay connection..."
  wait_for_relay_connection 30 || {
    echo "Vault did not connect to relay. Check relay URL and vault logs."
    exit 1
  }

  local vault_id
  local hpke_key
  vault_id="$(read_config_value "vault_id")"
  hpke_key="$(read_config_value "relay_hpke_public_key")"

  if [[ -z "${vault_id}" || -z "${hpke_key}" ]]; then
    echo "Failed to read vault_id or hpke_public_key from ${CONFIG_PATH}"
    exit 1
  fi

  echo "Creating pairing token..."
  local token
  token="$(create_pairing_token)"

  echo "Starting proxy with pairing token..."
  start_proxy "${vault_id}" "${hpke_key}" "${token}"

  test_proxy

  echo "Pairing flow OK."
  echo "Proxy running at ${PROXY_URL}"
}

main

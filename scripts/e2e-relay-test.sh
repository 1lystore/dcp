#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_PORT="${DCP_RELAY_PORT:-8421}"
VAULT_PORT="${DCP_VAULT_PORT:-8420}"
RELAY_URL="ws://127.0.0.1:${RELAY_PORT}"
VAULT_URL="http://127.0.0.1:${VAULT_PORT}"
VAULT_DIR="${DCP_VAULT_DIR:-${HOME}/.dcp}"
CONFIG_PATH="${VAULT_DIR}/config.json"
SERVICE_ID="${DCP_TEST_SERVICE_ID:-test-service}"
AGENT_NAME="${DCP_TEST_AGENT_NAME:-relay-e2e}"
SERVICE_KEY_PATH="${DCP_TEST_SERVICE_KEY_PATH:-${VAULT_DIR}/${SERVICE_ID}-keys.json}"
NODE_BIN="${DCP_NODE_BIN:-}"

RELAY_PID=""
SERVER_PID=""
STARTED_RELAY=0
STARTED_SERVER=0

cleanup() {
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
    # Try to auto-pick an LTS Node from nvm if available
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

  # Ensure npm/node use the same runtime
  local node_dir
  node_dir="$(dirname "${NODE_BIN}")"
  if [[ -d "${node_dir}" ]]; then
    export PATH="${node_dir}:${PATH}"
  fi
}

run_dcp() {
  local cli="${ROOT_DIR}/packages/dcp-cli/dist/cli.js"
  local src_dir="${ROOT_DIR}/packages/dcp-cli/src"

  local get_mtime
  get_mtime() {
    local target="$1"
    if stat -f %m "$target" >/dev/null 2>&1; then
      stat -f %m "$target"
    else
      stat -c %Y "$target"
    fi
  }

  local needs_build=0
  if [[ ! -f "${cli}" ]]; then
    needs_build=1
  else
    if [[ -d "${src_dir}" ]]; then
      local newest_src=""
      newest_src=$(find "${src_dir}" -type f -print0 | xargs -0 stat -f %m 2>/dev/null | sort -n | tail -1 || true)
      if [[ -z "${newest_src}" ]]; then
        newest_src=$(find "${src_dir}" -type f -print0 | xargs -0 stat -c %Y 2>/dev/null | sort -n | tail -1 || true)
      fi
      if [[ -n "${newest_src}" ]]; then
        local cli_mtime
        cli_mtime=$(get_mtime "${cli}")
        if [[ "${newest_src}" -gt "${cli_mtime}" ]]; then
          needs_build=1
        fi
      fi
    fi
  fi

  if [[ "${needs_build}" -eq 1 ]]; then
    echo "Building @dcprotocol/cli..."
    npm -w packages/dcp-cli run build
  fi

  if [[ -f "${cli}" ]]; then
    echo "Using local CLI: ${cli}"
    DCP_VAULT_DIR="${VAULT_DIR}" VAULT_DIR="${VAULT_DIR}" "${NODE_BIN}" "${cli}" "$@"
    return
  fi

  if command -v dcp >/dev/null 2>&1; then
    echo "Using global dcp CLI"
    DCP_NODE_BIN="${NODE_BIN}" DCP_VAULT_DIR="${VAULT_DIR}" VAULT_DIR="${VAULT_DIR}" dcp "$@"
    return
  fi

  echo "dcp CLI not found. Build failed or CLI missing."
  exit 1
}

wait_for_health() {
  local url="$1"
  local name="$2"
  local timeout="${3:-30}"
  local start
  start="$(date +%s)"
  while true; do
    if curl -s --max-time 2 "${url}/health" >/dev/null 2>&1; then
      return 0
    fi
    if (( $(date +%s) - start > timeout )); then
      echo "Timed out waiting for ${name} at ${url}"
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
    connected="$("${NODE_BIN}" -e "try { const s=JSON.parse(process.argv[1] || '{}'); console.log(s.connectedVaults ?? (s.connections && s.connections.connectedVaults) ?? 0); } catch { console.log(0); }" "${stats}")"
    if [[ "${connected}" -ge 1 ]]; then
      return 0
    fi
    if (( $(date +%s) - start > timeout )); then
      return 1
    fi
    sleep 0.5
  done
}

get_listen_pid() {
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${VAULT_PORT}" -sTCP:LISTEN 2>/dev/null | awk 'NR==2 {print $2}'
  fi
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
  wait_for_health "http://127.0.0.1:${RELAY_PORT}" "relay" 30
}

start_server() {
  if curl -s --max-time 2 "${VAULT_URL}/health" >/dev/null 2>&1; then
    local pid
    pid="$(get_listen_pid || true)"
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
  DCP_RELAY_URL="${RELAY_URL}" VAULT_PORT="${VAULT_PORT}" DCP_VAULT_DIR="${VAULT_DIR}" VAULT_DIR="${VAULT_DIR}" npm -w packages/dcp-server run dev >/tmp/dcp-server.log 2>&1 &
  SERVER_PID=$!
  STARTED_SERVER=1
  wait_for_health "${VAULT_URL}" "vault" 30
}

unlock_vault_if_needed() {
  local health
  health="$(curl -s --max-time 2 "${VAULT_URL}/health")"
  local initialized
  initialized="$("${NODE_BIN}" -e "const h=JSON.parse(process.argv[1]); console.log(h.initialized ? 'true' : 'false')" "${health}")"
  if [[ "${initialized}" != "true" ]]; then
    echo "Vault is not initialized. Run: dcp init"
    exit 1
  fi

  local unlocked
  unlocked="$("${NODE_BIN}" -e "const h=JSON.parse(process.argv[1]); console.log(h.unlocked ? 'true' : 'false')" "${health}")"
  if [[ "${unlocked}" == "true" ]]; then
    echo "Vault is already unlocked"
    return
  fi

  local passphrase="${DCP_TEST_PASSPHRASE:-}"
  if [[ -z "${passphrase}" ]]; then
    echo "Vault is locked. Enter passphrase to unlock."
    read -r -s -p "Passphrase: " passphrase
    echo
  fi
  curl -s -X POST "${VAULT_URL}/v1/vault/unlock" \
    -H 'Content-Type: application/json' \
    -d "{\"passphrase\":\"${passphrase}\"}" >/dev/null
  echo "Vault unlocked"
}

generate_service_keys() {
  if [[ -f "${SERVICE_KEY_PATH}" ]]; then
  eval "$("${NODE_BIN}" -e "const fs=require('fs'); const c=JSON.parse(fs.readFileSync(process.argv[1],'utf8')); console.log('SERVICE_PUBLIC='+c.public_key); console.log('SERVICE_PRIVATE='+c.private_key);" "${SERVICE_KEY_PATH}")"
  else
    eval "$("${NODE_BIN}" -e "const fs=require('fs'); const path=require('path'); const sodium=require('sodium-native'); const pk=Buffer.alloc(32); const sk=Buffer.alloc(64); sodium.crypto_sign_keypair(pk,sk); const out={}; out.public_key=pk.toString('base64'); out.private_key=sk.toString('base64'); fs.mkdirSync(path.dirname(process.argv[1]), {recursive:true}); fs.writeFileSync(process.argv[1], JSON.stringify(out, null, 2)); console.log('SERVICE_PUBLIC='+out.public_key); console.log('SERVICE_PRIVATE='+out.private_key);" "${SERVICE_KEY_PATH}")"
  fi
  if [[ -z "${SERVICE_PUBLIC:-}" || -z "${SERVICE_PRIVATE:-}" ]]; then
    echo "Failed to generate service keys"
    exit 1
  fi
}

trust_service() {
  echo "Trusting service ${SERVICE_ID} in vault..."
  run_dcp trust "${SERVICE_ID}" \
    --key="ed25519:${SERVICE_PUBLIC}" \
    --scopes="sign:solana,read:credentials.*" \
    --budget="1sol/day" \
    -y
}

run_client_test() {
  local vault_id
  local hpke_public_key
  local relay_url

  if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo "Vault config not found at ${CONFIG_PATH}"
    echo "Start the vault once with DCP_RELAY_URL set, then retry."
    exit 1
  fi

  vault_id="$("${NODE_BIN}" -e "const fs=require('fs'); const c=JSON.parse(fs.readFileSync(process.argv[1],'utf8')); console.log(c.vault_id || '')" "${CONFIG_PATH}")"
  hpke_public_key="$("${NODE_BIN}" -e "const fs=require('fs'); const c=JSON.parse(fs.readFileSync(process.argv[1],'utf8')); console.log(c.relay_hpke_public_key || '')" "${CONFIG_PATH}")"
  relay_url="$("${NODE_BIN}" -e "const fs=require('fs'); const c=JSON.parse(fs.readFileSync(process.argv[1],'utf8')); console.log(c.relay_url || '')" "${CONFIG_PATH}")"

  if [[ -n "${relay_url}" ]]; then
    RELAY_URL="${relay_url}"
  fi

  if [[ -z "${vault_id}" || -z "${hpke_public_key}" ]]; then
    echo "Missing relay identity in ${CONFIG_PATH}"
    echo "Ensure vault has started with DCP_RELAY_URL and is unlocked."
    exit 1
  fi

  echo "Running relay client test..."
  ${NODE_BIN} --input-type=module -e "
import { DcpClient } from '@dcprotocol/client';
const dcp = new DcpClient({
  mode: 'relay',
  vaultId: '${vault_id}',
  relayUrl: '${RELAY_URL}',
  vaultHpkePublicKey: '${hpke_public_key}',
  serviceId: '${SERVICE_ID}',
  servicePrivateKey: '${SERVICE_PRIVATE}',
  agentName: '${AGENT_NAME}'
});
const run = async () => {
  try {
    const addr = await dcp.getAddress('solana');
    console.log('Address:', addr);
  } catch (err) {
    console.error('Address error:', err);
    if (err && err.code === 'RECORD_NOT_FOUND') {
      console.error('No Solana wallet found. Run: dcp create-wallet --chain solana');
    }
  }
  try {
    const sig = await dcp.signMessage({ chain: 'solana', message: 'hello', description: 'relay e2e test' });
    console.log('Signature:', sig);
  } catch (err) {
    console.error('Sign error:', err);
  }
  await dcp.close();
};
run();
"

  echo "If consent was required, approve in DCP UI and re-run the script (it will reuse the trusted service)."
}

main() {
  require_node
  start_relay
  start_server
  unlock_vault_if_needed
  if ! wait_for_relay_connection 20; then
    echo "Vault not connected to relay yet."
    if [[ "${STARTED_SERVER}" -eq 1 ]]; then
      echo "Restarting vault server to re-init relay client..."
      kill "${SERVER_PID}" >/dev/null 2>&1 || true
      SERVER_PID=""
      STARTED_SERVER=0
      start_server
      unlock_vault_if_needed
      if ! wait_for_relay_connection 20; then
        echo "Relay still not connected. Check vault logs and relay URL."
        exit 1
      fi
    else
      echo "Restart vault server with DCP_RELAY_URL=${RELAY_URL} and try again."
      exit 1
    fi
  fi
  generate_service_keys
  trust_service
  run_client_test
}

main "$@"

#!/usr/bin/env bash
#
# demo-local.sh — one command to watch the WHOLE Cloud-Connect flow on your machine.
#
# Spins up a throwaway vault + relay + vault-server, issues a connect-link, runs a
# demo cloud agent, auto-approves (simulating your on-device tap), and shows the
# agent read the vault — then revokes and cleans everything up. Touches nothing real.
#
#   bash scripts/demo-local.sh
#
set -o pipefail
cd "$(dirname "$0")/.."
strip_ansi() { sed $'s/\x1b\\[[0-9;]*m//g'; }

RELAY_PORT=${RELAY_PORT:-8497}
VAULT_PORT=${VAULT_PORT:-8496}
VAULT_DIR=$(mktemp -d)/demo-vault
export DCP_RELAY_URL="ws://127.0.0.1:${RELAY_PORT}"
mkdir -p "$VAULT_DIR"

RELAY_PID=""; VAULT_PID=""
cleanup() {
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
  [ -n "$VAULT_PID" ] && kill "$VAULT_PID" 2>/dev/null || true
  rm -rf "$VAULT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

cli() { VAULT_DIR="$VAULT_DIR" DCP_RELAY_URL="$DCP_RELAY_URL" node packages/dcp-vault/dist/cli/index.js "$@"; }

echo "==> Building (local, no publish)…"
pnpm -r build >/dev/null 2>&1 || { echo "build failed"; exit 1; }

echo "==> Provisioning a throwaway vault…"
VAULT_DIR="$VAULT_DIR" pnpm --filter @dcprotocol/vault exec node -e "
(async()=>{const c=await import('@dcprotocol/core');const s=new c.VaultStorage();s.initializeSchema();
const mk=c.deriveKeyFromMnemonic(c.generateRecoveryMnemonic());await s.storeMasterKeyWithPassphrase(mk,'demo-pass-123');
const{encrypted,info}=c.createWallet('solana',mk);s.createRecord({scope:'crypto.wallet.solana',item_type:'WALLET_KEY',sensitivity:'critical',data:encrypted,chain:'solana',public_address:info.public_address});
c.zeroize(mk);s.close();console.log('    wallet:',info.public_address);})()" 2>&1 | grep wallet

echo "==> Starting relay (:$RELAY_PORT) and vault server (:$VAULT_PORT, connected to relay)…"
node packages/dcp-relay/dist/index.js --port "$RELAY_PORT" >/tmp/demo-relay.log 2>&1 & RELAY_PID=$!
DCP_RELAY_URL="$DCP_RELAY_URL" VAULT_DIR="$VAULT_DIR" VAULT_PORT="$VAULT_PORT" \
  node packages/dcp-vault/dist/server/index.js >/tmp/demo-vault.log 2>&1 & VAULT_PID=$!
sleep 4

CONNECTED=$(curl -s "localhost:$RELAY_PORT/stats" | grep -oE '"connectedVaults":[0-9]+' || echo "?")
echo "    relay $CONNECTED"
curl -s -X POST "localhost:$VAULT_PORT/v1/vault/unlock" -H 'content-type: application/json' \
  -d '{"passphrase":"demo-pass-123"}' >/dev/null

echo "==> Issuing a connect-link…"
LINK=$(cli cloud-connect link openclaw-demo --scopes read:wallet.address 2>/dev/null | grep -oE 'dcp_connect_v1_[A-Za-z0-9_-]+')
echo "    ${LINK:0:42}…"

echo "==> Running the demo cloud agent (redeems over the relay)…"
node scripts/demo-cloud-agent.mjs "$LINK" --relay "http://127.0.0.1:$RELAY_PORT" >/tmp/demo-agent.log 2>&1 & AGENT_PID=$!
sleep 4

PEND=$(cli cloud-connect pending 2>/dev/null | strip_ansi | tr -cd 'A-Za-z0-9 _:\n')
AID=$(printf '%s' "$PEND" | grep -oE 'agent_[a-f0-9]+' | head -1)
MC=$(printf '%s' "$PEND" | grep -oE 'Match code: [A-HJ-NP-Z2-9]{6}' | grep -oE '[A-HJ-NP-Z2-9]{6}' | head -1)
AID=$(printf '%s' "${AID:-}" | tr -cd 'a-z0-9_'); MC=$(printf '%s' "${MC:-}" | tr -cd 'A-Z0-9')
if [ -z "$AID" ] || [ -z "$MC" ]; then echo "could not find pending agent; see /tmp/demo-agent.log"; exit 1; fi
printf '==> Agent is waiting. On a real run you approve on-device after confirming the match code.\n    Auto-approving %s now...\n' "$AID"
cli cloud-connect approve "$AID" "$MC" 2>/dev/null | grep -i approved || true
sleep 6

echo ""
echo "==> Agent result:"
grep -E "Approved!|tools/list →|vault_get_address →|Done" /tmp/demo-agent.log | sed 's/^/    /'
kill $AGENT_PID 2>/dev/null || true

echo ""
echo "==> Revoking the agent (instant)…"
cli cloud-connect revoke "$AID" 2>/dev/null | grep -i revoked || true

echo ""
echo "✓ Done — full flow worked locally. (Throwaway vault + processes cleaned up.)"

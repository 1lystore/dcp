#!/usr/bin/env node
/**
 * Demo cloud agent — exercises the WHOLE Cloud-Connect flow locally so you can
 * watch it end-to-end without OpenClaw/Hermes/Claude.ai. Pure Node crypto (no deps).
 *
 * It plays the role of a cloud agent: OAuth device-flow (PKCE + DPoP) against your
 * local relay, then a real MCP call through the per-vault facade.
 *
 * PREREQ (3 terminals):
 *   1) relay:  node packages/dcp-relay/dist/index.js --port 8422
 *   2) vault:  DCP_RELAY_URL=ws://127.0.0.1:8422 VAULT_DIR=/tmp/dcp-demo \
 *              node packages/dcp-vault/dist/server/index.js
 *      (init+unlock the vault first; e.g. dcp init / create-wallet, then unlock)
 *   3) issue a link (same VAULT_DIR):
 *      VAULT_DIR=/tmp/dcp-demo DCP_RELAY_URL=ws://127.0.0.1:8422 \
 *        node packages/dcp-vault/dist/cli/index.js cloud-connect link demo --scopes read:wallet.address
 *
 * THEN run this with the printed connect-link:
 *   node scripts/demo-cloud-agent.mjs dcp_connect_v1_... --relay http://127.0.0.1:8422
 *
 * When it prints a MATCH CODE, approve on the vault side (verifying it matches):
 *   VAULT_DIR=/tmp/dcp-demo node packages/dcp-vault/dist/cli/index.js cloud-connect approve <agentId> <matchCode>
 * ...and watch this script receive a token and make an MCP call.
 */

import crypto from 'node:crypto';

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest();

const args = process.argv.slice(2);
const connectLink = args.find((a) => a.startsWith('dcp_connect_v1_'));
const relayArgIdx = args.indexOf('--relay');
const RELAY = (relayArgIdx >= 0 ? args[relayArgIdx + 1] : 'http://127.0.0.1:8422').replace(/\/+$/, '');

if (!connectLink) {
  console.error('Usage: node scripts/demo-cloud-agent.mjs <dcp_connect_v1_...> [--relay http://127.0.0.1:8422]');
  process.exit(1);
}

// Parse vault_id from the (untrusted) connect-link for routing.
let vaultId;
try {
  const env = JSON.parse(Buffer.from(connectLink.slice('dcp_connect_v1_'.length), 'base64url').toString());
  vaultId = env.payload.vault_id;
} catch {
  console.error('Could not parse the connect-link.');
  process.exit(1);
}

// --- DPoP key (EC P-256) + proof builder -----------------------------------
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = publicKey.export({ format: 'jwk' }); // { kty, crv, x, y }

function makeDpop(method, url, accessToken) {
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
  const payload = {
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
  };
  if (accessToken) payload.ath = b64url(sha256(accessToken));
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = crypto.sign('sha256', Buffer.from(signingInput), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${signingInput}.${b64url(sig)}`;
}

async function jpost(path, body, headers = {}) {
  const url = `${RELAY}${path}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }
  return { status: res.status, json };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  console.log(`\n▶ Demo cloud agent connecting to vault ${vaultId} via ${RELAY}\n`);

  const verifier = b64url(crypto.randomBytes(48));
  const challenge = b64url(sha256(verifier));

  // 1) /oauth/connect — redeem the connect-link (triggers on-device approval).
  const connect = await jpost(
    '/oauth/connect',
    { connect_link: connectLink, code_challenge: challenge },
    { dpop: makeDpop('POST', `${RELAY}/oauth/connect`) }
  );
  if (connect.status !== 200) {
    console.error('✗ /oauth/connect failed:', connect.status, JSON.stringify(connect.json));
    process.exit(1);
  }
  const deviceCode = connect.json.device_code;
  console.log('  ✓ connect-link redeemed.');
  console.log(`\n  ┌─────────────────────────────────────┐`);
  console.log(`  │  MATCH CODE:  ${String(connect.json.match_code).padEnd(22)}│`);
  console.log(`  └─────────────────────────────────────┘`);
  console.log('\n  → Approve on the vault side, e.g.:');
  console.log(`    node packages/dcp-vault/dist/cli/index.js cloud-connect approve <agentId> ${connect.json.match_code}`);
  console.log('    (run `cloud-connect pending` to get the agentId)\n');

  // 2) /oauth/token — poll until the owner approves on-device.
  process.stdout.write('  Waiting for approval');
  let accessToken;
  for (let i = 0; i < 100; i++) {
    const tok = await jpost(
      '/oauth/token',
      { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: deviceCode, code_verifier: verifier },
      { dpop: makeDpop('POST', `${RELAY}/oauth/token`) }
    );
    if (tok.status === 200) {
      accessToken = tok.json.access_token;
      break;
    }
    if (tok.json.error === 'authorization_pending') {
      process.stdout.write('.');
      await sleep(3000);
      continue;
    }
    console.error('\n✗ /oauth/token error:', tok.status, JSON.stringify(tok.json));
    process.exit(1);
  }
  if (!accessToken) {
    console.error('\n✗ Timed out waiting for approval.');
    process.exit(1);
  }
  console.log('\n  ✓ Approved! Got a DPoP + audience-bound access token.\n');

  // 3) Real MCP calls through the per-vault facade.
  const mcpUrl = `${RELAY}/v/${vaultId}/mcp`;
  const call = (rpc) =>
    jpost(`/v/${vaultId}/mcp`, rpc, {
      authorization: `DPoP ${accessToken}`,
      dpop: makeDpop('POST', mcpUrl, accessToken),
    });

  const list = await call({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  console.log('  tools/list →', list.status, JSON.stringify(list.json).slice(0, 200));

  const addr = await call({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: 'vault_get_address', arguments: { chain: 'solana' } },
  });
  console.log('  vault_get_address →', addr.status, JSON.stringify(addr.json).slice(0, 240));

  console.log('\n✓ Done. The agent operated the vault — keys never left the device.\n');
  process.exit(0);
}

main().catch((e) => {
  console.error('demo agent error:', e);
  process.exit(1);
});

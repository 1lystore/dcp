# @dcprotocol/client

Universal SDK for connecting an agent or service to a DCP vault.

Use this package when you want your code to talk to DCP directly instead of going through MCP.

## Install

```bash
npm install @dcprotocol/client
```

## When To Use It

Use `@dcprotocol/client` when:
- your agent runs on the same machine as the vault
- your service talks to a vault through the relay
- you need DCP from a custom framework or app
- you want one SDK for address lookup, signing, data reads, writes, and budget checks

Do **not** use direct relay mode if you do not want the agent process to hold a service identity key. In that case, run `dcp-proxy` from `@dcprotocol/proxy` on the remote machine and let the agent talk to localhost.

Examples below use the default public relay `wss://relay.dcp.1ly.store`. You can replace that with any compatible self-hosted relay.

## Quick Start

### Local-first agent

```ts
import { DcpClient } from '@dcprotocol/client';

const dcp = new DcpClient({
  mode: 'auto',
  agentName: 'openclaw-local',
});

const { address } = await dcp.getAddress('solana');
const signed = await dcp.signMessage({
  chain: 'solana',
  message: 'hello',
});
```

`mode: 'auto'` tries a local vault first. If local is unavailable and relay configuration is present, it falls back to relay mode.

### Direct relay mode

```ts
import { DcpClient } from '@dcprotocol/client';

const dcp = new DcpClient({
  mode: 'relay',
  vaultId: process.env.DCP_VAULT_ID,
  relayUrl: process.env.DCP_RELAY_URL,
  vaultHpkePublicKey: process.env.DCP_VAULT_HPKE_PUBLIC_KEY,
  serviceId: process.env.DCP_SERVICE_ID,
  servicePrivateKey: process.env.DCP_SERVICE_PRIVATE_KEY,
  agentName: 'my-remote-service',
});

const result = await dcp.signTx({
  chain: 'solana',
  unsignedTx: '<base64-transaction>',
  amount: '1',
  currency: 'SOL',
  description: 'Swap 1 SOL for USDC',
});
```

### Pairing a remote proxy

This is used by `dcp-proxy --pair ...` and by any infrastructure that needs to turn a pairing token into a trusted proxy identity.

```ts
import { DcpClient, generateSigningKeyPair } from '@dcprotocol/client';

const keys = generateSigningKeyPair();

const dcp = new DcpClient({
  mode: 'relay',
  vaultId: process.env.DCP_VAULT_ID,
  relayUrl: process.env.DCP_RELAY_URL,
  vaultHpkePublicKey: process.env.DCP_VAULT_HPKE_PUBLIC_KEY,
  serviceId: 'openclaw-vps',
  servicePrivateKey: keys.privateKey.toString('base64'),
});

await dcp.pairService({
  pairingToken: process.env.DCP_PAIRING_TOKEN!,
  servicePublicKey: `ed25519:${keys.publicKey.toString('base64')}`,
  serviceName: 'OpenClaw VPS',
});
```

## Configuration

### Constructor

```ts
new DcpClient({
  mode?: 'auto' | 'local' | 'relay',
  localUrl?: string,
  localCheckTimeoutMs?: number,
  timeoutMs?: number,
  vaultId?: string,
  relayUrl?: string,
  vaultHpkePublicKey?: string,
  serviceId?: string,
  servicePrivateKey?: string,
  agentId?: string,
  agentName?: string,
})
```

### Environment variable fallbacks

| Variable | Used for |
| --- | --- |
| `DCP_MODE` | `auto`, `local`, or `relay` |
| `DCP_URL` | Local vault URL |
| `DCP_VAULT_ID` | Relay target vault |
| `DCP_RELAY_URL` | Relay endpoint |
| `DCP_VAULT_HPKE_PUBLIC_KEY` | Vault relay encryption public key |
| `DCP_SERVICE_ID` | Service/proxy identity |
| `DCP_SERVICE_PRIVATE_KEY` | Service Ed25519 private key |
| `MCP_AGENT_NAME` | Default agent name |

## Supported Operations

| Method | Purpose |
| --- | --- |
| `isAvailable()` | Check whether the vault can be reached |
| `getAddress(chain)` | Return the public wallet address for a chain |
| `signTx(input)` | Sign a transaction inside the vault |
| `signMessage(input)` | Sign a message inside the vault |
| `signTypedData(input)` | Sign EIP-712 typed data |
| `signX402(input)` | Sign an x402 payment payload |
| `readCredential(scope, fields?)` | Read credential or data scopes |
| `readData(scope, fields?)` | Alias for `readCredential` |
| `writeCredential(scope, data)` | Write allowed data scopes |
| `budgetCheck(input)` | Check a budget before attempting a sign |
| `pairService(input)` | Pair a remote service/proxy with a vault |
| `clearSession()` | Drop cached consent session IDs |
| `close()` | Close sockets and zeroize local key material |

## Error Handling

The SDK throws `DcpError` for vault- and relay-specific failures.

Common codes:

| Code | Meaning | Typical action |
| --- | --- | --- |
| `VAULT_LOCKED` | Local or remote vault is locked | Unlock the vault |
| `VAULT_OFFLINE` | Relay target is not connected | Start/open the vault |
| `CONSENT_REQUIRED` | User must approve this request | Ask the user to approve in DCP |
| `CONSENT_DENIED` | User denied the request | Stop and surface the denial |
| `BUDGET_EXCEEDED_TX` | Per-transaction limit exceeded | Lower amount or raise policy |
| `BUDGET_EXCEEDED_DAILY` | Daily limit exceeded | Wait/reset or change budget |
| `RECORD_NOT_FOUND` | Requested scope is missing | Ask user to create/store it |
| `INVALID_CONFIG` | Required relay or local config missing | Fix env/config before retry |

Example:

```ts
import { DcpClient, DcpError } from '@dcprotocol/client';

try {
  await dcp.signMessage({ chain: 'solana', message: 'hello' });
} catch (err) {
  if (err instanceof DcpError && err.code === 'CONSENT_REQUIRED') {
    console.error('Approve the request in DCP, then retry.');
  }
  throw err;
}
```

## Notes For Integrators

- Critical secrets never leave the vault.
- Relay mode authenticates the caller with a service identity key.
- If you want remote agents to avoid holding that key directly, run `dcp-proxy` from `@dcprotocol/proxy` and point the agent to `http://127.0.0.1:<port>` instead.
- Call `close()` when your process shuts down.

## Requirements

- Node.js `>=18 <23`
- For local mode, the DCP server must be reachable at `http://127.0.0.1:8420` unless you override `localUrl`
- For relay mode, the vault must be connected to a relay and trusted for your service identity

## Related Docs

- Root: `README.md`
- CLI operator flows: `packages/dcp-cli/README.md`
- Desktop user flows: `packages/dcp-desktop/README.md`

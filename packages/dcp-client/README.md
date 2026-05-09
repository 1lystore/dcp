# @dcprotocol/client

TypeScript client for talking to a DCP vault.

Most agent developers should start with `@dcprotocol/agent`. Use this package when you are building a custom runtime, service, or app that needs direct vault calls.

## Install

```bash
npm install @dcprotocol/client
```

## Local Vault

```ts
import { DcpClient } from '@dcprotocol/client';

const client = new DcpClient({
  mode: 'local',
  vaultUrl: 'http://127.0.0.1:8420',
  agentName: 'my_agent',
});

const health = await client.health();
console.log(health);
```

## Relay Vault

Use relay mode when an agent has pairing credentials from DCP Desktop.

```ts
import { DcpClient } from '@dcprotocol/client';

const client = new DcpClient({
  mode: 'relay',
  relayUrl: 'wss://relay.example.com',
  vaultId: 'vault_...',
  serviceId: 'agent_...',
  servicePrivateKey: 'base64-ed25519-private-key',
});
```

## What It Handles

- local vault HTTP calls
- relay-backed vault calls
- typed request and response handling
- agent identity fields used by the vault

The vault still owns policy, approvals, wallet signing, and secret storage.

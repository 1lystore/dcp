# @dcprotocol/relay-client

Relay client for DCP - connects local vaults to the relay with HPKE encryption.

This is the **vault-side** relay connector. It is used by the DCP server or any custom vault process that must stay connected to a relay.

If you are building an agent or service that wants to call a vault, use `@dcprotocol/client` instead.

## Overview

The DCP Relay Client enables local vaults to connect to the DCP Relay server, receiving and responding to encrypted requests from cloud MCP clients. It handles:

- HPKE encryption/decryption (X25519 + ChaCha20-Poly1305)
- WebSocket connection management
- Automatic reconnection with exponential backoff + jitter
- Heartbeat keep-alive (30 seconds)

## Features

- **HPKE Encryption**: Forward-secret encryption using ephemeral keys
- **Auto-Reconnect**: Exponential backoff from 1s to 60s with jitter
- **Heartbeat**: 30-second keep-alive to detect connection issues
- **Event-Driven**: Subscribe to connection events
- **Memory Safe**: Cryptographic key material is zeroized after use

## Installation

```bash
npm install @dcprotocol/relay-client
```

## Quick Start

```typescript
import {
  RelayClient,
  generateKeyPair,
  generateSigningKeyPair,
  createRelayClient,
} from '@dcprotocol/relay-client';

// Generate HPKE keypair for the vault
const keyPair = await generateKeyPair();
const signingKeyPair = generateSigningKeyPair();

// Create client
const client = createRelayClient(
  'wss://relay.example.com',
  'vault_abc123',
  keyPair,
  signingKeyPair,
  { debug: true }
);

// Set request handler
client.setRequestHandler(async (action, decryptedPayload) => {
  console.log('Received:', action, decryptedPayload.toString());

  // Example: read requester public key from payload
  const parsed = JSON.parse(decryptedPayload.toString());
  const requesterPublicKey = Buffer.from(parsed.reply_public_key, 'base64');

  // Process request and return encrypted response
  const response = Buffer.from(JSON.stringify({ success: true }));
  return { payload: response, recipientPublicKey: requesterPublicKey };
});

// Subscribe to events
client.on('connected', () => console.log('Connected to relay'));
client.on('disconnected', (reason) => console.log('Disconnected:', reason));
client.on('reconnecting', (attempt, delayMs) => {
  console.log(`Reconnecting in ${delayMs}ms (attempt ${attempt})`);
});
client.on('error', (err) => console.error('Error:', err));

// Connect
await client.connect();

// Get public key to share with clients
const publicKey = client.getPublicKey();
console.log('Vault public key:', publicKey);

// Cleanup on shutdown
process.on('SIGINT', () => client.destroy());
```

## HPKE Encryption

The client uses HPKE (Hybrid Public Key Encryption) with:
- **Key Exchange**: X25519 (Curve25519)
- **AEAD**: ChaCha20-Poly1305
- **KDF**: HKDF-SHA256

### Encrypt a Message

```typescript
import { encrypt, encodeToBase64, generateKeyPair } from '@dcprotocol/relay-client';

const recipientKeyPair = await generateKeyPair();
const plaintext = Buffer.from('Hello, World!');

// Encrypt to recipient's public key
const encrypted = await encrypt(plaintext, recipientKeyPair.publicKey);
const base64 = encodeToBase64(encrypted);
```

### Decrypt a Message

```typescript
import { decrypt, decodeFromBase64 } from '@dcprotocol/relay-client';

const encrypted = decodeFromBase64(base64);
const plaintext = await decrypt(encrypted, recipientKeyPair.privateKey);
console.log(plaintext.toString()); // 'Hello, World!'
```

## API Reference

### RelayClient

```typescript
class RelayClient {
  // Connection
  connect(): Promise<void>;
  disconnect(): void;
  destroy(): void;

  // State
  getState(): ClientState; // 'disconnected' | 'connecting' | 'connected' | 'reconnecting'
  isConnected(): boolean;

  // Encryption
  getPublicKey(): string;
  encryptPayload(plaintext: Buffer, recipientPublicKey: Buffer): Promise<string>;
  decryptPayload(encryptedBase64: string): Promise<Buffer>;

  // Request handling
  setRequestHandler(handler: RequestHandler): void;

  // Events
  on(event: 'connected', callback: () => void): void;
  on(event: 'disconnected', callback: (reason: string) => void): void;
  on(event: 'reconnecting', callback: (attempt: number, delayMs: number) => void): void;
  on(event: 'error', callback: (error: Error) => void): void;
  on(event: 'request', callback: (envelope: RelayEnvelope) => void): void;
}
```

### RequestHandler

```typescript
type RequestHandler = (
  action: ActionType,
  decryptedPayload: Buffer
) => Promise<{ payload: Buffer; recipientPublicKey: Buffer }>;
```

### Configuration

```typescript
interface RelayClientConfig {
  relayUrl: string;         // Relay server URL
  vaultId: string;          // Vault identifier
  keyPair: HpkeKeyPair;     // HPKE keypair
  signingKeyPair: SigningKeyPair; // Ed25519 signing keypair (relay auth)
  pairingToken?: string;    // Optional vault pairing token for relay registration
  autoReconnect: boolean;   // Default: true
  reconnectMinMs: number;   // Default: 1000
  reconnectMaxMs: number;   // Default: 60000
  heartbeatIntervalMs: number; // Default: 30000
  debug: boolean;           // Default: false
}
```

### Crypto Functions

```typescript
// Key generation
function generateKeyPair(): HpkeKeyPair;

// Encryption
function encrypt(plaintext: Buffer, recipientPublicKey: Buffer): EncryptedMessage;
function decrypt(encrypted: EncryptedMessage, privateKey: Buffer): Buffer;

// Serialization
function serializeEncrypted(encrypted: EncryptedMessage): Buffer;
function deserializeEncrypted(data: Buffer): EncryptedMessage;
function encodeToBase64(encrypted: EncryptedMessage): string;
function decodeFromBase64(base64: string): EncryptedMessage;

// Key utilities
function encodePublicKey(publicKey: Buffer): string;
function decodePublicKey(base64: string): Buffer;
function zeroize(buffer: Buffer): void;
```

## Error Codes

| Code | Description |
|------|-------------|
| `CLIENT_NOT_CONNECTED` | Client is not connected |
| `CLIENT_ALREADY_CONNECTED` | Client is already connected |
| `CLIENT_CONNECTION_FAILED` | Failed to connect |
| `CLIENT_ENCRYPTION_FAILED` | Encryption failed |
| `CLIENT_DECRYPTION_FAILED` | Decryption failed |
| `CLIENT_INVALID_KEY` | Invalid key format or size |

## Reconnection Logic

The client implements exponential backoff with jitter:

```
delay = min(maxDelay, minDelay * 2^attempt) + random(0, 0.25 * baseDelay)
```

Example progression:
- Attempt 1: ~1s
- Attempt 2: ~2s
- Attempt 3: ~4s
- Attempt 4: ~8s
- Attempt 5: ~16s
- ...
- Max: ~60s

## Security Notes

1. **Private keys are never exported** - Only public keys are shared
2. **Ephemeral keys for forward secrecy** - Each encryption uses a fresh keypair
3. **Memory zeroization** - Sensitive buffers are cleared after use
4. **No key logging** - Debug mode never logs key material

## Typical Use

- `@dcprotocol/vault` uses this package to connect a local vault to a relay
- `@dcprotocol/desktop` bundles this for the desktop app's relay connection
- A custom desktop or headless vault can use it directly
- It is not intended to be the primary package for agent developers (use `@dcprotocol/agent` instead)

## License

Apache-2.0

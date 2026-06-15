import { describe, it, expect } from 'vitest';
import { randomBytes } from 'crypto';
import {
  createConnectLink,
  decodeConnectLink,
  verifyConnectLinkWithKey,
  isConnectLink,
  hpkeFingerprint,
  formatFingerprint,
  generateMatchCode,
  hashConnectLinkSecret,
  CONNECT_LINK_PREFIX,
  MATCH_CODE_LENGTH,
  generateSigningKeyPair,
  type CreateConnectLinkInput,
} from '../src/index.js';

function makeInput(overrides: Partial<CreateConnectLinkInput> = {}): {
  input: CreateConnectLinkInput;
  signingPublicKey: Buffer;
  signingPrivateKey: Buffer;
  hpke: string;
} {
  const keys = generateSigningKeyPair();
  const hpke = randomBytes(32).toString('base64');
  const input: CreateConnectLinkInput = {
    vault_id: 'vault_test',
    agent_id: 'agent_test',
    agent_name: 'openclaw-aws',
    mode: 'mcp',
    relay_url: 'wss://relay.example/v/vault_test/mcp',
    vault_hpke_public_key: hpke,
    vault_signing_public_key: keys.publicKey.toString('base64'),
    ...overrides,
  };
  return { input, signingPublicKey: keys.publicKey, signingPrivateKey: keys.privateKey, hpke };
}

describe('Connect-link codec', () => {
  it('creates a prefixed, recognizable token', () => {
    const { input, signingPrivateKey } = makeInput();
    const link = createConnectLink(input, signingPrivateKey);
    expect(link.token.startsWith(CONNECT_LINK_PREFIX)).toBe(true);
    expect(isConnectLink(link.token)).toBe(true);
    expect(isConnectLink('dcp_pair_v1_xxx')).toBe(false);
  });

  it('pins the HPKE key and computes a matching fingerprint', () => {
    const { input, signingPrivateKey, hpke } = makeInput();
    const link = createConnectLink(input, signingPrivateKey);
    const decoded = decodeConnectLink(link.token)!;
    expect(decoded.payload.vault_hpke_public_key).toBe(hpke);
    expect(decoded.payload.vault_hpke_fingerprint).toBe(hpkeFingerprint(hpke));
    expect(link.vault_hpke_fingerprint).toBe(hpkeFingerprint(hpke));
  });

  it('verifies with the correct signing key and rejects the wrong key', () => {
    const { input, signingPrivateKey, signingPublicKey } = makeInput();
    const link = createConnectLink(input, signingPrivateKey);
    const verified = verifyConnectLinkWithKey(link.token, signingPublicKey);
    expect(verified).not.toBeNull();
    expect(verified!.link_id).toBe(link.link_id);
    expect(verified!.vault_id).toBe('vault_test');

    const otherKey = generateSigningKeyPair().publicKey;
    expect(verifyConnectLinkWithKey(link.token, otherKey)).toBeNull();
  });

  it('rejects a tampered pinned key (signature no longer matches)', () => {
    const { input, signingPrivateKey, signingPublicKey } = makeInput();
    const link = createConnectLink(input, signingPrivateKey);
    const decoded = decodeConnectLink(link.token)!;
    // Attacker swaps the pinned HPKE key but cannot re-sign.
    decoded.payload.vault_hpke_public_key = randomBytes(32).toString('base64');
    const tampered =
      CONNECT_LINK_PREFIX + Buffer.from(JSON.stringify(decoded), 'utf8').toString('base64url');
    expect(verifyConnectLinkWithKey(tampered, signingPublicKey)).toBeNull();
  });

  it('rejects an expired link', () => {
    const { input, signingPrivateKey, signingPublicKey } = makeInput();
    const link = createConnectLink({ ...input, ttl_ms: -1000 }, signingPrivateKey);
    // decode (no expiry gate) still works, but verify rejects it.
    expect(decodeConnectLink(link.token)).not.toBeNull();
    expect(verifyConnectLinkWithKey(link.token, signingPublicKey)).toBeNull();
  });

  it('carries a high-entropy secret that hashes deterministically', () => {
    const { input, signingPrivateKey } = makeInput();
    const link = createConnectLink(input, signingPrivateKey);
    const decoded = decodeConnectLink(link.token)!;
    expect(decoded.payload.secret).toBe(link.secret);
    expect(link.secret.length).toBeGreaterThanOrEqual(40);
    expect(hashConnectLinkSecret(link.secret)).toBe(hashConnectLinkSecret(decoded.payload.secret));
  });

  it('returns null for malformed tokens', () => {
    expect(decodeConnectLink('not-a-link')).toBeNull();
    expect(decodeConnectLink(CONNECT_LINK_PREFIX + 'garbage')).toBeNull();
    expect(verifyConnectLinkWithKey('not-a-link', randomBytes(32))).toBeNull();
  });
});

describe('hpkeFingerprint', () => {
  it('is deterministic and 64 hex chars', () => {
    const key = randomBytes(32).toString('base64');
    const fp = hpkeFingerprint(key);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
    expect(hpkeFingerprint(key)).toBe(fp);
  });

  it('differs for different keys and formats for display', () => {
    const a = hpkeFingerprint(randomBytes(32).toString('base64'));
    const b = hpkeFingerprint(randomBytes(32).toString('base64'));
    expect(a).not.toBe(b);
    expect(formatFingerprint(a)).toMatch(/^[0-9a-f]{4}( [0-9a-f]{4}){3}$/);
  });
});

describe('generateMatchCode', () => {
  it('has the right length and uses only the unambiguous alphabet', () => {
    const code = generateMatchCode();
    expect(code).toHaveLength(MATCH_CODE_LENGTH);
    // No 0/O/1/I/L (ambiguous) and uppercase only.
    expect(code).toMatch(/^[2-9A-HJ-NP-Z]{6}$/);
  });

  it('is not constant across many draws (CSPRNG)', () => {
    const codes = new Set(Array.from({ length: 50 }, () => generateMatchCode()));
    // Astronomically unlikely to collide to a single value; expect high variety.
    expect(codes.size).toBeGreaterThan(40);
  });
});

import { describe, it, expect } from 'vitest';
import {
  generateVerificationPhrase,
  parsePairingInvite,
  generateAgentKeypair,
  relayHttpUrl,
  VPS_INVITE_PREFIX,
} from '../src/pairing.js';

describe('Pairing', () => {
  describe('generateVerificationPhrase', () => {
    it('should generate deterministic phrase from same inputs', () => {
      const publicKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);
      const inviteId = 'inv_test123';

      const phrase1 = generateVerificationPhrase(publicKey, inviteId);
      const phrase2 = generateVerificationPhrase(publicKey, inviteId);

      expect(phrase1).toBe(phrase2);
    });

    it('should generate different phrases for different public keys', () => {
      const publicKey1 = new Uint8Array(32).fill(1);
      const publicKey2 = new Uint8Array(32).fill(2);
      const inviteId = 'inv_test123';

      const phrase1 = generateVerificationPhrase(publicKey1, inviteId);
      const phrase2 = generateVerificationPhrase(publicKey2, inviteId);

      expect(phrase1).not.toBe(phrase2);
    });

    it('should generate different phrases for different invite IDs', () => {
      const publicKey = new Uint8Array(32).fill(1);
      const inviteId1 = 'inv_test1';
      const inviteId2 = 'inv_test2';

      const phrase1 = generateVerificationPhrase(publicKey, inviteId1);
      const phrase2 = generateVerificationPhrase(publicKey, inviteId2);

      expect(phrase1).not.toBe(phrase2);
    });

    it('should generate 3-word hyphenated phrase', () => {
      const publicKey = new Uint8Array(32).fill(1);
      const inviteId = 'inv_test123';

      const phrase = generateVerificationPhrase(publicKey, inviteId);
      const words = phrase.split('-');

      expect(words).toHaveLength(3);
      expect(words.every((w) => w.length > 0)).toBe(true);
    });

    it('should work with base64 string public key', () => {
      const publicKeyBytes = new Uint8Array(32).fill(1);
      const publicKeyBase64 = Buffer.from(publicKeyBytes).toString('base64');
      const inviteId = 'inv_test123';

      const phrase1 = generateVerificationPhrase(publicKeyBytes, inviteId);
      const phrase2 = generateVerificationPhrase(publicKeyBase64, inviteId);

      expect(phrase1).toBe(phrase2);
    });
  });

  describe('parsePairingInvite', () => {
    it('should reject invites without correct prefix', () => {
      expect(() => parsePairingInvite('invalid_invite')).toThrow(`must start with ${VPS_INVITE_PREFIX}`);
    });

    it('should parse valid VPS invite', () => {
      const data = {
        version: 1,
        invite_id: 'inv_test123',
        vault_id: 'vault_abc',
        relay_url: 'wss://relay.example.com',
        vault_public_key: 'dGVzdC1wdWJsaWMta2V5',
        vault_signing_key: 'dGVzdC1zaWduaW5nLWtleQ',
        expires_at: Date.now() + 60000, // 1 minute from now
      };
      const encoded = Buffer.from(JSON.stringify(data)).toString('base64url');
      const invite = `${VPS_INVITE_PREFIX}${encoded}`;

      const parsed = parsePairingInvite(invite);

      expect(parsed.invite_id).toBe('inv_test123');
      expect(parsed.vault_id).toBe('vault_abc');
      expect(parsed.relay_url).toBe('wss://relay.example.com');
      expect(parsed.vault_public_key).toBe('dGVzdC1wdWJsaWMta2V5');
      expect(parsed.vault_signing_key).toBe('dGVzdC1zaWduaW5nLWtleQ');
    });

    it('should reject expired invites', () => {
      const data = {
        version: 1,
        invite_id: 'inv_test123',
        vault_id: 'vault_abc',
        relay_url: 'wss://relay.example.com',
        vault_public_key: 'dGVzdC1wdWJsaWMta2V5',
        vault_signing_key: 'dGVzdC1zaWduaW5nLWtleQ',
        expires_at: Date.now() - 60000, // 1 minute ago (expired)
      };
      const encoded = Buffer.from(JSON.stringify(data)).toString('base64url');
      const invite = `${VPS_INVITE_PREFIX}${encoded}`;

      expect(() => parsePairingInvite(invite)).toThrow('expired');
    });

    it('should reject invites with missing fields', () => {
      const data = {
        version: 1,
        invite_id: 'inv_test123',
        // missing vault_id, relay_url, vault_public_key, vault_signing_key, expires_at
      };
      const encoded = Buffer.from(JSON.stringify(data)).toString('base64url');
      const invite = `${VPS_INVITE_PREFIX}${encoded}`;

      expect(() => parsePairingInvite(invite)).toThrow('malformed data');
    });

    it('should reject malformed invite data', () => {
      const invite = `${VPS_INVITE_PREFIX}not-valid-base64!!!`;

      expect(() => parsePairingInvite(invite)).toThrow();
    });

    it('should reject old dcp_pair_v1_ format', () => {
      expect(() => parsePairingInvite('dcp_pair_v1_abc123')).toThrow(`must start with ${VPS_INVITE_PREFIX}`);
    });
  });

  describe('generateAgentKeypair', () => {
    it('should generate valid Ed25519 keypair', () => {
      const { privateKey, publicKey } = generateAgentKeypair();

      expect(privateKey).toBeInstanceOf(Uint8Array);
      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(privateKey.length).toBe(64);
      expect(publicKey.length).toBe(32);
    });

    it('should generate unique keypairs', () => {
      const keypair1 = generateAgentKeypair();
      const keypair2 = generateAgentKeypair();

      expect(Buffer.from(keypair1.privateKey)).not.toEqual(Buffer.from(keypair2.privateKey));
      expect(Buffer.from(keypair1.publicKey)).not.toEqual(Buffer.from(keypair2.publicKey));
    });
  });

  describe('relayHttpUrl', () => {
    it('should convert websocket relay URLs to HTTP URLs for REST pairing endpoints', () => {
      expect(relayHttpUrl('wss://relay.example.com')).toBe('https://relay.example.com');
      expect(relayHttpUrl('ws://localhost:8787/ws')).toBe('http://localhost:8787');
      expect(relayHttpUrl('https://relay.example.com/')).toBe('https://relay.example.com');
    });
  });
});

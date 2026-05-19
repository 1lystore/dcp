import { describe, expect, it } from 'vitest';
import { verifySignature } from '@dcprotocol/core';
import { canonicalJson, createMobilePairingInvite } from '../src/mobile-pairing.js';

function canonicalInvitePayload(invite: Record<string, unknown>): string {
  const { signature: _signature, ...unsigned } = invite;
  return canonicalJson(unsigned);
}

describe('mobile pairing', () => {
  it('creates a signed DCP Mobile pairing invite URL', () => {
    const { invite, inviteUrl, pendingConfig } = createMobilePairingInvite({
      client: 'claude-desktop',
      environment: 'local',
      agentName: 'Claude Desktop',
      relayUrl: 'https://relay.example.test/',
      requestedScopes: ['read:wallet.address', 'sign:solana'],
      requestedBudget: {
        daily: 5,
        currency: 'USDC',
        approval_threshold: 0.01,
      },
      ttlSeconds: 300,
    });

    expect(invite.type).toBe('dcp_agent_pairing');
    expect(invite.version).toBe('1.0');
    expect(invite.relay_url).toBe('https://relay.example.test');
    expect(invite.agent_client).toBe('claude-desktop');
    expect(invite.environment).toBe('local');
    expect(invite.requested_scopes).toEqual(['read:wallet.address', 'sign:solana']);
    expect(invite.signature).toBeTruthy();
    expect(inviteUrl.startsWith('dcp://pair?invite=')).toBe(true);
    expect(pendingConfig.service_keypair.private).toBeTruthy();
    expect(pendingConfig.invite_id).toBe(invite.invite_id);
  });

  it('signs the invite with the generated agent public key', () => {
    const { invite } = createMobilePairingInvite({
      client: 'custom',
      environment: 'dev',
      agentName: 'Test Agent',
    });

    const valid = verifySignature(
      Buffer.from(canonicalInvitePayload(invite), 'utf8'),
      Buffer.from(invite.signature!, 'base64'),
      Buffer.from(invite.agent_public_key, 'base64')
    );

    expect(valid).toBe(true);
  });

  it('covers nested budget fields in the invite signature', () => {
    const { invite } = createMobilePairingInvite({
      client: 'custom',
      environment: 'dev',
      agentName: 'Budget Integrity Agent',
      requestedBudget: {
        daily: 1,
        currency: 'USDC',
        approval_threshold: 0,
      },
    });

    const tampered = {
      ...invite,
      requested_budget: {
        ...invite.requested_budget,
        daily: 999,
      },
    };

    const valid = verifySignature(
      Buffer.from(canonicalInvitePayload(tampered), 'utf8'),
      Buffer.from(invite.signature!, 'base64'),
      Buffer.from(invite.agent_public_key, 'base64')
    );

    expect(valid).toBe(false);
  });

  it('rejects unsupported MVP scopes', () => {
    expect(() =>
      createMobilePairingInvite({
        client: 'custom',
        environment: 'dev',
        agentName: 'Bad Scope Agent',
        requestedScopes: ['read:api.key' as never],
      })
    ).toThrow('Unsupported mobile MVP scope');
  });
});

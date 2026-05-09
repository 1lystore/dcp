/**
 * Tests for notification formatting
 *
 * PRIVACY TESTS: Verify that notifications NEVER include sensitive data
 */

import { describe, it, expect } from 'vitest';
import {
  formatConsentNotification,
  formatTestNotification,
  formatPairingSuccess,
  formatHelpMessage,
  formatStatusMessage,
  categorizeRequest,
  sanitizeAgentName,
  escapeMarkdown,
} from '../src/notification.js';
import type { TelegramConsentPayload, TelegramRequestCategory } from '@dcprotocol/core';

describe('sanitizeAgentName', () => {
  it('should truncate long names', () => {
    const longName = 'a'.repeat(50);
    const result = sanitizeAgentName(longName);
    // Result includes escaped "..." which becomes "\.\.\." (6 chars instead of 3)
    // So max length is 29 + 6 = 35 after escaping
    expect(result.length).toBeLessThanOrEqual(35);
    // The dots are escaped as \.\.\. for MarkdownV2
    expect(result).toContain('\\.');
  });

  it('should escape Markdown special characters', () => {
    const result = sanitizeAgentName('agent_with*special[chars]');
    expect(result).toContain('\\');
  });

  it('should remove control characters', () => {
    const result = sanitizeAgentName('agent\x00\x1Fname');
    expect(result).toBe('agentname');
  });

  it('should return "Unknown Agent" for empty input', () => {
    expect(sanitizeAgentName('')).toBe('Unknown Agent');
    expect(sanitizeAgentName('   ')).toBe('Unknown Agent');
  });
});

describe('escapeMarkdown', () => {
  it('should escape all Markdown special characters', () => {
    const input = '_*[]()~`>#+=|{}.!-';
    const result = escapeMarkdown(input);
    expect(result).not.toBe(input);
    // Each character should be escaped
    expect(result.split('\\').length).toBeGreaterThan(1);
  });

  it('should leave normal text unchanged', () => {
    const input = 'normal text 123';
    expect(escapeMarkdown(input)).toBe(input);
  });
});

describe('categorizeRequest', () => {
  it('should categorize transaction signing', () => {
    expect(categorizeRequest('sign', 'sign:solana')).toBe('transaction_signing');
    expect(categorizeRequest('sign_tx', 'any')).toBe('transaction_signing');
  });

  it('should categorize message signing', () => {
    expect(categorizeRequest('sign_message', 'any')).toBe('message_signing');
    expect(categorizeRequest('sign_typed_data', 'any')).toBe('message_signing');
  });

  it('should categorize credential access', () => {
    expect(categorizeRequest('read', 'read:credentials.api.openai')).toBe('credential_access');
    expect(categorizeRequest('write', 'write:credentials.api.stripe')).toBe('data_write');
  });

  it('should categorize data read/write', () => {
    expect(categorizeRequest('read', 'read:identity.email')).toBe('data_read');
    expect(categorizeRequest('write', 'write:preferences.diet')).toBe('data_write');
  });

  it('should return "other" for unknown actions', () => {
    expect(categorizeRequest('unknown', 'unknown:scope')).toBe('other');
  });
});

describe('formatConsentNotification', () => {
  const basePayload: TelegramConsentPayload = {
    consent_id: 'consent_abc123',
    agent_name: 'trading-bot',
    category: 'transaction_signing',
    review_link: 'http://localhost:8421/consent/abc123',
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  };

  it('should format notification correctly', () => {
    const result = formatConsentNotification(basePayload);
    expect(result).toContain('Approval Needed');
    expect(result).toContain('trading\\-bot');
    expect(result).toContain('sign a transaction');
    // Request IDs, links, and commands are not embedded in notification text.
    // Users interact through Telegram inline buttons or the desktop app.
    expect(result).not.toContain('consent_abc123');
    expect(result).not.toContain('Review Request');
    expect(result).not.toContain('localhost');
  });

  it('should NEVER include amount or currency', () => {
    const result = formatConsentNotification(basePayload);
    expect(result).not.toMatch(/\$|\d+\s*(USDC|SOL|ETH)/i);
  });

  it('should NEVER include addresses', () => {
    const result = formatConsentNotification(basePayload);
    expect(result).not.toMatch(/0x[a-fA-F0-9]{40}/); // Ethereum address
    expect(result).not.toMatch(/[1-9A-HJ-NP-Za-km-z]{32,44}/); // Solana address
  });

  it('should sanitize agent names', () => {
    const payload = {
      ...basePayload,
      agent_name: 'malicious*agent_with[special]chars',
    };
    const result = formatConsentNotification(payload);
    expect(result).toContain('\\');
  });

  it('should truncate long agent names', () => {
    const payload = {
      ...basePayload,
      agent_name: 'a'.repeat(100),
    };
    const result = formatConsentNotification(payload);
    // Dots are escaped as \.\.\. for MarkdownV2
    expect(result).toContain('\\.');
  });

  it('should show correct category icon', () => {
    const categories: TelegramRequestCategory[] = [
      'transaction_signing',
      'message_signing',
      'data_read',
      'data_write',
      'credential_access',
      'other',
    ];

    for (const category of categories) {
      const payload = { ...basePayload, category };
      const result = formatConsentNotification(payload);
      // Should contain some emoji
      expect(result).toMatch(/[\u{1F300}-\u{1F9FF}]/u);
    }
  });
});

describe('formatTestNotification', () => {
  it('should include success message', () => {
    const result = formatTestNotification();
    expect(result).toContain('Connected');
    expect(result).toContain('/status');
  });
});

describe('formatPairingSuccess', () => {
  it('should truncate vault ID for privacy', () => {
    const result = formatPairingSuccess('vault_abcdefghijklmnop');
    expect(result).toContain('vault_ab');
    expect(result).toContain('...');
    expect(result).not.toContain('vault_abcdefghijklmnop');
  });

  it('should include helpful commands', () => {
    const result = formatPairingSuccess('vault_123');
    expect(result).toContain('/help');
  });
});

describe('formatHelpMessage', () => {
  it('should list all commands', () => {
    const result = formatHelpMessage();
    expect(result).toContain('/start');
    expect(result).toContain('/pair');
    expect(result).toContain('/status');
    expect(result).toContain('/mute');
    expect(result).toContain('/unmute');
    expect(result).toContain('/unlink');
    expect(result).toContain('/help');
  });
});

describe('formatStatusMessage', () => {
  it('should show enabled status correctly', () => {
    const result = formatStatusMessage({
      enabled: true,
      notificationsThisHour: 5,
      rateLimit: 30,
    });
    expect(result).toContain('Connected');
    expect(result).toContain('5/30');
  });

  it('should show disabled status correctly', () => {
    const result = formatStatusMessage({
      enabled: false,
      notificationsThisHour: 0,
      rateLimit: 30,
    });
    expect(result).toContain('Disabled');
  });

  it('should show mute status', () => {
    const mutedUntil = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    const result = formatStatusMessage({
      enabled: true,
      mutedUntil,
      notificationsThisHour: 0,
      rateLimit: 30,
    });
    expect(result).toContain('Muted until');
  });
});

describe('Privacy Compliance', () => {
  const sensitivePatterns = [
    // Amounts
    /\b\d+\s*(USDC|SOL|ETH|USD)\b/i,
    // Ethereum addresses
    /0x[a-fA-F0-9]{40}/,
    // Solana addresses
    /[1-9A-HJ-NP-Za-km-z]{32,44}/,
    // Private keys
    /private.*key/i,
    // API keys
    /api.*key.*[a-zA-Z0-9]{20,}/i,
    // Secrets
    /secret/i,
    // Transaction data
    /tx_data|transaction_data|signed_tx/i,
  ];

  it('consent notification should not contain sensitive data', () => {
    const payload: TelegramConsentPayload = {
      consent_id: 'consent_123',
      agent_name: 'test-agent',
      category: 'transaction_signing',
      review_link: 'http://localhost/consent/123',
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 300000).toISOString(),
    };

    const result = formatConsentNotification(payload);

    for (const pattern of sensitivePatterns) {
      expect(result).not.toMatch(pattern);
    }
  });

  it('all formatters should be privacy-safe', () => {
    const formatters = [
      () => formatTestNotification(),
      () => formatPairingSuccess('vault_123456789'),
      () => formatHelpMessage(),
      () => formatStatusMessage({ enabled: true, notificationsThisHour: 0, rateLimit: 30 }),
    ];

    for (const formatter of formatters) {
      const result = formatter();
      for (const pattern of sensitivePatterns) {
        expect(result).not.toMatch(pattern);
      }
    }
  });
});

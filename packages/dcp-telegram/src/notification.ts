/**
 * Notification Formatting for DCP Telegram Service
 *
 * PRIVACY-FIRST DESIGN (protocol spec section 15):
 * - PERMITTED: agent_name, request category, request_id, review_link
 * - FORBIDDEN: secrets, transaction payloads, amounts, addresses, credentials
 *
 * All notification content must be privacy-safe. Never include sensitive data.
 */

import type { TelegramConsentPayload, TelegramRequestCategory } from '@dcprotocol/core';

/**
 * Maximum length for agent name in notifications
 */
const MAX_AGENT_NAME_LENGTH = 32;

/**
 * Maximum length for request ID display
 */
const MAX_REQUEST_ID_LENGTH = 16;

/**
 * Human-readable category labels
 */
const CATEGORY_LABELS: Record<TelegramRequestCategory, string> = {
  transaction_signing: 'Transaction Signing',
  message_signing: 'Message Signing',
  data_read: 'Data Access',
  data_write: 'Data Update',
  credential_access: 'Credential Access',
  other: 'Vault Operation',
};

/**
 * Human-readable scope descriptions for better context
 * Maps scope patterns to user-friendly descriptions
 */
function formatScopeDescription(scope?: string): string | null {
  if (!scope) return null;

  const scopeLower = scope.toLowerCase();

  // Signing scopes
  if (scopeLower.startsWith('sign:')) {
    const chain = scope.split(':')[1] || 'blockchain';
    const chainNames: Record<string, string> = {
      solana: 'Solana',
      ethereum: 'Ethereum',
      base: 'Base',
      polygon: 'Polygon',
    };
    return `Sign ${chainNames[chain.toLowerCase()] || chain} transaction`;
  }

  // Identity scopes
  if (scopeLower.includes('identity.email')) return 'Email address';
  if (scopeLower.includes('identity.name')) return 'Full name';
  if (scopeLower.includes('identity.phone')) return 'Phone number';
  if (scopeLower.includes('identity.passport')) return 'Passport details';
  if (scopeLower.includes('identity')) return 'Identity information';

  // Address scopes
  if (scopeLower.includes('address')) return 'Physical address';

  // Wallet scopes
  if (scopeLower.includes('wallet')) return 'Wallet access';

  // Credential scopes
  if (scopeLower.includes('credentials.api.')) {
    const service = scope.split('.').pop() || 'API';
    return `${service.charAt(0).toUpperCase() + service.slice(1)} API credentials`;
  }
  if (scopeLower.includes('credentials')) return 'API credentials';

  // Preference scopes
  if (scopeLower.includes('preferences.diet')) return 'Dietary preferences';
  if (scopeLower.includes('preferences.sizes')) return 'Size preferences';
  if (scopeLower.includes('preferences.brands')) return 'Brand preferences';
  if (scopeLower.includes('preferences')) return 'Personal preferences';

  // Health scopes
  if (scopeLower.includes('health')) return 'Health data';

  // Budget scopes
  if (scopeLower.includes('budget')) return 'Budget settings';

  // Generic read/write
  if (scopeLower.startsWith('read:')) {
    const target = scope.split(':')[1] || 'data';
    return `Read ${target}`;
  }
  if (scopeLower.startsWith('write:')) {
    const target = scope.split(':')[1] || 'data';
    return `Write ${target}`;
  }

  return null;
}

/**
 * Category icons for visual distinction
 */
const CATEGORY_ICONS: Record<TelegramRequestCategory, string> = {
  transaction_signing: '💳',
  message_signing: '✍️',
  data_read: '📖',
  data_write: '📝',
  credential_access: '🔑',
  other: '📋',
};

/**
 * Sanitize agent name for safe display.
 * - Truncates to max length
 * - Escapes special Markdown characters
 * - Removes control characters
 */
export function sanitizeAgentName(name: string): string {
  // Remove control characters and trim
  let sanitized = name.replace(/[\x00-\x1F\x7F]/g, '').trim();

  // Truncate if too long
  if (sanitized.length > MAX_AGENT_NAME_LENGTH) {
    sanitized = sanitized.slice(0, MAX_AGENT_NAME_LENGTH - 3) + '...';
  }

  // Escape Markdown special characters
  sanitized = escapeMarkdown(sanitized);

  return sanitized || 'Unknown Agent';
}

/**
 * Escape Markdown special characters for Telegram
 */
export function escapeMarkdown(text: string): string {
  return text.replace(/[_*[\]()~`>#+=|{}.!-]/g, '\\$&');
}

/**
 * Format request ID for display (truncated for privacy)
 */
export function formatRequestId(requestId: string): string {
  if (requestId.length <= MAX_REQUEST_ID_LENGTH) {
    return requestId;
  }
  return requestId.slice(0, MAX_REQUEST_ID_LENGTH - 3) + '...';
}

/**
 * Categorize a request action and scope into a privacy-safe category.
 *
 * @param action - The action type (e.g., 'sign', 'read', 'write')
 * @param scope - The scope being accessed (e.g., 'sign:solana', 'read:credentials.api.openai')
 * @returns Privacy-safe category
 */
export function categorizeRequest(action: string, scope: string): TelegramRequestCategory {
  const actionLower = action.toLowerCase();
  const scopeLower = scope.toLowerCase();

  // Transaction signing
  if (
    actionLower === 'sign' ||
    actionLower === 'sign_tx' ||
    scopeLower.startsWith('sign:')
  ) {
    return 'transaction_signing';
  }

  // Message signing
  if (
    actionLower === 'sign_message' ||
    actionLower === 'sign_typed_data'
  ) {
    return 'message_signing';
  }

  // Credential access
  if (scopeLower.includes('credentials') || scopeLower.includes('api')) {
    return actionLower === 'write' ? 'data_write' : 'credential_access';
  }

  // Data read
  if (actionLower === 'read') {
    return 'data_read';
  }

  // Data write
  if (actionLower === 'write') {
    return 'data_write';
  }

  return 'other';
}

/**
 * Calculate time remaining until expiration
 */
function getTimeRemaining(expiresAt: string): string {
  const now = Date.now();
  const expires = new Date(expiresAt).getTime();
  const remainingMs = expires - now;

  if (remainingMs <= 0) {
    return 'Expired';
  }

  const minutes = Math.floor(remainingMs / 60000);
  const seconds = Math.floor((remainingMs % 60000) / 1000);

  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }
  return `${seconds}s`;
}

/**
 * Human-readable chain names
 */
const CHAIN_NAMES: Record<string, string> = {
  base: 'Base',
  ethereum: 'Ethereum',
  solana: 'Solana',
  polygon: 'Polygon',
};

/**
 * Format amount with clean decimal places (avoid float artifacts)
 */
function formatDisplayAmount(amount: number): string {
  // Round to 6 decimal places max, trim trailing zeros
  const rounded = Math.round(amount * 1000000) / 1000000;
  return String(rounded);
}

/**
 * Format a consent notification message for Telegram.
 *
 * Human-friendly format with transaction context for informed decisions.
 */
export function formatConsentNotification(payload: TelegramConsentPayload): string {
  const agentName = sanitizeAgentName(payload.agent_name);
  const timeRemaining = getTimeRemaining(payload.expires_at);

  // Build human-readable action description
  const chainName = payload.chain ? (CHAIN_NAMES[payload.chain.toLowerCase()] || payload.chain) : null;

  const lines = [`🔐 *Approval Needed*`, ``];

  // For transaction signing with amount - lead with the key info
  if (payload.category === 'transaction_signing' && payload.amount !== undefined && payload.currency) {
    const amount = formatDisplayAmount(payload.amount);
    if (chainName) {
      lines.push(`${agentName} wants to send *${escapeMarkdown(amount)} ${escapeMarkdown(payload.currency)}* on ${escapeMarkdown(chainName)}\\.`);
    } else {
      lines.push(`${agentName} wants to send *${escapeMarkdown(amount)} ${escapeMarkdown(payload.currency)}*\\.`);
    }
  } else if (payload.category === 'transaction_signing') {
    // Transaction signing without amount info
    if (chainName) {
      lines.push(`${agentName} wants to sign a transaction on ${escapeMarkdown(chainName)}\\.`);
    } else {
      lines.push(`${agentName} wants to sign a transaction\\.`);
    }
  } else if (payload.category === 'message_signing') {
    lines.push(`${agentName} wants to sign a message\\.`);
  } else if (payload.category === 'data_read') {
    const what = formatScopeDescription(payload.scope) || 'data';
    lines.push(`${agentName} wants to read ${escapeMarkdown(what.toLowerCase())}\\.`);
  } else if (payload.category === 'data_write') {
    const what = formatScopeDescription(payload.scope) || 'data';
    lines.push(`${agentName} wants to write ${escapeMarkdown(what.toLowerCase())}\\.`);
  } else if (payload.category === 'credential_access') {
    const what = formatScopeDescription(payload.scope) || 'credentials';
    lines.push(`${agentName} wants to access ${escapeMarkdown(what.toLowerCase())}\\.`);
  } else {
    lines.push(`${agentName} is requesting access\\.`);
  }

  lines.push(``, `⏱️ Reply within ${timeRemaining}`);

  return lines.join('\n');
}

/**
 * Build inline keyboard markup for approve/deny buttons
 */
export function buildConsentInlineKeyboard(consentId: string): {
  inline_keyboard: Array<Array<{ text: string; callback_data: string }>>;
} {
  return {
    inline_keyboard: [
      [
        { text: '✅ Approve', callback_data: `approve:${consentId}` },
        { text: '❌ Deny', callback_data: `deny:${consentId}` },
      ],
    ],
  };
}

export function formatApprovalQueued(consentId: string, action: 'approve' | 'deny'): string {
  const verb = action === 'approve' ? 'Approval' : 'Denial';
  return [
    `✅ *${verb} Queued*`,
    ``,
    `Request: \`${formatRequestId(consentId)}\``,
    ``,
    `Your desktop will process this shortly\\.`,
  ].join('\n');
}

export function formatApprovalProcessed(
  consentId: string,
  action: 'approve' | 'deny',
  result: string
): string {
  const ok = result === 'success';
  const verb = action === 'approve' ? 'approved' : 'denied';
  if (ok) {
    return [
      `✅ *Consent ${escapeMarkdown(verb)}*`,
      ``,
      `Request: \`${formatRequestId(consentId)}\``,
    ].join('\n');
  }

  return [
    `⚠️ *Consent Command Failed*`,
    ``,
    `Request: \`${formatRequestId(consentId)}\``,
    `Result: ${escapeMarkdown(result)}`,
  ].join('\n');
}

/**
 * Format a test notification message
 */
export function formatTestNotification(): string {
  return [
    `✅ *DCP Telegram Connected*`,
    ``,
    `Your vault is successfully linked to Telegram\\.`,
    `You will receive notifications when approval is needed\\.`,
    ``,
    `Use /status to check connection status\\.`,
    `Use /mute to temporarily silence notifications\\.`,
  ].join('\n');
}

/**
 * Budget exceeded notification payload
 */
export interface BudgetExceededPayload {
  agent_name: string;
  amount: number;
  currency: string;
  chain: string;
  error_code: 'BUDGET_EXCEEDED_TX' | 'BUDGET_EXCEEDED_DAILY';
  remaining_daily: number;
  remaining_tx: number;
  limit_daily: number;
  limit_tx: number;
  message: string;
}

/**
 * Format a budget exceeded notification message for Telegram.
 *
 * This notifies the admin when an agent tries to spend beyond budget limits.
 * The admin should then manually increase limits in the Desktop app if needed.
 */
export function formatBudgetExceededNotification(payload: BudgetExceededPayload): string {
  const agentName = sanitizeAgentName(payload.agent_name);
  const isDaily = payload.error_code === 'BUDGET_EXCEEDED_DAILY';
  const icon = isDaily ? '📊' : '💳';
  const limitType = isDaily ? 'Daily Budget' : 'Transaction Limit';

  // Round to 4 decimal places to avoid JS float artifacts like 0.15599999999999992
  const formatAmount = (n: number) => Math.round(n * 10000) / 10000;

  const lines = [
    `🚫 *DCP Vault: Budget Exceeded*`,
    ``,
    `${icon} *Type:* ${escapeMarkdown(limitType)} Exceeded`,
    `🤖 *Agent:* ${agentName}`,
    ``,
    `*Attempted:* ${escapeMarkdown(String(formatAmount(payload.amount)))} ${escapeMarkdown(payload.currency)}`,
    `*Limit:* ${escapeMarkdown(String(formatAmount(isDaily ? payload.limit_daily : payload.limit_tx)))} ${escapeMarkdown(payload.currency)}`,
  ];

  if (isDaily) {
    lines.push(`*Remaining today:* ${escapeMarkdown(String(formatAmount(payload.remaining_daily)))} ${escapeMarkdown(payload.currency)}`);
  }

  lines.push(
    ``,
    `⚠️ *Transaction was rejected*`,
    ``,
    `To allow higher amounts, open your DCP Desktop app and increase the budget limits in Settings\\.`,
  );

  return lines.join('\n');
}

/**
 * Format a pairing success message
 */
export function formatPairingSuccess(vaultId: string): string {
  // Only show first 8 chars of vault ID for privacy
  const shortVaultId = vaultId.slice(0, 8) + '...';

  return [
    `🎉 *Pairing Successful\\!*`,
    ``,
    `Your DCP Vault is now connected to Telegram\\.`,
    `Vault: \`${shortVaultId}\``,
    ``,
    `You will receive notifications when:`,
    `• An agent requests transaction signing`,
    `• An agent requests data access`,
    `• An agent requests credential access`,
    ``,
    `Use /help to see available commands\\.`,
  ].join('\n');
}

/**
 * Format help message with available commands
 */
export function formatHelpMessage(): string {
  return [
    `📖 *DCP Vault Bot Commands*`,
    ``,
    `/start \\- Begin pairing process`,
    `/pair \\<code\\> \\- Complete pairing with 6\\-digit code`,
    `/approve \\<request\\> \\- Approve a vault request`,
    `/deny \\<request\\> \\- Deny a vault request`,
    `/status \\- Check connection status`,
    `/mute \\<1h\\|6h\\|24h\\> \\- Mute notifications`,
    `/unmute \\- Resume notifications`,
    `/unlink \\- Disconnect from vault`,
    `/help \\- Show this message`,
    ``,
    `For more info, visit: https://dcp\\.1ly\\.store`,
  ].join('\n');
}

/**
 * Format status message
 */
export function formatStatusMessage(config: {
  enabled: boolean;
  mutedUntil?: string;
  lastNotification?: string;
  notificationsThisHour: number;
  rateLimit: number;
}): string {
  const status = config.enabled ? '✅ Connected' : '⏸️ Disabled';

  let muteStatus = 'Not muted';
  if (config.mutedUntil) {
    const mutedUntil = new Date(config.mutedUntil);
    if (mutedUntil > new Date()) {
      muteStatus = `Muted until ${mutedUntil.toLocaleTimeString()}`;
    }
  }

  const lastActivity = config.lastNotification
    ? new Date(config.lastNotification).toLocaleString()
    : 'Never';

  return [
    `📊 *DCP Vault Status*`,
    ``,
    `*Connection:* ${status}`,
    `*Notifications:* ${muteStatus}`,
    `*Last activity:* ${lastActivity}`,
    `*Rate limit:* ${config.notificationsThisHour}/${config.rateLimit} this hour`,
  ].join('\n');
}

/**
 * Format mute confirmation message
 */
export function formatMuteConfirmation(duration: string, until: Date): string {
  return [
    `🔇 *Notifications Muted*`,
    ``,
    `You won't receive notifications for ${duration}\\.`,
    `Muted until: ${escapeMarkdown(until.toLocaleString())}`,
    ``,
    `Use /unmute to resume notifications\\.`,
  ].join('\n');
}

/**
 * Format unmute confirmation message
 */
export function formatUnmuteConfirmation(): string {
  return [
    `🔔 *Notifications Resumed*`,
    ``,
    `You will now receive vault approval notifications\\.`,
  ].join('\n');
}

/**
 * Format unlink confirmation message
 */
export function formatUnlinkConfirmation(): string {
  return [
    `👋 *Disconnected from DCP Vault*`,
    ``,
    `Your Telegram is no longer linked to your vault\\.`,
    `Use /start to connect again\\.`,
  ].join('\n');
}

/**
 * Format error message
 */
export function formatErrorMessage(error: string): string {
  return [
    `❌ *Error*`,
    ``,
    escapeMarkdown(error),
    ``,
    `If this persists, check your DCP Desktop app\\.`,
  ].join('\n');
}

/**
 * Format rate limit warning
 */
export function formatRateLimitWarning(resetIn: number): string {
  const minutes = Math.ceil(resetIn / 60000);
  return [
    `⚠️ *Rate Limited*`,
    ``,
    `Too many notifications\\. Please wait ${minutes} minute${minutes > 1 ? 's' : ''}\\.`,
  ].join('\n');
}

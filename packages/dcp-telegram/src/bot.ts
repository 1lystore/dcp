/**
 * Telegram Bot for DCP Vault (Option B from protocol spec section 15)
 *
 * Cloud bot that:
 * - Handles pairing codes from users
 * - Completes vault ↔ chat_id pairings
 * - Sends consent notifications
 * - Handles mute/unmute/unlink commands
 *
 * ONE shared bot for ALL users.
 */

import type { TelegramConsentPayload } from '@dcprotocol/core';
import type { TelegramBotConfig, NotificationResult } from './types.js';
import { MUTE_DURATIONS, BOT_COMMANDS } from './types.js';
import { TelegramStore } from './store.js';
import {
  formatConsentNotification,
  formatTestNotification,
  formatBudgetExceededNotification,
  formatPairingSuccess,
  formatHelpMessage,
  formatStatusMessage,
  formatMuteConfirmation,
  formatUnmuteConfirmation,
  formatUnlinkConfirmation,
  formatErrorMessage,
  formatApprovalQueued,
  formatApprovalProcessed,
  formatRateLimitWarning,
  type BudgetExceededPayload,
  buildConsentInlineKeyboard,
} from './notification.js';
import type { ApprovalAction } from './types.js';

type TelegramParseMode = 'MarkdownV2' | 'HTML';

interface TelegramMessage {
  message_id: number;
  chat: {
    id: number;
  };
  text?: string;
}

interface TelegramCallbackQuery {
  id: string;
  data?: string;
  message?: TelegramMessage;
}

interface TelegramUpdate {
  update_id: number;
  message?: TelegramMessage;
  callback_query?: TelegramCallbackQuery;
}

interface SendMessageOptions {
  parse_mode?: TelegramParseMode;
  disable_web_page_preview?: boolean;
  reply_markup?: unknown;
}

class TelegramApiClient {
  private baseUrl: string;

  constructor(botToken: string) {
    this.baseUrl = `https://api.telegram.org/bot${botToken}`;
  }

  async setMyCommands(commands: Array<{ command: string; description: string }>): Promise<void> {
    await this.request('setMyCommands', { commands });
  }

  async sendMessage(
    chatId: number,
    text: string,
    options: SendMessageOptions = {}
  ): Promise<TelegramMessage> {
    return this.request<TelegramMessage>('sendMessage', {
      chat_id: chatId,
      text,
      ...options,
    });
  }

  async answerCallbackQuery(callbackQueryId: string, options: { text?: string } = {}): Promise<void> {
    await this.request('answerCallbackQuery', {
      callback_query_id: callbackQueryId,
      ...options,
    });
  }

  async editMessageReplyMarkup(
    replyMarkup: unknown,
    options: { chat_id: number; message_id: number }
  ): Promise<void> {
    await this.request('editMessageReplyMarkup', {
      ...options,
      reply_markup: replyMarkup,
    });
  }

  async getUpdates(offset: number, timeout = 30): Promise<TelegramUpdate[]> {
    return this.request<TelegramUpdate[]>('getUpdates', {
      offset,
      timeout,
      allowed_updates: ['message', 'callback_query'],
    });
  }

  private async request<T = unknown>(method: string, body: Record<string, unknown>): Promise<T> {
    const response = await fetch(`${this.baseUrl}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    const payload = await response.json() as { ok?: boolean; result?: T; description?: string };
    if (!response.ok || !payload.ok) {
      throw new Error(payload.description || `Telegram API ${method} failed`);
    }

    return payload.result as T;
  }
}

/**
 * DCP Telegram Bot (Cloud Service)
 */
export class DcpTelegramBot {
  private bot: TelegramApiClient;
  private store: TelegramStore;
  private config: TelegramBotConfig;
  private isRunning = false;
  private pollAbort: AbortController | null = null;
  private pollOffset = 0;

  constructor(config: TelegramBotConfig, store: TelegramStore) {
    this.config = config;
    this.store = store;

    this.bot = new TelegramApiClient(config.botToken);

    this.setupCommands();
  }

  /**
   * Set up bot commands menu
   */
  private async setupCommands(): Promise<void> {
    try {
      await this.bot.setMyCommands(
        BOT_COMMANDS.map((cmd) => ({
          command: cmd.command,
          description: cmd.description,
        }))
      );
    } catch (err) {
      if (this.config.debug) {
        console.error('Failed to set bot commands:', err);
      }
    }
  }

  private async handleUpdate(update: TelegramUpdate): Promise<void> {
    if (update.message?.text) {
      await this.handleTextMessage(update.message);
    }

    if (update.callback_query) {
      await this.handleCallbackQuery(update.callback_query);
    }
  }

  private async handleTextMessage(message: TelegramMessage): Promise<void> {
    const text = message.text?.trim() || '';
    const chatId = message.chat.id;

    const startPairMatch = text.match(/^\/start\s+pair_(\d{6})$/);
    if (startPairMatch) {
      await this.handlePair(chatId, startPairMatch[1]);
      return;
    }

    if (/^\/start\b/.test(text)) {
      await this.handleStart(chatId);
      return;
    }

    const pairMatch = text.match(/^\/pair\s+(\d{6})$/);
    if (pairMatch) {
      await this.handlePair(chatId, pairMatch[1]);
      return;
    }

    if (/^\/pair$/.test(text)) {
      await this.sendMessage(
        chatId,
        '❓ Please provide your 6\\-digit pairing code:\n\n`/pair 123456`',
        'MarkdownV2'
      );
      return;
    }

    if (/^\/status\b/.test(text)) {
      await this.handleStatus(chatId);
      return;
    }

    const approveMatch = text.match(/^\/approve\s+(\S+)$/);
    if (approveMatch) {
      await this.handleRemoteApproval(chatId, approveMatch[1], 'approve');
      return;
    }

    if (/^\/approve$/.test(text)) {
      await this.sendMessage(chatId, '❓ Please provide the request ID:\n\n`/approve abc123`', 'MarkdownV2');
      return;
    }

    const denyMatch = text.match(/^\/deny\s+(\S+)$/);
    if (denyMatch) {
      await this.handleRemoteApproval(chatId, denyMatch[1], 'deny');
      return;
    }

    if (/^\/deny$/.test(text)) {
      await this.sendMessage(chatId, '❓ Please provide the request ID:\n\n`/deny abc123`', 'MarkdownV2');
      return;
    }

    const muteMatch = text.match(/^\/mute(?:\s+(\S+))?/);
    if (muteMatch) {
      await this.handleMute(chatId, muteMatch[1] || '1h');
      return;
    }

    if (/^\/unmute\b/.test(text)) {
      await this.handleUnmute(chatId);
      return;
    }

    if (/^\/unlink\b/.test(text)) {
      await this.handleUnlink(chatId);
      return;
    }

    if (/^\/help\b/.test(text)) {
      await this.handleHelp(chatId);
    }
  }

  private async handleCallbackQuery(query: TelegramCallbackQuery): Promise<void> {
    if (!query.data || !query.message) return;

    const chatId = query.message.chat.id;
    const [action, consentId] = query.data.split(':');

    if (action !== 'approve' && action !== 'deny') {
      return;
    }

    try {
      await this.bot.answerCallbackQuery(query.id, {
        text: action === 'approve' ? '✅ Processing approval...' : '❌ Processing denial...',
      });

      await this.bot.editMessageReplyMarkup(
        { inline_keyboard: [] },
        { chat_id: chatId, message_id: query.message.message_id }
      );
    } catch (err) {
      if (this.config.debug) {
        console.error('Failed to acknowledge callback:', err);
      }
    }

    await this.handleRemoteApproval(chatId, consentId, action);
  }

  private async pollUpdates(signal: AbortSignal): Promise<void> {
    while (!signal.aborted && this.isRunning) {
      try {
        const updates = await this.bot.getUpdates(this.pollOffset, 30);
        for (const update of updates) {
          this.pollOffset = Math.max(this.pollOffset, update.update_id + 1);
          await this.handleUpdate(update);
        }
      } catch (err) {
        if (signal.aborted || !this.isRunning) {
          return;
        }
        if (this.config.debug) {
          console.error('Telegram polling error:', err);
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
  }

  /**
   * Handle /start command
   */
  private async handleStart(chatId: number): Promise<void> {
    const message = [
      `👋 *Welcome to DCP Vault Bot\\!*`,
      ``,
      `This bot sends you notifications when your vault needs approval\\.`,
      ``,
      `*To connect your vault:*`,
      `1\\. Open DCP Desktop`,
      `2\\. Go to Settings \\> Telegram`,
      `3\\. Click "Connect Telegram"`,
      `4\\. Send the 6\\-digit code here: \`/pair CODE\``,
      ``,
      `Use /help to see all commands\\.`,
    ].join('\n');

    await this.sendMessage(chatId, message, 'MarkdownV2');
  }

  /**
   * Handle /pair command - validates code from cloud store
   */
  private async handlePair(chatId: number, code: string): Promise<void> {
    console.log(`[BOT] Pairing attempt: chat=${chatId}, code=${code}`);

    try {
      // Try to consume the pairing code
      const vaultId = this.store.pairings.consumePairingCode(code);

      if (!vaultId) {
        await this.sendMessage(
          chatId,
          formatErrorMessage('Invalid or expired pairing code. Please get a new code from DCP Desktop.'),
          'MarkdownV2'
        );
        return;
      }

      // Complete the pairing
      const pairing = this.store.pairings.completePairing(vaultId, String(chatId));
      console.log(`[BOT] Pairing completed: vault=${vaultId}, chat=${chatId}`);

      await this.sendMessage(
        chatId,
        formatPairingSuccess(vaultId),
        'MarkdownV2'
      );
    } catch (err) {
      console.error('[BOT] Pairing error:', err);
      await this.sendMessage(
        chatId,
        formatErrorMessage('Failed to complete pairing. Please try again.'),
        'MarkdownV2'
      );
    }
  }

  /**
   * Handle /status command
   */
  private async handleStatus(chatId: number): Promise<void> {
    const pairing = this.store.pairings.getPairingByChatId(String(chatId));

    if (!pairing) {
      await this.sendMessage(
        chatId,
        '❌ *Not Connected*\n\nUse /start to learn how to connect your vault\\.',
        'MarkdownV2'
      );
      return;
    }

    const status = {
      enabled: pairing.enabled,
      mutedUntil: pairing.muted_until || undefined,
      lastNotification: pairing.last_notification_at || undefined,
      notificationsThisHour: this.store.rateLimiter.getRemaining(String(chatId), 30),
      rateLimit: 30,
    };

    await this.sendMessage(chatId, formatStatusMessage(status), 'MarkdownV2');
  }

  private async handleRemoteApproval(
    chatId: number,
    consentId: string,
    action: ApprovalAction
  ): Promise<void> {
    const chatIdString = String(chatId);
    const pairing = this.store.pairings.getPairingByChatId(chatIdString);

    if (!pairing) {
      await this.sendMessage(
        chatId,
        formatErrorMessage('Not connected to a vault'),
        'MarkdownV2'
      );
      return;
    }

    if (!pairing.enabled) {
      await this.sendMessage(
        chatId,
        formatErrorMessage('Telegram notifications are disabled for this vault'),
        'MarkdownV2'
      );
      return;
    }

    if (this.store.rateLimiter.isLimited(chatIdString)) {
      await this.sendMessage(
        chatId,
        formatRateLimitWarning(this.store.rateLimiter.getResetTime(chatIdString)),
        'MarkdownV2'
      );
      return;
    }

    const normalizedConsentId = consentId.trim();
    if (!normalizedConsentId) {
      await this.sendMessage(
        chatId,
        formatErrorMessage('Request ID is required'),
        'MarkdownV2'
      );
      return;
    }

    // protocol spec: Include pairing_id for command binding
    const command = this.store.approvals.createApprovalCommand(
      pairing.vault_id,
      chatIdString,
      normalizedConsentId,
      action,
      pairing.vault_id // pairing_id is vault_id since each vault has one pairing
    );
    console.log(
      `[APPROVAL] Queued ${action} command ${command.id} for vault ${pairing.vault_id}, consent ${normalizedConsentId}`
    );
    this.store.rateLimiter.record(chatIdString);

    await this.sendMessage(
      chatId,
      formatApprovalQueued(normalizedConsentId, action),
      'MarkdownV2'
    );
  }

  /**
   * Handle /mute command
   */
  private async handleMute(chatId: number, duration: string): Promise<void> {
    const durationMs = MUTE_DURATIONS[duration];

    if (!durationMs) {
      await this.sendMessage(
        chatId,
        '❓ Invalid duration\\. Use: `/mute 1h`, `/mute 6h`, or `/mute 24h`',
        'MarkdownV2'
      );
      return;
    }

    const pairing = this.store.pairings.getPairingByChatId(String(chatId));

    if (!pairing) {
      await this.sendMessage(
        chatId,
        formatErrorMessage('Not connected to a vault'),
        'MarkdownV2'
      );
      return;
    }

    const mutedUntil = new Date(Date.now() + durationMs);
    this.store.pairings.mutePairing(pairing.vault_id, mutedUntil);

    await this.sendMessage(
      chatId,
      formatMuteConfirmation(duration, mutedUntil),
      'MarkdownV2'
    );
  }

  /**
   * Handle /unmute command
   */
  private async handleUnmute(chatId: number): Promise<void> {
    const pairing = this.store.pairings.getPairingByChatId(String(chatId));

    if (!pairing) {
      await this.sendMessage(
        chatId,
        formatErrorMessage('Not connected to a vault'),
        'MarkdownV2'
      );
      return;
    }

    this.store.pairings.unmutePairing(pairing.vault_id);
    await this.sendMessage(chatId, formatUnmuteConfirmation(), 'MarkdownV2');
  }

  /**
   * Handle /unlink command
   */
  private async handleUnlink(chatId: number): Promise<void> {
    const deleted = this.store.pairings.deletePairingByChatId(String(chatId));

    if (deleted) {
      await this.sendMessage(chatId, formatUnlinkConfirmation(), 'MarkdownV2');
    } else {
      await this.sendMessage(
        chatId,
        formatErrorMessage('Not connected to a vault'),
        'MarkdownV2'
      );
    }
  }

  /**
   * Handle /help command
   */
  private async handleHelp(chatId: number): Promise<void> {
    await this.sendMessage(chatId, formatHelpMessage(), 'MarkdownV2');
  }

  /**
   * Send a consent notification with inline approve/deny buttons
   */
  async sendConsentNotification(
    chatId: string,
    payload: TelegramConsentPayload
  ): Promise<NotificationResult> {
    try {
      const message = formatConsentNotification(payload);
      const keyboard = buildConsentInlineKeyboard(payload.consent_id);

      const result = await this.bot.sendMessage(Number(chatId), message, {
        parse_mode: 'MarkdownV2',
        disable_web_page_preview: true,
        reply_markup: keyboard,
      });

      return {
        success: true,
        messageId: result.message_id,
      };
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      console.error(`[BOT] Failed to send notification to ${chatId}:`, errorMessage);
      return {
        success: false,
        error: errorMessage,
      };
    }
  }

  /**
   * Send a test notification
   */
  async sendTestNotification(chatId: string): Promise<NotificationResult> {
    try {
      const message = formatTestNotification();
      const result = await this.bot.sendMessage(Number(chatId), message, {
        parse_mode: 'MarkdownV2',
      });

      return {
        success: true,
        messageId: result.message_id,
      };
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      console.error(
        `[BOT] Failed to send approval processed notification to ${chatId}:`,
        errorMessage
      );
      return {
        success: false,
        error: errorMessage,
      };
    }
  }

  /**
   * Send a budget exceeded notification
   * Notifies admin when daily/tx budget is exceeded
   */
  async sendBudgetExceededNotification(
    chatId: string,
    payload: BudgetExceededPayload
  ): Promise<NotificationResult> {
    try {
      const message = formatBudgetExceededNotification(payload);
      const result = await this.bot.sendMessage(Number(chatId), message, {
        parse_mode: 'MarkdownV2',
      });

      return {
        success: true,
        messageId: result.message_id,
      };
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      console.error(`[BOT] Failed to send budget notification to ${chatId}:`, errorMessage);
      return {
        success: false,
        error: errorMessage,
      };
    }
  }

  async sendApprovalProcessedNotification(
    chatId: string,
    consentId: string,
    action: ApprovalAction,
    result: string
  ): Promise<NotificationResult> {
    try {
      const message = formatApprovalProcessed(consentId, action, result);
      const sent = await this.bot.sendMessage(Number(chatId), message, {
        parse_mode: 'MarkdownV2',
      });
      return {
        success: true,
        messageId: sent.message_id,
      };
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      return {
        success: false,
        error: errorMessage,
      };
    }
  }

  /**
   * Send a message to a chat
   */
  private async sendMessage(
    chatId: number,
    text: string,
    parseMode?: 'MarkdownV2' | 'HTML'
  ): Promise<void> {
    try {
      await this.bot.sendMessage(chatId, text, {
        parse_mode: parseMode,
      });
    } catch (err) {
      if (this.config.debug) {
        console.error('Failed to send message:', err);
      }
    }
  }

  /**
   * Get store statistics
   */
  getStats() {
    return this.store.getStats();
  }

  /**
   * Start the bot
   */
  async start(): Promise<void> {
    if (this.isRunning) return;
    this.isRunning = true;
    if (!this.config.webhookUrl) {
      this.pollAbort = new AbortController();
      void this.pollUpdates(this.pollAbort.signal);
    }
    console.log('[BOT] DCP Telegram Bot started');
  }

  /**
   * Stop the bot
   */
  async stop(): Promise<void> {
    if (!this.isRunning) return;
    this.isRunning = false;
    this.pollAbort?.abort();
    this.pollAbort = null;
    console.log('[BOT] DCP Telegram Bot stopped');
  }
}

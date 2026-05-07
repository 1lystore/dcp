/**
 * Telegram Bot for DCP Vault (Option B from PRD Section 15)
 *
 * Cloud bot that:
 * - Handles pairing codes from users
 * - Completes vault ↔ chat_id pairings
 * - Sends consent notifications
 * - Handles mute/unmute/unlink commands
 *
 * ONE shared bot for ALL users.
 */

import TelegramBot from 'node-telegram-bot-api';
import type { TelegramConsentPayload } from '@dcprotocol/core';
import type { TelegramBotConfig, NotificationResult } from './types.js';
import { MUTE_DURATIONS, BOT_COMMANDS } from './types.js';
import { TelegramStore } from './store.js';
import {
  formatConsentNotification,
  formatTestNotification,
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
  buildConsentInlineKeyboard,
} from './notification.js';
import type { ApprovalAction } from './types.js';

/**
 * DCP Telegram Bot (Cloud Service)
 */
export class DcpTelegramBot {
  private bot: TelegramBot;
  private store: TelegramStore;
  private config: TelegramBotConfig;
  private isRunning = false;

  constructor(config: TelegramBotConfig, store: TelegramStore) {
    this.config = config;
    this.store = store;

    // Initialize bot with polling
    this.bot = new TelegramBot(config.botToken, {
      polling: !config.webhookUrl,
    });

    this.setupCommands();
    this.setupHandlers();
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

  /**
   * Set up message handlers
   */
  private setupHandlers(): void {
    // Handle /start command
    this.bot.onText(/\/start/, async (msg) => {
      await this.handleStart(msg.chat.id);
    });

    // Handle /pair command with code
    this.bot.onText(/\/pair\s+(\d{6})/, async (msg, match) => {
      const code = match?.[1];
      if (code) {
        await this.handlePair(msg.chat.id, code);
      }
    });

    // Handle /pair without code
    this.bot.onText(/\/pair$/, async (msg) => {
      await this.sendMessage(
        msg.chat.id,
        '❓ Please provide your 6\\-digit pairing code:\n\n`/pair 123456`',
        'MarkdownV2'
      );
    });

    // Handle /status command
    this.bot.onText(/\/status/, async (msg) => {
      await this.handleStatus(msg.chat.id);
    });

    // Handle /approve command
    this.bot.onText(/\/approve\s+(\S+)/, async (msg, match) => {
      const consentId = match?.[1];
      if (consentId) {
        await this.handleRemoteApproval(msg.chat.id, consentId, 'approve');
      }
    });

    this.bot.onText(/\/approve$/, async (msg) => {
      await this.sendMessage(
        msg.chat.id,
        '❓ Please provide the request ID:\n\n`/approve abc123`',
        'MarkdownV2'
      );
    });

    // Handle /deny command
    this.bot.onText(/\/deny\s+(\S+)/, async (msg, match) => {
      const consentId = match?.[1];
      if (consentId) {
        await this.handleRemoteApproval(msg.chat.id, consentId, 'deny');
      }
    });

    this.bot.onText(/\/deny$/, async (msg) => {
      await this.sendMessage(
        msg.chat.id,
        '❓ Please provide the request ID:\n\n`/deny abc123`',
        'MarkdownV2'
      );
    });

    // Handle /mute command
    this.bot.onText(/\/mute(?:\s+(\S+))?/, async (msg, match) => {
      const duration = match?.[1] || '1h';
      await this.handleMute(msg.chat.id, duration);
    });

    // Handle /unmute command
    this.bot.onText(/\/unmute/, async (msg) => {
      await this.handleUnmute(msg.chat.id);
    });

    // Handle /unlink command
    this.bot.onText(/\/unlink/, async (msg) => {
      await this.handleUnlink(msg.chat.id);
    });

    // Handle /help command
    this.bot.onText(/\/help/, async (msg) => {
      await this.handleHelp(msg.chat.id);
    });

    // Handle inline button callbacks (approve/deny buttons)
    this.bot.on('callback_query', async (query) => {
      if (!query.data || !query.message) return;

      const chatId = query.message.chat.id;
      const [action, consentId] = query.data.split(':');

      if (action === 'approve' || action === 'deny') {
        // CRITICAL: Answer callback IMMEDIATELY to prevent Telegram timeout
        // Telegram has a ~30 second timeout for callback queries
        try {
          await this.bot.answerCallbackQuery(query.id, {
            text: action === 'approve' ? '✅ Processing approval...' : '❌ Processing denial...',
          });

          // Remove buttons to prevent duplicate clicks
          await this.bot.editMessageReplyMarkup(
            { inline_keyboard: [] },
            { chat_id: chatId, message_id: query.message.message_id }
          );
        } catch (err) {
          if (this.config.debug) {
            console.error('Failed to acknowledge callback:', err);
          }
          // Continue processing even if callback ack fails (user may have already clicked)
        }

        // Now process the approval (this sends a message)
        await this.handleRemoteApproval(chatId, consentId, action as ApprovalAction);
      }
    });

    // Handle polling errors
    this.bot.on('polling_error', (err) => {
      if (this.config.debug) {
        console.error('Telegram polling error:', err);
      }
    });
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

    // PRD Sprint 8 Task 9: Include pairing_id for command binding
    this.store.approvals.createApprovalCommand(
      pairing.vault_id,
      chatIdString,
      normalizedConsentId,
      action,
      pairing.vault_id // pairing_id is vault_id since each vault has one pairing
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
    console.log('[BOT] DCP Telegram Bot started');
  }

  /**
   * Stop the bot
   */
  async stop(): Promise<void> {
    if (!this.isRunning) return;
    this.isRunning = false;
    await this.bot.stopPolling();
    console.log('[BOT] DCP Telegram Bot stopped');
  }
}

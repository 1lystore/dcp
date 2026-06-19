/**
 * Ports — the platform-specific dependencies the runtime calls.
 *
 * The runtime owns the WORKFLOW; each app (desktop, mobile) implements these
 * interfaces as adapters. The private key lives ONLY behind `Signer`, in the
 * platform adapter — never in the runtime or in wallet-core.
 */

import type { SwapQuote } from '../swap.js';
import type { PriorSpend, ApprovalRequest, ActivityEvent } from './types.js';
import type { ApprovalOutcome } from './consent.js';

/** Holds/uses the wallet key. Desktop → delegates to the local vault. Mobile → secure enclave. */
export interface Signer {
  /** The wallet's public address (owner / fee-payer). */
  readonly address: string;
  /** Sign an unsigned tx (base64) → signed tx (base64). The key never leaves this adapter. */
  sign(unsignedTxB64: string): Promise<string>;
}

/** Chain reads + submit. Implemented over a managed RPC proxy. */
export interface RpcClient {
  getLatestBlockhash(): Promise<string>;
  /** true if the account exists on-chain (rent / ATA-existence checks). */
  accountExists(address: string): Promise<boolean>;
  submit(signedTxB64: string, opts: { confirm: boolean }): Promise<{ signature: string; status: string }>;
}

/** Jupiter quote + swap-tx build (network). Fee/config injected by the adapter. */
export interface SwapProvider {
  quote(args: { inputMint: string; outputMint: string; rawInAmount: string; slippageBps: number }): Promise<SwapQuote>;
  buildSwapTx(quote: SwapQuote, owner: string): Promise<string>;
}

/** Plain-English approval gate (PIN/biometric on mobile, modal on desktop). */
export interface ApprovalUI {
  /**
   * Resolve `true`/`{ approved: true }` to approve, `false`/`{ approved: false }`
   * to deny, or `{ deferred: true, consentId, ... }` to hand off to an out-of-band
   * consent flow (desktop/agents) — the runner then throws `ConsentRequiredError`.
   */
  requestApproval(req: ApprovalRequest): Promise<boolean | ApprovalOutcome>;
}

/** Budget enforcement + spend recording. */
export interface BudgetStore {
  check(amount: number, currency: string): Promise<{ withinDailyLimit: boolean; needsApproval: boolean }>;
  record(args: { amount: number; currency: string; signature: string }): Promise<void>;
}

/** Idempotency lookup + commit (intent→signature). Persistence is platform-specific. */
export interface IdempotencyStore {
  get(key: string): Promise<PriorSpend | null>;
  /** Persist the successful spend under `key` so a later retry replays it. Called
   *  by the runtime ONLY after a non-failed submit — never on failure. */
  commit(key: string, spend: PriorSpend & { signature: string }): Promise<void>;
}

/** Managed config (allow-listed programs, jupiter program ids). */
export interface ConfigProvider {
  jupiterProgramIds(): string[];
  swapAllowedPrograms(): string[];
}

/** Persists + formats wallet activity/audit. */
export interface ActivityRecorder {
  record(event: ActivityEvent): Promise<void>;
}

export interface TransferPorts {
  signer: Signer;
  rpc: RpcClient;
  approval: ApprovalUI;
  budget: BudgetStore;
  idempotency: IdempotencyStore;
  activity: ActivityRecorder;
}

export interface SwapPorts extends TransferPorts {
  swapProvider: SwapProvider;
  config: ConfigProvider;
}

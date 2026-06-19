/**
 * Request/result + summary types for the wallet runtime workflows.
 * Plain data — no platform specifics.
 */

export interface PriorSpend {
  operation: string;
  destination?: string | null;
  currency: string;
  amount: number;
  /** Present once the spend successfully broadcast — enables idempotent replay. */
  signature?: string;
}

export interface TransferRequest {
  chain: 'solana';
  to: string;
  amount: number;
  /** 'SOL' for native, or a token symbol for SPL (with mint + decimals). */
  currency: string;
  mint?: string;
  decimals?: number;
  idempotencyKey?: string;
  /** true = wait for confirmation (default); false = return on broadcast. */
  confirm?: boolean;
  description?: string;
}

export interface TokenRef {
  mint: string;
  decimals: number;
  currency: string;
}

export interface SwapRequest {
  chain: 'solana';
  fromToken: TokenRef;
  toToken: TokenRef;
  amount: number;
  slippageBps?: number;
  idempotencyKey?: string;
  confirm?: boolean;
}

export interface ExecResult {
  signature: string;
  status: string;
  idempotentReplay?: boolean;
  /** Quoted output (base units) for swaps. */
  outAmount?: string;
}

export interface ApprovalRequest {
  kind: 'transfer' | 'swap';
  /** Plain-English description shown to the human. */
  summary: string;
  amount: number;
  currency: string;
  destination?: string;
}

export interface ActivityEvent {
  kind: 'transfer' | 'swap';
  amount: number;
  currency: string;
  destination?: string;
  signature: string;
  status: string;
}

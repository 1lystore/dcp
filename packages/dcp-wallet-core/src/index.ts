/**
 * @dcprotocol/wallet-core — the pure DCP wallet brain.
 *
 * Tx build / decode / validation + the shared protocol error type. Zero native
 * deps, no storage, no key custody — importable identically from Node, browser,
 * and React Native. Higher packages (core, vault, agent, the private runtimes)
 * build their orchestration on top of these primitives.
 */

export { VaultError } from './errors.js';
export type { VaultErrorCode } from './errors.js';

export {
  buildSolanaTransferTx,
  buildSplTransferTx,
  getSolanaAtaAddress,
  verifyTransferTx,
  getTransactionSigners,
  getTransactionProgramIds,
} from './solana-tx.js';
export type { TransferVerifyResult } from './solana-tx.js';

export {
  validateSwapQuote,
  validateSwapTransaction,
  idempotencyIntentMatches,
  DEFAULT_SWAP_ALLOWED_PROGRAMS,
  DEFAULT_JUPITER_PROGRAM_IDS,
} from './swap.js';
export type { ValidationResult, SwapQuote, SwapQuoteIntent, SpendIntent } from './swap.js';

// On-chain reads (balances, tx status, history, token search) + the RPC reader.
// Pure web3.js + fetch (RN-safe), so desktop, agents, and mobile share one reader.
export * from './solana-reads.js';

// SPL token registry + resolution (pure lookups; per-cluster overrides injected).
export {
  WSOL_MINT,
  DEFAULT_KNOWN_TOKENS,
  resolveToken,
  resolveSwapToken,
} from './tokens.js';
export type { TokenInfo, TokenRegistry } from './tokens.js';

// Jupiter swap integration (quote/build; fee + endpoint injected, never hardcoded).
export { DEFAULT_JUPITER_API, jupiterQuote, jupiterBuildSwapTx } from './jupiter.js';
export type { JupiterConfig } from './jupiter.js';

// Runner — the workflow (build → validate → approve → sign → verify → submit →
// record) over the platform ports. Shared by the vault server and mobile.
export { executeTransfer } from './runtime/transfer.js';
export { executeSwap } from './runtime/swap.js';
export { ConsentRequiredError, normalizeApproval } from './runtime/consent.js';
export type { ApprovalOutcome, ConsentDeferred } from './runtime/consent.js';
export type {
  Signer,
  RpcClient,
  SwapProvider,
  ApprovalUI,
  BudgetStore,
  IdempotencyStore,
  ConfigProvider,
  ActivityRecorder,
  TransferPorts,
  SwapPorts,
} from './runtime/ports.js';
export type {
  PriorSpend,
  TransferRequest,
  SwapRequest,
  TokenRef,
  ExecResult,
  ApprovalRequest,
  ActivityEvent,
} from './runtime/types.js';

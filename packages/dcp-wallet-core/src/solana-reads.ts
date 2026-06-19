/**
 * Solana read helpers — read-only Solana data backing the wallet read tools
 * (balances, transaction status, transaction history, token search). These are
 * PUBLIC RPC reads — no private key is ever used here, so they require no consent.
 *
 * Design rules:
 *  - The RPC endpoint is a CONFIG parameter, never a hardcoded secret. Hosts inject
 *    DCP_SOLANA_RPC_URL (e.g. their proxy); otherwise the public mainnet default is
 *    used. The endpoint is NOT an agent-supplied tool param, so an agent cannot point
 *    reads at an arbitrary RPC to dodge a host's proxy.
 *  - Cost controls: a short-TTL cache + hard limit caps so a chatty agent cannot fan
 *    out unbounded RPC calls. History returns signatures + light metadata only (it
 *    never fans out to getTransaction).
 *
 * Connection and fetch are injectable for hermetic unit tests.
 */

import { Connection, PublicKey, LAMPORTS_PER_SOL } from '@solana/web3.js';

// ============================================================================
// Constants & config
// ============================================================================

const DEFAULT_RPC_URL = 'https://api.mainnet-beta.solana.com';
const DEFAULT_JUPITER_SEARCH_URL = 'https://lite-api.jup.ag/tokens/v2/search';
const RPC_TIMEOUT_MS = 10_000;
const CACHE_TTL_MS = 10_000;
const CONFIRM_TIMEOUT_MS = 30_000; // PRD §10.7: non-blocking return after this
const CONFIRM_POLL_MS = 2_000;

const HISTORY_DEFAULT_LIMIT = 20;
const HISTORY_MAX_LIMIT = 50; // PRD §10.3 hard cap
const SEARCH_DEFAULT_LIMIT = 10;
const SEARCH_MAX_LIMIT = 20;
// Cap the token list so an active wallet with hundreds of dust tokens can't
// flood an agent's context. Known/tagged tokens are prioritized.
const MAX_BALANCE_TOKENS = 50;

const SOLANA_EXPLORER_TX = 'https://solscan.io/tx/';

// Classic SPL Token program. USDC/USDT/1LY are all classic SPL.
const TOKEN_PROGRAM_ID = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');

// Well-known mints for friendly symbol tagging.
const KNOWN_MINTS: Record<string, string> = {
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: 'USDC',
  Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB: 'USDT',
  Aih3sbAbu39Yn7jB2Qf4btZ5eWtDGQJH2gMfC4qdBAGS: '1LY',
};

// Base58 signature: 64-byte sig → 86-88 base58 chars. Loose but excludes junk.
const BASE58_SIG_RE = /^[1-9A-HJ-NP-Za-km-z]{64,90}$/;

/**
 * Thrown for caller-supplied bad input (malformed address/signature) so callers
 * can map it to an InvalidParams error rather than an internal error.
 */
export class ReadInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReadInputError';
  }
}

// ============================================================================
// Public result types
// ============================================================================

export interface TokenBalance {
  mint: string;
  symbol?: string;
  amount: string; // raw integer string
  decimals: number;
  ui: number; // human-readable amount
}

export interface SolanaBalances {
  address: string;
  sol: { lamports: number; ui: number };
  tokens: TokenBalance[];
  /** Total non-zero SPL token holdings before the response cap. */
  total_tokens: number;
  /** True when `tokens` was truncated to MAX_BALANCE_TOKENS. */
  truncated: boolean;
}

export type SignatureStatus = 'processed' | 'confirmed' | 'finalized' | 'failed' | 'not_found';

export interface TxStatusResult {
  signature: string;
  status: SignatureStatus;
  slot?: number;
  confirmations?: number | null;
  err?: unknown;
  explorer_url: string;
}

export interface TxHistoryItem {
  signature: string;
  slot: number;
  block_time?: number | null;
  status: SignatureStatus;
  err?: unknown;
  memo?: string | null;
  explorer_url: string;
}

export interface TxHistoryResult {
  address: string;
  count: number;
  transactions: TxHistoryItem[];
}

export interface TokenSearchItem {
  mint: string;
  symbol?: string;
  name?: string;
  decimals?: number;
  icon?: string;
}

export interface TokenSearchResult {
  query: string;
  count: number;
  tokens: TokenSearchItem[];
}

export type ConfirmStatus = 'submitted' | 'processed' | 'confirmed' | 'finalized' | 'failed';

export interface ConfirmResult {
  signature: string;
  status: ConfirmStatus;
  slot?: number;
  err?: unknown;
  explorer_url: string;
}

// ============================================================================
// Minimal RPC surface (so tests can inject a mock without @solana/web3.js)
// ============================================================================

interface ParsedTokenAccount {
  account: {
    data: {
      parsed: {
        info: {
          mint: string;
          tokenAmount: {
            amount: string;
            decimals: number;
            uiAmount: number | null;
          };
        };
      };
    };
  };
}

interface SignatureInfo {
  signature: string;
  slot: number;
  blockTime?: number | null;
  err: unknown;
  confirmationStatus?: string;
  memo?: string | null;
}

export interface SolanaRpc {
  getBalance(pubkey: PublicKey): Promise<number>;
  getParsedTokenAccountsByOwner(
    owner: PublicKey,
    filter: { programId: PublicKey }
  ): Promise<{ value: ParsedTokenAccount[] }>;
  getSignatureStatuses(
    signatures: string[],
    config?: { searchTransactionHistory?: boolean }
  ): Promise<{ value: Array<SignatureStatusInfo | null> }>;
  getSignaturesForAddress(
    address: PublicKey,
    options?: { limit?: number; before?: string }
  ): Promise<SignatureInfo[]>;
  getLatestBlockhash(): Promise<{ blockhash: string; lastValidBlockHeight: number }>;
  sendRawTransaction(
    raw: Buffer | Uint8Array,
    options?: { skipPreflight?: boolean; maxRetries?: number }
  ): Promise<string>;
}

interface SignatureStatusInfo {
  slot: number;
  confirmations: number | null;
  err: unknown;
  confirmationStatus?: string;
}

// ============================================================================
// Pure helpers (exported for unit tests)
// ============================================================================

/** Resolve the RPC URL: explicit override → env → public mainnet default. */
export function resolveSolanaRpcUrl(override?: string): string {
  return override || process.env.DCP_SOLANA_RPC_URL || DEFAULT_RPC_URL;
}

/** Clamp a requested history limit into [1, HISTORY_MAX_LIMIT]. */
export function clampHistoryLimit(requested?: number): number {
  if (typeof requested !== 'number' || !Number.isFinite(requested)) return HISTORY_DEFAULT_LIMIT;
  return Math.max(1, Math.min(HISTORY_MAX_LIMIT, Math.floor(requested)));
}

/** Clamp a requested search limit into [1, SEARCH_MAX_LIMIT]. */
export function clampSearchLimit(requested?: number): number {
  if (typeof requested !== 'number' || !Number.isFinite(requested)) return SEARCH_DEFAULT_LIMIT;
  return Math.max(1, Math.min(SEARCH_MAX_LIMIT, Math.floor(requested)));
}

/** Map a raw signature-status value into a coarse status string. */
export function mapSignatureStatus(value: SignatureStatusInfo | null | undefined): SignatureStatus {
  if (!value) return 'not_found';
  if (value.err) return 'failed';
  const cs = value.confirmationStatus;
  if (cs === 'finalized' || cs === 'confirmed' || cs === 'processed') return cs;
  return 'processed';
}

function historyItemStatus(info: SignatureInfo): SignatureStatus {
  if (info.err) return 'failed';
  const cs = info.confirmationStatus;
  if (cs === 'finalized' || cs === 'confirmed' || cs === 'processed') return cs;
  return 'confirmed';
}

/** Friendly symbol for a mint, if known. */
export function tagSymbol(mint: string): string | undefined {
  return KNOWN_MINTS[mint];
}

/** Parse a Jupiter token-search response into our shape. */
export function parseJupiterSearch(raw: unknown, limit: number): TokenSearchItem[] {
  if (!Array.isArray(raw)) return [];
  const items: TokenSearchItem[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') continue;
    const e = entry as Record<string, unknown>;
    const mint = typeof e.id === 'string' ? e.id : typeof e.address === 'string' ? e.address : undefined;
    if (!mint) continue;
    items.push({
      mint,
      symbol: typeof e.symbol === 'string' ? e.symbol : undefined,
      name: typeof e.name === 'string' ? e.name : undefined,
      decimals: typeof e.decimals === 'number' ? e.decimals : undefined,
      icon: typeof e.icon === 'string' ? e.icon : undefined,
    });
    if (items.length >= limit) break;
  }
  return items;
}

function toPublicKey(address: string): PublicKey {
  try {
    return new PublicKey(address);
  } catch {
    throw new ReadInputError(`Invalid Solana address: ${address}`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function timeoutFetch(fetchImpl: typeof fetch, timeoutMs: number): typeof fetch {
  return ((input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const timeout = typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function'
      ? AbortSignal.timeout(timeoutMs)
      : undefined;
    if (timeout) {
      return fetchImpl(input, { ...init, signal: timeout });
    }

    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    if (!controller) {
      return fetchImpl(input, init);
    }
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    return fetchImpl(input, { ...init, signal: controller.signal }).finally(() => clearTimeout(timer));
  }) as typeof fetch;
}

// ============================================================================
// SolanaReader
// ============================================================================

export interface SolanaReaderOptions {
  /** Explicit RPC URL override; otherwise env DCP_SOLANA_RPC_URL or public mainnet. */
  rpcUrl?: string;
  /** Inject an RPC client (tests). Defaults to a real @solana/web3.js Connection. */
  connection?: SolanaRpc;
  /** Inject fetch (tests / token search). Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Jupiter token-search base URL override. */
  jupiterSearchUrl?: string;
  /** Cache TTL in ms (default 10s). */
  cacheTtlMs?: number;
  /** Clock injection for cache expiry (tests). */
  now?: () => number;
}

export class SolanaReader {
  private readonly rpcUrl: string;
  private readonly injectedConnection?: SolanaRpc;
  private lazyConnection?: SolanaRpc;
  private readonly fetchImpl: typeof fetch;
  private readonly jupiterSearchUrl: string;
  private readonly cacheTtlMs: number;
  private readonly now: () => number;
  private readonly cache = new Map<string, { value: unknown; expiresAt: number }>();

  constructor(options: SolanaReaderOptions = {}) {
    this.rpcUrl = resolveSolanaRpcUrl(options.rpcUrl);
    this.injectedConnection = options.connection;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.jupiterSearchUrl = options.jupiterSearchUrl ?? DEFAULT_JUPITER_SEARCH_URL;
    this.cacheTtlMs = options.cacheTtlMs ?? CACHE_TTL_MS;
    this.now = options.now ?? Date.now;
  }

  private rpc(): SolanaRpc {
    if (this.injectedConnection) return this.injectedConnection;
    if (!this.lazyConnection) {
      this.lazyConnection = new Connection(this.rpcUrl, {
        commitment: 'confirmed',
        fetch: timeoutFetch(this.fetchImpl, RPC_TIMEOUT_MS),
      }) as unknown as SolanaRpc;
    }
    return this.lazyConnection;
  }

  private async cached<T>(key: string, produce: () => Promise<T>): Promise<T> {
    const hit = this.cache.get(key);
    const t = this.now();
    if (hit && hit.expiresAt > t) return hit.value as T;
    const value = await produce();
    this.cache.set(key, { value, expiresAt: t + this.cacheTtlMs });
    return value;
  }

  /** SOL + SPL token balances for an address (cached). */
  async getBalances(address: string): Promise<SolanaBalances> {
    const owner = toPublicKey(address);
    return this.cached(`bal:${address}`, async () => {
      const rpc = this.rpc();
      const [lamports, parsed] = await Promise.all([
        rpc.getBalance(owner),
        rpc.getParsedTokenAccountsByOwner(owner, { programId: TOKEN_PROGRAM_ID }),
      ]);

      const allTokens: TokenBalance[] = [];
      for (const acct of parsed.value) {
        const info = acct.account?.data?.parsed?.info;
        if (!info) continue;
        const amount = info.tokenAmount.amount;
        if (!amount || amount === '0') continue;
        allTokens.push({
          mint: info.mint,
          symbol: tagSymbol(info.mint),
          amount,
          decimals: info.tokenAmount.decimals,
          ui: info.tokenAmount.uiAmount ?? 0,
        });
      }

      // Prioritize known/tagged tokens (USDC, USDT, 1LY), then by balance, so the
      // capped list shows what matters rather than arbitrary dust.
      allTokens.sort((a, b) => {
        const ka = a.symbol ? 1 : 0;
        const kb = b.symbol ? 1 : 0;
        if (ka !== kb) return kb - ka;
        return b.ui - a.ui;
      });

      return {
        address,
        sol: { lamports, ui: lamports / LAMPORTS_PER_SOL },
        tokens: allTokens.slice(0, MAX_BALANCE_TOKENS),
        total_tokens: allTokens.length,
        truncated: allTokens.length > MAX_BALANCE_TOKENS,
      };
    });
  }

  /** Status of a single transaction signature (not cached — it changes). */
  async getTxStatus(signature: string): Promise<TxStatusResult> {
    if (!BASE58_SIG_RE.test(signature)) {
      throw new ReadInputError('Invalid transaction signature');
    }
    const rpc = this.rpc();
    const res = await rpc.getSignatureStatuses([signature], { searchTransactionHistory: true });
    const value = res.value?.[0] ?? null;
    return {
      signature,
      status: mapSignatureStatus(value),
      slot: value?.slot,
      confirmations: value?.confirmations,
      err: value?.err ?? undefined,
      explorer_url: SOLANA_EXPLORER_TX + signature,
    };
  }

  /** Recent transaction signatures for an address (cached, capped, no fan-out). */
  async getTxHistory(address: string, options?: { limit?: number; before?: string }): Promise<TxHistoryResult> {
    const owner = toPublicKey(address);
    const limit = clampHistoryLimit(options?.limit);
    const before = options?.before;
    return this.cached(`hist:${address}:${limit}:${before ?? ''}`, async () => {
      const rpc = this.rpc();
      const sigs = await rpc.getSignaturesForAddress(owner, { limit, before });
      const transactions: TxHistoryItem[] = sigs.map((s) => ({
        signature: s.signature,
        slot: s.slot,
        block_time: s.blockTime ?? null,
        status: historyItemStatus(s),
        err: s.err ?? undefined,
        memo: s.memo ?? null,
        explorer_url: SOLANA_EXPLORER_TX + s.signature,
      }));
      return { address, count: transactions.length, transactions };
    });
  }

  /** Search the Jupiter token list (cached). Degrades gracefully on failure. */
  async searchTokens(query: string, limit?: number): Promise<TokenSearchResult> {
    const trimmed = (query ?? '').trim();
    if (!trimmed) return { query: trimmed, count: 0, tokens: [] };
    const max = clampSearchLimit(limit);
    return this.cached(`tok:${trimmed}:${max}`, async () => {
      const url = `${this.jupiterSearchUrl}?query=${encodeURIComponent(trimmed)}`;
      const res = await timeoutFetch(this.fetchImpl, RPC_TIMEOUT_MS)(url, {
        headers: { accept: 'application/json' },
      });
      if (!res.ok) {
        throw new Error(`Token search failed (${res.status})`);
      }
      const raw = await res.json();
      const tokens = parseJupiterSearch(raw, max);
      return { query: trimmed, count: tokens.length, tokens };
    });
  }

  /** Fetch a recent blockhash for building a transaction (not cached). */
  async getLatestBlockhash(): Promise<{ blockhash: string; lastValidBlockHeight: number }> {
    return this.rpc().getLatestBlockhash();
  }

  /** Broadcast a base64 signed transaction; returns the signature. */
  async submitTransaction(signedTxBase64: string): Promise<string> {
    const raw = Buffer.from(signedTxBase64, 'base64');
    return this.rpc().sendRawTransaction(raw, { skipPreflight: false, maxRetries: 3 });
  }

  /**
   * Poll a signature to commitment. Returns as soon as it is confirmed/finalized
   * or failed; on timeout returns a non-blocking `submitted` status (PRD §10.7)
   * so the agent can poll vault_get_tx_status rather than hang.
   */
  async confirmSignature(
    signature: string,
    options?: { timeoutMs?: number; pollMs?: number }
  ): Promise<ConfirmResult> {
    const timeoutMs = options?.timeoutMs ?? CONFIRM_TIMEOUT_MS;
    const pollMs = options?.pollMs ?? CONFIRM_POLL_MS;
    const explorer_url = SOLANA_EXPLORER_TX + signature;
    const start = this.now();
    const rpc = this.rpc();

    for (;;) {
      const res = await rpc.getSignatureStatuses([signature], { searchTransactionHistory: true });
      const value = res.value?.[0] ?? null;
      const status = mapSignatureStatus(value);
      if (status === 'failed' || status === 'confirmed' || status === 'finalized') {
        return { signature, status, slot: value?.slot, err: value?.err ?? undefined, explorer_url };
      }
      if (this.now() - start >= timeoutMs) {
        // Not yet visible/processed within the window — hand back to the agent.
        return { signature, status: status === 'processed' ? 'processed' : 'submitted', explorer_url };
      }
      await sleep(pollMs);
    }
  }
}

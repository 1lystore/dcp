import { describe, expect, it, vi } from 'vitest';
import { PublicKey } from '@solana/web3.js';
import {
  SolanaReader,
  clampHistoryLimit,
  clampSearchLimit,
  mapSignatureStatus,
  parseJupiterSearch,
  resolveSolanaRpcUrl,
  tagSymbol,
  type SolanaRpc,
} from '../src/solana-reads.js';

const OWNER = '5xJ8Xy9aRMfHV6oC1yQF3W8m6sQF8eD1yU6tQ8rJ7aBc';
const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const SIG = '5'.repeat(88);

function makeRpc(overrides: Partial<SolanaRpc> = {}): SolanaRpc {
  return {
    getBalance: vi.fn(async () => 0),
    getParsedTokenAccountsByOwner: vi.fn(async () => ({ value: [] })),
    getSignatureStatuses: vi.fn(async () => ({ value: [null] })),
    getSignaturesForAddress: vi.fn(async () => []),
    getLatestBlockhash: vi.fn(async () => ({ blockhash: 'GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi', lastValidBlockHeight: 1 })),
    sendRawTransaction: vi.fn(async () => '5'.repeat(88)),
    ...overrides,
  };
}

describe('pure helpers', () => {
  it('clampHistoryLimit enforces [1,50] and default 20', () => {
    expect(clampHistoryLimit(undefined)).toBe(20);
    expect(clampHistoryLimit(0)).toBe(1);
    expect(clampHistoryLimit(5)).toBe(5);
    expect(clampHistoryLimit(999)).toBe(50);
    expect(clampHistoryLimit(NaN)).toBe(20);
    expect(clampHistoryLimit(7.9)).toBe(7);
  });

  it('clampSearchLimit enforces [1,20] and default 10', () => {
    expect(clampSearchLimit(undefined)).toBe(10);
    expect(clampSearchLimit(100)).toBe(20);
    expect(clampSearchLimit(3)).toBe(3);
  });

  it('mapSignatureStatus maps null/err/confirmation', () => {
    expect(mapSignatureStatus(null)).toBe('not_found');
    expect(mapSignatureStatus({ slot: 1, confirmations: 0, err: { x: 1 } })).toBe('failed');
    expect(mapSignatureStatus({ slot: 1, confirmations: 1, err: null, confirmationStatus: 'finalized' })).toBe('finalized');
    expect(mapSignatureStatus({ slot: 1, confirmations: 1, err: null })).toBe('processed');
  });

  it('tagSymbol knows USDC, unknown returns undefined', () => {
    expect(tagSymbol(USDC_MINT)).toBe('USDC');
    expect(tagSymbol('SomeRandomMint1111111111111111111111111111')).toBeUndefined();
  });

  it('parseJupiterSearch maps id→mint and respects the limit', () => {
    const raw = [
      { id: USDC_MINT, symbol: 'USDC', name: 'USD Coin', decimals: 6, icon: 'x' },
      { id: 'mint2', symbol: 'AAA', decimals: 9 },
      { symbol: 'no-id-skipped' },
    ];
    const out = parseJupiterSearch(raw, 1);
    expect(out).toEqual([{ mint: USDC_MINT, symbol: 'USDC', name: 'USD Coin', decimals: 6, icon: 'x' }]);
    expect(parseJupiterSearch('not-an-array', 5)).toEqual([]);
  });

  it('resolveSolanaRpcUrl: override > env > default', () => {
    expect(resolveSolanaRpcUrl('https://override.test')).toBe('https://override.test');
    const prev = process.env.DCP_SOLANA_RPC_URL;
    process.env.DCP_SOLANA_RPC_URL = 'https://env.test';
    expect(resolveSolanaRpcUrl()).toBe('https://env.test');
    if (prev === undefined) delete process.env.DCP_SOLANA_RPC_URL;
    else process.env.DCP_SOLANA_RPC_URL = prev;
  });
});

describe('SolanaReader.getBalances', () => {
  it('returns SOL + non-zero SPL tokens with USDC tagged', async () => {
    const rpc = makeRpc({
      getBalance: vi.fn(async () => 1_500_000_000), // 1.5 SOL
      getParsedTokenAccountsByOwner: vi.fn(async () => ({
        value: [
          { account: { data: { parsed: { info: { mint: USDC_MINT, tokenAmount: { amount: '2500000', decimals: 6, uiAmount: 2.5 } } } } } },
          { account: { data: { parsed: { info: { mint: 'zeroMint', tokenAmount: { amount: '0', decimals: 0, uiAmount: 0 } } } } } },
        ],
      })),
    });
    const reader = new SolanaReader({ connection: rpc });
    const out = await reader.getBalances(OWNER);
    expect(out.sol.ui).toBe(1.5);
    expect(out.tokens).toHaveLength(1); // zero-balance filtered out
    expect(out.tokens[0]).toMatchObject({ mint: USDC_MINT, symbol: 'USDC', ui: 2.5 });
    expect(out.total_tokens).toBe(1);
    expect(out.truncated).toBe(false);
  });

  it('caps to 50 tokens, prioritizing tagged tokens, and flags truncation', async () => {
    const value = [
      // 60 untagged dust tokens with tiny balances
      ...Array.from({ length: 60 }, (_, i) => ({
        account: { data: { parsed: { info: { mint: `dust${i}`, tokenAmount: { amount: '1', decimals: 0, uiAmount: 1 } } } } },
      })),
      // one tagged USDC at the end of the raw list
      { account: { data: { parsed: { info: { mint: USDC_MINT, tokenAmount: { amount: '5000000', decimals: 6, uiAmount: 5 } } } } } },
    ];
    const reader = new SolanaReader({
      connection: makeRpc({ getParsedTokenAccountsByOwner: vi.fn(async () => ({ value })) }),
    });
    const out = await reader.getBalances(OWNER);
    expect(out.total_tokens).toBe(61);
    expect(out.tokens).toHaveLength(50);
    expect(out.truncated).toBe(true);
    expect(out.tokens[0]).toMatchObject({ symbol: 'USDC' }); // tagged token floated to top
  });

  it('rejects an invalid address before any RPC call', async () => {
    const rpc = makeRpc();
    const reader = new SolanaReader({ connection: rpc });
    await expect(reader.getBalances('not-a-valid-address')).rejects.toThrow(/Invalid Solana address/);
    expect(rpc.getBalance).not.toHaveBeenCalled();
  });

  it('caches within the TTL window', async () => {
    const rpc = makeRpc({ getBalance: vi.fn(async () => 1) });
    let clock = 1000;
    const reader = new SolanaReader({ connection: rpc, now: () => clock, cacheTtlMs: 10_000 });
    await reader.getBalances(OWNER);
    await reader.getBalances(OWNER);
    expect(rpc.getBalance).toHaveBeenCalledTimes(1); // second hit served from cache
    clock += 20_000;
    await reader.getBalances(OWNER);
    expect(rpc.getBalance).toHaveBeenCalledTimes(2); // expired → refetch
  });
});

describe('SolanaReader.getTxStatus', () => {
  it('rejects malformed signatures', async () => {
    const reader = new SolanaReader({ connection: makeRpc() });
    await expect(reader.getTxStatus('bad sig!')).rejects.toThrow(/Invalid transaction signature/);
  });

  it('returns mapped status + explorer url', async () => {
    const rpc = makeRpc({
      getSignatureStatuses: vi.fn(async () => ({ value: [{ slot: 42, confirmations: null, err: null, confirmationStatus: 'finalized' }] })),
    });
    const reader = new SolanaReader({ connection: rpc });
    const out = await reader.getTxStatus(SIG);
    expect(out.status).toBe('finalized');
    expect(out.slot).toBe(42);
    expect(out.explorer_url).toContain(SIG);
  });
});

describe('SolanaReader.getTxHistory', () => {
  it('clamps the limit and maps items without fanning out', async () => {
    const getSignaturesForAddress = vi.fn(async () => [
      { signature: SIG, slot: 10, blockTime: 1700, err: null, confirmationStatus: 'confirmed', memo: null },
    ]);
    const reader = new SolanaReader({ connection: makeRpc({ getSignaturesForAddress }) });
    const out = await reader.getTxHistory(OWNER, { limit: 999 });
    expect(getSignaturesForAddress).toHaveBeenCalledWith(expect.any(PublicKey), { limit: 50, before: undefined });
    expect(out.count).toBe(1);
    expect(out.transactions[0]).toMatchObject({ signature: SIG, status: 'confirmed', block_time: 1700 });
  });
});

describe('SolanaReader.searchTokens', () => {
  it('fetches Jupiter and parses results', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify([{ id: USDC_MINT, symbol: 'USDC', decimals: 6 }]), { status: 200 }));
    const reader = new SolanaReader({ connection: makeRpc(), fetchImpl: fetchImpl as unknown as typeof fetch });
    const out = await reader.searchTokens('USDC', 5);
    expect(out.count).toBe(1);
    expect(out.tokens[0].mint).toBe(USDC_MINT);
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it('returns empty for blank query without calling fetch', async () => {
    const fetchImpl = vi.fn();
    const reader = new SolanaReader({ connection: makeRpc(), fetchImpl: fetchImpl as unknown as typeof fetch });
    const out = await reader.searchTokens('   ');
    expect(out).toEqual({ query: '', count: 0, tokens: [] });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('throws on non-OK response', async () => {
    const fetchImpl = vi.fn(async () => new Response('nope', { status: 500 }));
    const reader = new SolanaReader({ connection: makeRpc(), fetchImpl: fetchImpl as unknown as typeof fetch });
    await expect(reader.searchTokens('USDC')).rejects.toThrow(/Token search failed/);
  });
});

describe('SolanaReader submit/confirm', () => {
  it('submitTransaction decodes base64 and returns the signature', async () => {
    const sendRawTransaction = vi.fn(async () => SIG);
    const reader = new SolanaReader({ connection: makeRpc({ sendRawTransaction }) });
    const sig = await reader.submitTransaction(Buffer.from('hello').toString('base64'));
    expect(sig).toBe(SIG);
    const passed = sendRawTransaction.mock.calls[0][0] as Buffer;
    expect(Buffer.from(passed).toString()).toBe('hello');
  });

  it('confirmSignature returns confirmed when status reaches confirmed', async () => {
    const reader = new SolanaReader({
      connection: makeRpc({
        getSignatureStatuses: vi.fn(async () => ({ value: [{ slot: 9, confirmations: 1, err: null, confirmationStatus: 'confirmed' }] })),
      }),
    });
    const out = await reader.confirmSignature(SIG, { timeoutMs: 1000, pollMs: 1 });
    expect(out.status).toBe('confirmed');
    expect(out.slot).toBe(9);
  });

  it('confirmSignature returns non-blocking submitted on timeout', async () => {
    const reader = new SolanaReader({
      connection: makeRpc({ getSignatureStatuses: vi.fn(async () => ({ value: [null] })) }),
    });
    const out = await reader.confirmSignature(SIG, { timeoutMs: 0, pollMs: 1 });
    expect(out.status).toBe('submitted');
  });

  it('confirmSignature returns failed when the tx errored', async () => {
    const reader = new SolanaReader({
      connection: makeRpc({
        getSignatureStatuses: vi.fn(async () => ({ value: [{ slot: 9, confirmations: 0, err: { InstructionError: [] }, confirmationStatus: 'processed' }] })),
      }),
    });
    const out = await reader.confirmSignature(SIG, { timeoutMs: 1000, pollMs: 1 });
    expect(out.status).toBe('failed');
  });
});

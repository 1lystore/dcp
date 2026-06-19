import { describe, it, expect, afterEach, vi } from 'vitest';
import { jupiterQuote, jupiterBuildSwapTx, DEFAULT_JUPITER_API, VaultError } from '../src/index.js';

const WSOL = 'So11111111111111111111111111111111111111112';
const USDC = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const OWNER = 'Dq9XEjvhYbSdWQbzbi3LDsjPJvU2n8FYiw3QnSgnHFVm';

afterEach(() => vi.unstubAllGlobals());

function ok(json: unknown) {
  return { ok: true, status: 200, json: async () => json } as Response;
}

describe('jupiterQuote', () => {
  const args = { inputMint: WSOL, outputMint: USDC, amountBaseUnits: '1000000', slippageBps: 50 };

  it('builds the quote URL from the request and returns the quote', async () => {
    let calledUrl = '';
    vi.stubGlobal('fetch', vi.fn(async (url: string) => { calledUrl = String(url); return ok({ outAmount: '500' }); }));
    const q = await jupiterQuote({ apiBase: DEFAULT_JUPITER_API }, args);
    expect(q.outAmount).toBe('500');
    expect(calledUrl).toContain(`inputMint=${WSOL}`);
    expect(calledUrl).toContain(`outputMint=${USDC}`);
    expect(calledUrl).toContain('amount=1000000');
    expect(calledUrl).toContain('slippageBps=50');
  });

  it('adds platformFeeBps ONLY when both a rate and an account are set', async () => {
    let url = '';
    vi.stubGlobal('fetch', vi.fn(async (u: string) => { url = String(u); return ok({ outAmount: '1' }); }));

    await jupiterQuote({ apiBase: DEFAULT_JUPITER_API, feeBps: 50, feeAccount: 'FeeAcct' }, args);
    expect(url).toContain('platformFeeBps=50');

    await jupiterQuote({ apiBase: DEFAULT_JUPITER_API, feeBps: 50 }, args); // no account
    expect(url).not.toContain('platformFeeBps');

    await jupiterQuote({ apiBase: DEFAULT_JUPITER_API, feeBps: 0, feeAccount: 'FeeAcct' }, args); // zero rate
    expect(url).not.toContain('platformFeeBps');
  });

  it('retries a transient fetch failure, then succeeds', async () => {
    let n = 0;
    vi.stubGlobal('fetch', vi.fn(async () => { if (n++ === 0) throw new Error('blip'); return ok({ outAmount: '7' }); }));
    const q = await jupiterQuote({ apiBase: DEFAULT_JUPITER_API }, args);
    expect(q.outAmount).toBe('7');
    expect(n).toBe(2);
  });

  it('throws on a non-ok response', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 503 }) as Response));
    await expect(jupiterQuote({ apiBase: DEFAULT_JUPITER_API }, args)).rejects.toThrowError(VaultError);
  });
});

describe('jupiterBuildSwapTx', () => {
  const quote = { inputMint: WSOL, outputMint: USDC };

  it('posts the quote + owner and returns the swap tx', async () => {
    let body: any;
    vi.stubGlobal('fetch', vi.fn(async (_u: string, init: RequestInit) => {
      body = JSON.parse(String(init.body));
      return ok({ swapTransaction: 'BASE64TX' });
    }));
    const tx = await jupiterBuildSwapTx({ apiBase: DEFAULT_JUPITER_API }, quote, OWNER);
    expect(tx).toBe('BASE64TX');
    expect(body.userPublicKey).toBe(OWNER);
    expect(body.quoteResponse).toEqual(quote);
    expect(body.feeAccount).toBeUndefined();
  });

  it('includes feeAccount only when the fee is enabled', async () => {
    let body: any;
    vi.stubGlobal('fetch', vi.fn(async (_u: string, init: RequestInit) => {
      body = JSON.parse(String(init.body));
      return ok({ swapTransaction: 'X' });
    }));
    await jupiterBuildSwapTx({ apiBase: DEFAULT_JUPITER_API, feeBps: 50, feeAccount: 'FeeAcct' }, quote, OWNER);
    expect(body.feeAccount).toBe('FeeAcct');
  });

  it('throws when Jupiter returns no swap transaction', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ok({})));
    await expect(jupiterBuildSwapTx({ apiBase: DEFAULT_JUPITER_API }, quote, OWNER)).rejects.toThrowError(VaultError);
  });
});

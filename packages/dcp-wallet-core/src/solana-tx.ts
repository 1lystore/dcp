/**
 * Pure Solana transaction logic — the shared "wallet brain".
 *
 * Build, decode, and validate transactions. No private keys, no storage, no I/O,
 * no native deps — only @solana/web3.js + @solana/spl-token, so this is safe to
 * import identically from Node (vault server), the browser, and React Native
 * (mobile). Signing is NEVER done here; callers sign through a platform Signer.
 *
 * Moved verbatim out of @dcprotocol/core/wallet.ts (which carries native deps and
 * cannot be imported by React Native). @dcprotocol/core now re-exports these.
 */

import {
  PublicKey,
  Transaction,
  VersionedTransaction,
  SystemProgram,
  ComputeBudgetProgram,
  TransactionInstruction,
  LAMPORTS_PER_SOL,
} from '@solana/web3.js';
import {
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccountInstruction,
  createTransferCheckedInstruction,
} from '@solana/spl-token';
import { VaultError } from './errors.js';

/**
 * Build an UNSIGNED Solana SOL transfer (legacy tx, base64) from a structured
 * intent. The vault later signs it only after budget + consent are satisfied.
 * Fee-payer is always the sender — DCP never sponsors gas.
 *
 * @param fromAddress - Sender (the vault wallet) base58 address; also fee-payer
 * @param toAddress   - Recipient base58 address
 * @param amountSol   - Amount of SOL to send (e.g. 0.05)
 * @param blockhash   - A recent blockhash fetched from RPC
 * @returns Base64-encoded unsigned legacy transaction (ready for signTransaction)
 */
export function buildSolanaTransferTx(
  fromAddress: string,
  toAddress: string,
  amountSol: number,
  blockhash: string,
  options?: {
    /** Priority fee in micro-lamports per compute unit (helps land during congestion). */
    priorityFeeMicroLamports?: number;
    /** Per-transfer nonce embedded as a memo so distinct transfers never collide. */
    memo?: string;
  }
): string {
  let from: PublicKey;
  let to: PublicKey;
  try {
    from = new PublicKey(fromAddress);
  } catch {
    throw new VaultError('INVALID_CHAIN', `Invalid from address: ${fromAddress}`);
  }
  try {
    to = new PublicKey(toAddress);
  } catch {
    throw new VaultError('INVALID_CHAIN', `Invalid to address: ${toAddress}`);
  }
  if (from.equals(to)) {
    throw new VaultError('INVALID_CHAIN', 'Refusing to build a self-transfer (from == to)');
  }
  if (typeof amountSol !== 'number' || !Number.isFinite(amountSol) || amountSol <= 0) {
    throw new VaultError('INVALID_CHAIN', 'amount must be a positive number of SOL');
  }
  const lamports = Math.round(amountSol * LAMPORTS_PER_SOL);
  if (lamports <= 0) {
    throw new VaultError('INVALID_CHAIN', 'amount is too small (rounds to 0 lamports)');
  }
  if (!blockhash) {
    throw new VaultError('INVALID_CHAIN', 'blockhash is required to build the transaction');
  }

  const tx = new Transaction();
  tx.feePayer = from;
  tx.recentBlockhash = blockhash;

  // Priority fee (compute-unit price) so the transfer lands during congestion.
  // Default is a small non-zero tip; pass 0 to disable.
  const priorityFee = options?.priorityFeeMicroLamports ?? 1000;
  if (priorityFee > 0) {
    tx.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: priorityFee }));
  }

  tx.add(SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports }));

  if (options?.memo) tx.add(memoInstruction(options.memo));

  return tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');
}

/** Derive the Associated Token Account address for (mint, owner). Pure. */
export function getSolanaAtaAddress(mint: string, owner: string): string {
  return getAssociatedTokenAddressSync(new PublicKey(mint), new PublicKey(owner)).toBase58();
}

// SPL Memo program — used to embed a per-transfer nonce so two distinct transfers
// with identical from/to/amount (and a cached blockhash) never produce the same
// transaction signature. Same nonce → same tx (idempotent); different nonce →
// different tx (distinct send).
const MEMO_PROGRAM_ID = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
function memoInstruction(memo: string): TransactionInstruction {
  return new TransactionInstruction({ keys: [], programId: MEMO_PROGRAM_ID, data: Buffer.from(memo, 'utf8') });
}

/** Convert a human token amount to base units (bigint) without float error. */
function toBaseUnits(amount: number, decimals: number): bigint {
  if (typeof amount !== 'number' || !Number.isFinite(amount) || amount <= 0) {
    throw new VaultError('INVALID_CHAIN', 'amount must be a positive number');
  }
  // Bound `decimals` (a user-supplied value) BEFORE it feeds string/bigint sizing.
  // Without this, a huge `decimals` makes `'0'.repeat(decimals)` (and toFixed/10n**)
  // allocate unbounded memory — a denial-of-service vector. No real SPL token exceeds
  // a handful of decimals; 18 is a generous ceiling.
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) {
    throw new VaultError('INVALID_CHAIN', 'decimals must be an integer between 0 and 18');
  }
  const fixed = amount.toFixed(decimals);
  const [whole, frac = ''] = fixed.split('.');
  const raw = BigInt(whole) * 10n ** BigInt(decimals) + BigInt((frac + '0'.repeat(decimals)).slice(0, decimals) || '0');
  if (raw <= 0n) {
    throw new VaultError('INVALID_CHAIN', 'amount is too small for this token');
  }
  return raw;
}

/**
 * Build an UNSIGNED SPL token transfer (e.g. USDC) from a structured intent.
 *
 * If the recipient has never held this token (no Associated Token Account), the
 * transaction CREATES their ATA first — paid by the sender — so sending to a
 * brand-new wallet "just works", the way Phantom does. Fee-payer is the sender.
 *
 * @param createRecipientAta - true when the recipient's ATA does not yet exist
 *                             (the caller checks this via RPC before building)
 */
export function buildSplTransferTx(params: {
  fromAddress: string;
  toAddress: string;
  mint: string;
  amount: number;
  decimals: number;
  blockhash: string;
  createRecipientAta: boolean;
  priorityFeeMicroLamports?: number;
  /** Per-transfer nonce embedded as a memo so distinct transfers never collide. */
  memo?: string;
}): string {
  let from: PublicKey;
  let to: PublicKey;
  let mint: PublicKey;
  try {
    from = new PublicKey(params.fromAddress);
  } catch {
    throw new VaultError('INVALID_CHAIN', `Invalid from address: ${params.fromAddress}`);
  }
  try {
    to = new PublicKey(params.toAddress);
  } catch {
    throw new VaultError('INVALID_CHAIN', `Invalid to address: ${params.toAddress}`);
  }
  try {
    mint = new PublicKey(params.mint);
  } catch {
    throw new VaultError('INVALID_CHAIN', `Invalid token mint: ${params.mint}`);
  }
  if (from.equals(to)) {
    throw new VaultError('INVALID_CHAIN', 'Refusing to build a self-transfer (from == to)');
  }
  if (!params.blockhash) {
    throw new VaultError('INVALID_CHAIN', 'blockhash is required to build the transaction');
  }
  const rawAmount = toBaseUnits(params.amount, params.decimals);

  const fromAta = getAssociatedTokenAddressSync(mint, from);
  const toAta = getAssociatedTokenAddressSync(mint, to);

  const tx = new Transaction();
  tx.feePayer = from;
  tx.recentBlockhash = params.blockhash;

  const priorityFee = params.priorityFeeMicroLamports ?? 1000;
  if (priorityFee > 0) {
    tx.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: priorityFee }));
  }

  // Create the recipient's token account if they've never held this token.
  if (params.createRecipientAta) {
    tx.add(createAssociatedTokenAccountInstruction(from, toAta, to, mint));
  }

  tx.add(createTransferCheckedInstruction(fromAta, mint, toAta, from, rawAmount, params.decimals));

  if (params.memo) tx.add(memoInstruction(params.memo));

  return tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');
}

// ============================================================================
// Transfer verification (anti blind-sign for vault_sign_tx)
// ============================================================================

const SYSTEM_PROGRAM_ID = '11111111111111111111111111111111';
const COMPUTE_BUDGET_PROGRAM_ID = 'ComputeBudget111111111111111111111111111111';
const TOKEN_PROGRAM_STR = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const ATA_PROGRAM_ID = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const MEMO_PROGRAM_STR = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';

interface NormIx {
  programId: string;
  keys: string[];
  data: Buffer;
}

/** Decode a base64 tx (legacy or versioned) into fee-payer + flat instructions. */
function normalizeTx(unsignedTxB64: string): { feePayer: string; ixs: NormIx[]; resolvable: boolean } {
  const buf = Buffer.from(unsignedTxB64, 'base64');
  try {
    const tx = Transaction.from(buf);
    return {
      feePayer: tx.feePayer?.toBase58() ?? '',
      ixs: tx.instructions.map((ix) => ({
        programId: ix.programId.toBase58(),
        keys: ix.keys.map((k) => k.pubkey.toBase58()),
        data: Buffer.from(ix.data),
      })),
      resolvable: true,
    };
  } catch {
    /* not a legacy tx */
  }
  try {
    const vtx = VersionedTransaction.deserialize(buf);
    const keys = vtx.message.staticAccountKeys.map((k) => k.toBase58());
    const n = keys.length;
    let resolvable = true;
    const ixs = vtx.message.compiledInstructions.map((ci) => {
      const programId = ci.programIdIndex < n ? keys[ci.programIdIndex] : ((resolvable = false), '');
      const ixKeys = ci.accountKeyIndexes.map((i) => (i < n ? keys[i] : ((resolvable = false), '')));
      return { programId, keys: ixKeys, data: Buffer.from(ci.data) };
    });
    return { feePayer: keys[0] ?? '', ixs, resolvable };
  } catch {
    return { feePayer: '', ixs: [], resolvable: false };
  }
}

export interface TransferVerifyResult {
  /** false → the tx contradicts what was declared; the caller MUST refuse to sign. */
  ok: boolean;
  reason?: string;
  /** true when the tx was a recognized simple SOL/SPL transfer we could fully check. */
  verified: boolean;
}

/**
 * Verify that an agent-supplied unsigned transaction actually matches the
 * declared amount/destination before the vault signs it — closing the
 * blind-sign gap on vault_sign_tx for simple SOL and SPL transfers.
 *
 * Returns:
 *  - { ok:true,  verified:true }  → a simple transfer that matches the declaration
 *  - { ok:false, ... }            → a simple transfer that CONTRADICTS it → do not sign
 *  - { ok:true,  verified:false } → not a simple SOL/SPL transfer (complex/opaque);
 *                                   not enforced here (those go through DCP-built paths)
 *
 * Pure + local: ~sub-millisecond, no network.
 */
export function verifyTransferTx(params: {
  unsignedTx: string;
  owner: string;
  declaredAmount?: number;
  declaredDestination?: string;
  currency?: string;
}): TransferVerifyResult {
  const { feePayer, ixs, resolvable } = normalizeTx(params.unsignedTx);
  if (!resolvable || ixs.length === 0) return { ok: true, verified: false };

  let solOut = 0n;
  const solDests = new Set<string>();
  const tokenTransfers: { destAta: string; amount: bigint; decimals?: number; mint?: string }[] = [];
  let hasOther = false;

  for (const ix of ixs) {
    if (
      ix.programId === COMPUTE_BUDGET_PROGRAM_ID ||
      ix.programId === MEMO_PROGRAM_STR ||
      ix.programId === ATA_PROGRAM_ID
    ) {
      continue;
    }
    if (ix.programId === SYSTEM_PROGRAM_ID) {
      // SystemProgram.transfer: 4-byte ix index (2) + 8-byte lamports (u64 LE)
      if (ix.data.length === 12 && ix.data.readUInt32LE(0) === 2) {
        const from = ix.keys[0];
        const to = ix.keys[1];
        if (from !== params.owner) return { ok: false, reason: 'transfer is not from the wallet owner', verified: true };
        solOut += ix.data.readBigUInt64LE(4);
        solDests.add(to);
      } else {
        hasOther = true;
      }
    } else if (ix.programId === TOKEN_PROGRAM_STR) {
      if (ix.data[0] === 12 && ix.data.length >= 10) {
        // transferChecked: amount(u64) at 1, decimals at 9; keys [src, mint, dst, owner]
        tokenTransfers.push({
          amount: ix.data.readBigUInt64LE(1),
          decimals: ix.data[9],
          mint: ix.keys[1],
          destAta: ix.keys[2],
        });
      } else if (ix.data[0] === 3 && ix.data.length >= 9) {
        // transfer: amount(u64) at 1; keys [src, dst, owner]
        tokenTransfers.push({ amount: ix.data.readBigUInt64LE(1), destAta: ix.keys[1] });
      } else {
        hasOther = true;
      }
    } else {
      hasOther = true;
    }
  }

  // Anything beyond plain transfers (swaps, defi, unknown programs) is not a
  // "simple transfer" — out of scope here. Those must go through DCP-built tools.
  if (hasOther) return { ok: true, verified: false };
  if (solOut === 0n && tokenTransfers.length === 0) return { ok: true, verified: false };

  if (feePayer && feePayer !== params.owner) {
    return { ok: false, reason: 'fee-payer is not the wallet owner', verified: true };
  }

  // --- SOL checks ---
  if (solOut > 0n) {
    if (params.declaredAmount !== undefined && (params.currency ?? 'SOL').toUpperCase() === 'SOL') {
      const declaredLamports = BigInt(Math.round(params.declaredAmount * LAMPORTS_PER_SOL));
      if (solOut > declaredLamports) {
        return { ok: false, reason: `tx sends ${solOut} lamports but only ${declaredLamports} was declared`, verified: true };
      }
    }
    if (params.declaredDestination && !solDests.has(params.declaredDestination)) {
      return { ok: false, reason: 'tx destination does not match the declared destination', verified: true };
    }
  }

  // --- SPL checks ---
  if (tokenTransfers.length > 0) {
    for (const t of tokenTransfers) {
      if (params.declaredDestination && t.mint) {
        const expectedAta = getAssociatedTokenAddressSync(
          new PublicKey(t.mint),
          new PublicKey(params.declaredDestination)
        ).toBase58();
        if (t.destAta !== expectedAta) {
          return { ok: false, reason: 'token destination does not match the declared destination', verified: true };
        }
      }
    }
    if (params.declaredAmount !== undefined) {
      const decimals = tokenTransfers.find((t) => t.decimals !== undefined)?.decimals;
      if (decimals !== undefined) {
        const total = tokenTransfers.reduce((a, t) => a + t.amount, 0n);
        const declaredBase = BigInt(Math.round(params.declaredAmount * 10 ** decimals));
        if (total > declaredBase) {
          return { ok: false, reason: 'token amount exceeds the declared amount', verified: true };
        }
      }
    }
  }

  return { ok: true, verified: true };
}

/**
 * Extract the fee-payer and required-signature count from an unsigned tx
 * (versioned or legacy). Used to validate a third-party-built swap transaction
 * (e.g. from Jupiter) before signing: the vault must be the ONLY required signer
 * and the fee-payer, so a tampered tx can't slip in a hidden co-signer.
 */
export function getTransactionSigners(unsignedTxB64: string): {
  feePayer: string;
  numRequiredSignatures: number;
} {
  const buf = Buffer.from(unsignedTxB64, 'base64');
  try {
    const vtx = VersionedTransaction.deserialize(buf);
    return {
      feePayer: vtx.message.staticAccountKeys[0]?.toBase58() ?? '',
      numRequiredSignatures: vtx.message.header.numRequiredSignatures,
    };
  } catch {
    /* not versioned */
  }
  const tx = Transaction.from(buf);
  const header = tx.compileMessage().header;
  return {
    feePayer: tx.feePayer?.toBase58() ?? '',
    numRequiredSignatures: header.numRequiredSignatures,
  };
}

/**
 * Top-level program IDs invoked by a transaction.
 *
 * Reliable even for versioned txs that use Address Lookup Tables: Solana forbids
 * loading a program account via a LUT, so every invoked program is always present
 * in the static account keys. `resolvable: false` means the tx could not be decoded
 * (caller should treat it as opaque and refuse to make trust decisions on it).
 *
 * Pure + local, no network.
 */
export function getTransactionProgramIds(unsignedTxB64: string): {
  programIds: string[];
  resolvable: boolean;
} {
  const { ixs, resolvable } = normalizeTx(unsignedTxB64);
  const set = new Set<string>();
  for (const ix of ixs) if (ix.programId) set.add(ix.programId);
  return { programIds: [...set], resolvable };
}

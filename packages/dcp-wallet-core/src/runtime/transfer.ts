/**
 * Transfer workflow — the single orchestration shared by desktop + mobile.
 *
 *   idempotency → build → budget → approve → sign(port) → verify-signed → submit → record
 *
 * Every security gate (idempotency, budget, approval, verify-after-sign) runs
 * BEFORE submit, and the private key is only touched behind the Signer port.
 */

import { buildSolanaTransferTx, buildSplTransferTx, getSolanaAtaAddress, verifyTransferTx } from '../solana-tx.js';
import { idempotencyIntentMatches } from '../swap.js';
import { VaultError } from '../errors.js';
import { ConsentRequiredError, normalizeApproval } from './consent.js';
import type { TransferPorts } from './ports.js';
import type { TransferRequest, ExecResult } from './types.js';

export async function executeTransfer(req: TransferRequest, ports: TransferPorts): Promise<ExecResult> {
  const { signer, rpc, approval, budget, idempotency, activity } = ports;
  const owner = signer.address;
  const isNative = (req.currency || 'SOL').toUpperCase() === 'SOL' && !req.mint;

  // 1. Idempotency: replay an identical prior transfer; reject key reuse for a
  //    different intent (never blindly replay an unrelated signature).
  const key = req.idempotencyKey;
  if (key) {
    const prior = await idempotency.get(key);
    if (prior) {
      const sameIntent = idempotencyIntentMatches(
        { operation: prior.operation, destination: prior.destination, currency: prior.currency, amount: prior.amount },
        { operation: 'transfer', destination: req.to, currency: req.currency, amount: req.amount }
      );
      if (!sameIntent) {
        throw new VaultError('IDEMPOTENCY_CONFLICT', 'This idempotency key was already used for a different transfer.');
      }
      if (prior.signature) return { signature: prior.signature, status: 'submitted', idempotentReplay: true };
    }
  }

  // 2. Build the transaction ourselves (wallet-core, pure). The idempotency key
  //    doubles as a per-transfer memo nonce so distinct transfers never collide.
  const blockhash = await rpc.getLatestBlockhash();
  const memo = key || undefined;
  let unsignedTx: string;
  if (isNative) {
    unsignedTx = buildSolanaTransferTx(owner, req.to, req.amount, blockhash, memo ? { memo } : undefined);
  } else {
    if (!req.mint || req.decimals === undefined) {
      throw new VaultError('INVALID_CHAIN', 'SPL transfer requires mint and decimals');
    }
    const recipientAtaExists = await rpc.accountExists(getSolanaAtaAddress(req.mint, req.to));
    unsignedTx = buildSplTransferTx({
      fromAddress: owner,
      toAddress: req.to,
      mint: req.mint,
      amount: req.amount,
      decimals: req.decimals,
      blockhash,
      createRecipientAta: !recipientAtaExists,
      memo,
    });
  }

  // 3. Budget + explicit approval (plain English) before any signing.
  const b = await budget.check(req.amount, req.currency);
  if (!b.withinDailyLimit) {
    throw new VaultError('BUDGET_EXCEEDED_DAILY', 'Transfer exceeds the daily budget.');
  }
  if (b.needsApproval) {
    const decision = normalizeApproval(await approval.requestApproval({
      kind: 'transfer',
      summary: req.description || `Send ${req.amount} ${req.currency} to ${req.to}`,
      amount: req.amount,
      currency: req.currency,
      destination: req.to,
    }));
    if ('deferred' in decision && decision.deferred) throw new ConsentRequiredError(decision);
    if (!decision.approved) throw new VaultError('CONSENT_DENIED', 'Transfer was not approved.');
  }

  // 4. Sign (key behind the port).
  const signedTx = await signer.sign(unsignedTx);

  // 5. Verify the SIGNED tx STILL matches the declared intent — defense against a
  //    compromised/buggy signer swapping the transaction out from under us.
  const verdict = verifyTransferTx({
    unsignedTx: signedTx,
    owner,
    declaredAmount: req.amount,
    declaredDestination: req.to,
    currency: req.currency,
  });
  if (!verdict.ok) {
    throw new VaultError('INVALID_TX', `Signed transaction does not match the requested transfer: ${verdict.reason}`);
  }

  // 6. Submit. Record activity always, but only DEBIT budget + COMMIT idempotency
  //    when the tx did not fail — a failed broadcast must never count as spend and
  //    must leave the idempotency key free to retry.
  const res = await rpc.submit(signedTx, { confirm: req.confirm ?? true });
  const succeeded = res.status !== 'failed';
  if (succeeded) {
    await budget.record({ amount: req.amount, currency: req.currency, signature: res.signature });
    if (key) {
      await idempotency.commit(key, {
        operation: 'transfer',
        destination: req.to,
        currency: req.currency,
        amount: req.amount,
        signature: res.signature,
      });
    }
  }
  await activity.record({
    kind: 'transfer',
    amount: req.amount,
    currency: req.currency,
    destination: req.to,
    signature: res.signature,
    status: res.status,
  });

  return { signature: res.signature, status: res.status };
}

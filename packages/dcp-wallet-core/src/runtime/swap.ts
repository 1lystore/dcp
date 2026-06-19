/**
 * Swap workflow — shared orchestration over Jupiter.
 *
 *   idempotency → quote → validate-quote → build → validate-tx → budget → approve
 *     → sign(port) → re-validate-signed → submit → record
 *
 * Both validators come from wallet-core, so desktop + mobile bound the swap to the
 * caller's intent and the program allow-list identically.
 */

import { validateSwapQuote, validateSwapTransaction, idempotencyIntentMatches } from '../swap.js';
import { VaultError } from '../errors.js';
import { ConsentRequiredError, normalizeApproval } from './consent.js';
import type { SwapPorts } from './ports.js';
import type { SwapRequest, ExecResult } from './types.js';

export async function executeSwap(req: SwapRequest, ports: SwapPorts): Promise<ExecResult> {
  const { signer, rpc, swapProvider, approval, budget, idempotency, activity, config } = ports;
  const owner = signer.address;
  const slippageBps = req.slippageBps ?? 50;

  if (req.fromToken.mint === req.toToken.mint) {
    throw new VaultError('INVALID_CHAIN', 'from and to tokens are the same');
  }

  // 1. Idempotency (destination = output mint identifies the swap intent).
  const key = req.idempotencyKey;
  if (key) {
    const prior = await idempotency.get(key);
    if (prior) {
      const sameIntent = idempotencyIntentMatches(
        { operation: prior.operation, destination: prior.destination, currency: prior.currency, amount: prior.amount },
        { operation: 'swap', destination: req.toToken.mint, currency: req.fromToken.currency, amount: req.amount }
      );
      if (!sameIntent) {
        throw new VaultError('IDEMPOTENCY_CONFLICT', 'This idempotency key was already used for a different swap.');
      }
      if (prior.signature) return { signature: prior.signature, status: 'submitted', idempotentReplay: true };
    }
  }

  // 2. Quote + bind it to the caller's intent BEFORE building anything.
  const rawIn = BigInt(Math.round(req.amount * 10 ** req.fromToken.decimals)).toString();
  const quote = await swapProvider.quote({
    inputMint: req.fromToken.mint,
    outputMint: req.toToken.mint,
    rawInAmount: rawIn,
    slippageBps,
  });
  const quoteCheck = validateSwapQuote(quote, {
    inputMint: req.fromToken.mint,
    outputMint: req.toToken.mint,
    rawInAmount: rawIn,
    slippageBps,
  });
  if (!quoteCheck.ok) throw new VaultError('INVALID_CHAIN', quoteCheck.reason!);

  // 3. Build + validate the third-party tx (sole signer + program allow-list).
  const swapTx = await swapProvider.buildSwapTx(quote, owner);
  const txCheck = validateSwapTransaction(swapTx, {
    owner,
    jupiterProgramIds: config.jupiterProgramIds(),
    allowedPrograms: config.swapAllowedPrograms(),
  });
  if (!txCheck.ok) throw new VaultError('INVALID_CHAIN', txCheck.reason!);

  // 4. Budget + approval (charged on the input being spent).
  const b = await budget.check(req.amount, req.fromToken.currency);
  if (!b.withinDailyLimit) {
    throw new VaultError('BUDGET_EXCEEDED_DAILY', 'Swap exceeds the daily budget.');
  }
  if (b.needsApproval) {
    const decision = normalizeApproval(await approval.requestApproval({
      kind: 'swap',
      summary: `Swap ${req.amount} ${req.fromToken.currency} → ${req.toToken.currency}`,
      amount: req.amount,
      currency: req.fromToken.currency,
    }));
    if ('deferred' in decision && decision.deferred) throw new ConsentRequiredError(decision);
    if (!decision.approved) throw new VaultError('CONSENT_DENIED', 'Swap was not approved.');
  }

  // 5. Sign, then 6. re-validate the SIGNED tx — a signer must not have changed the
  //    message (fee-payer / signer count / programs stay bounded).
  const signedTx = await signer.sign(swapTx);
  const signedCheck = validateSwapTransaction(signedTx, {
    owner,
    jupiterProgramIds: config.jupiterProgramIds(),
    allowedPrograms: config.swapAllowedPrograms(),
  });
  if (!signedCheck.ok) {
    throw new VaultError('INVALID_TX', `Signed swap transaction failed validation: ${signedCheck.reason}`);
  }

  // 7. Submit. Record activity always; only DEBIT budget + COMMIT idempotency when
  //    the swap did not fail (a failed swap is no spend and is free to retry).
  const res = await rpc.submit(signedTx, { confirm: req.confirm ?? true });
  const succeeded = res.status !== 'failed';
  if (succeeded) {
    await budget.record({ amount: req.amount, currency: req.fromToken.currency, signature: res.signature });
    if (key) {
      await idempotency.commit(key, {
        operation: 'swap',
        destination: req.toToken.mint,
        currency: req.fromToken.currency,
        amount: req.amount,
        signature: res.signature,
      });
    }
  }
  await activity.record({
    kind: 'swap',
    amount: req.amount,
    currency: req.fromToken.currency,
    destination: req.toToken.mint,
    signature: res.signature,
    status: res.status,
  });

  return { signature: res.signature, status: res.status, outAmount: quote.outAmount };
}

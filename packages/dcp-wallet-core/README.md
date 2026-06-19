# @dcprotocol/wallet-core

The pure **wallet brain** for DCP — transaction building, decoding, validation, the
execution runner, and the shared protocol error type. **Zero native dependencies, no
storage, no key custody, no UI** — so it imports identically in Node (the vault
server, agents), the browser, and React Native (the mobile app).

This is the single source of truth for wallet *logic*. Higher packages
(`@dcprotocol/core`, `@dcprotocol/vault`, the official apps) build their platform
adapters on top of it, so a fix / feature / fee change happens **once** and every
surface gets it.

## What's inside

| Area | Exports |
|---|---|
| **Build** | `buildSolanaTransferTx`, `buildSplTransferTx`, `getSolanaAtaAddress` |
| **Decode / validate** | `verifyTransferTx` (anti-blind-sign), `getTransactionSigners`, `getTransactionProgramIds` |
| **Swap safety** | `validateSwapQuote` (quote↔intent), `validateSwapTransaction` (sole-signer + program allow-list), `idempotencyIntentMatches` |
| **Jupiter** | `jupiterQuote`, `jupiterBuildSwapTx` (fee + endpoint **injected**, never hardcoded) |
| **Tokens** | `resolveToken`, `resolveSwapToken`, `WSOL_MINT`, `DEFAULT_KNOWN_TOKENS` |
| **Reads** | `SolanaReader` (balances, tx status, history, token search) |
| **Runner** | `executeTransfer`, `executeSwap` + the ports (`Signer`, `RpcClient`, `BudgetStore`, `IdempotencyStore`, `ApprovalUI`, `ActivityRecorder`, `ConfigProvider`, `SwapProvider`) |
| **Consent** | `ConsentRequiredError`, `normalizeApproval` (supports both inline-PIN and async approve-later) |
| **Errors** | `VaultError`, `VaultErrorCode` (the shared protocol error type) |

## Design rules (do not break)

- **No native deps.** Only `@solana/web3.js`, `@solana/spl-token`, `fetch`. A native
  dependency (sqlite/sodium/keychain) would break the React Native build — that is the
  whole reason this package exists separately from `@dcprotocol/core`.
- **The brain never signs and never holds a key.** The runner builds + validates, then
  delegates signing to the platform's `Signer` port.
- **No business config.** The swap fee (rate + account) and RPC endpoint are *injected*
  by the host, never embedded here.

## Usage (runner)

```ts
import { executeTransfer, type TransferPorts } from '@dcprotocol/wallet-core';

const ports: TransferPorts = { signer, rpc, approval, budget, idempotency, activity };
const result = await executeTransfer(
  { chain: 'solana', to, amount, currency: 'SOL', idempotencyKey },
  ports,
);
```

The runner runs: `idempotency → build → validate → budget → approval → sign(port) →
verify-after-sign → submit → record-on-success`. Approval may return a boolean
(inline PIN) or `{ deferred, consentId }` (async consent) — the latter throws
`ConsentRequiredError` for the host to surface as `requires_consent`.

## License

Apache-2.0

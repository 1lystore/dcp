# @dcprotocol/core

Core primitives for DCP runtimes.

Most developers should use `@dcprotocol/vault`, `@dcprotocol/agent`, or `@dcprotocol/client` first. Use core when you are extending DCP itself or building a runtime that needs the same primitives as the vault.

## Install

```bash
npm install @dcprotocol/core
```

## What Is Inside

```text
crypto      encryption, signatures, canonical JSON
wallet      key custody (create/encrypt/sign) + RE-EXPORTS the pure wallet logic
            (tx build/validate/runner) from @dcprotocol/wallet-core
storage     SQLite vault storage and audit data
budget      budget and policy helpers
pairing     signed pairing grants and remote-agent invites
types       shared TypeScript types (VaultError is re-exported from wallet-core)
```

## Relationship to `@dcprotocol/wallet-core`

The pure, dependency-light wallet logic — transaction building, validation, the
execution runner, token registry, Jupiter, and the shared `VaultError` — lives in
`@dcprotocol/wallet-core` (no native deps, React-Native-safe). `core` adds **key
custody, storage, and crypto** (which need native modules) on top, and re-exports
`wallet-core` for backward compatibility. Import wallet primitives from either; they
are the same code.

## Boundaries

Core provides building blocks. The vault decides policy, approval, signing, and storage behavior in the running product.

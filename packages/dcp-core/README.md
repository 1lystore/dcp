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
wallet      Solana and EVM wallet operations
storage     SQLite vault storage and audit data
budget      budget and policy helpers
pairing     signed pairing grants and remote-agent invites
types       shared TypeScript types
```

## Boundaries

Core provides building blocks. The vault decides policy, approval, signing, and storage behavior in the running product.

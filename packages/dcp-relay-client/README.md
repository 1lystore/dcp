# @dcprotocol/relay-client

Relay transport client for DCP runtimes.

Most developers should use `@dcprotocol/agent` or `@dcprotocol/client`. Use this package when you are building transport-level DCP integrations.

## Install

```bash
npm install @dcprotocol/relay-client
```

## What It Does

- connects to a DCP relay
- sends encrypted envelopes
- receives encrypted responses
- handles relay transport details

It does not own vault policy, approvals, wallet signing, or secret storage. Those stay with the vault.

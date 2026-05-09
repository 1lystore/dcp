# @dcprotocol/vault

The local DCP vault CLI.

Use it to create a vault, add data, manage agents, and review activity.

## Install

```bash
npm install -g @dcprotocol/vault
```

## Start

```bash
dcp init
dcp create-wallet --chain solana
dcp add identity.email
dcp list
```

## Common Commands

```bash
dcp add identity.name
dcp add credentials.api.openai
dcp read identity.email
dcp agents
dcp revoke <agent_id>
dcp activity
```

## Remote Pairing

For remote agent testing:

```bash
dcp pairing start openclaw-vps --scopes sign:solana,read:identity.email
```

For normal remote setup, use the invite flow in DCP Desktop.

## Data

By default, the vault uses:

```text
~/.dcp
```

The vault owns the secrets. Agents get scoped access and approved actions, not direct control of the vault.

# DCP Examples

Small examples for calling a DCP vault from JavaScript.

The main developer path is still the installed vault and agent:

```bash
npm install -g @dcprotocol/vault @dcprotocol/agent
dcp init
dcp create-wallet --chain solana
dcp-agent run --mode mcp --agent claude_desktop
```

## Examples

```text
read-personal-data   read scoped identity data from the vault
sign-solana-tx       request a Solana transaction signature
```

Run an example from its folder:

```bash
npm install
node index.js
```

The examples expect a local vault endpoint at `http://127.0.0.1:8420`. If approval is required, approve from the vault or Desktop flow you are testing.

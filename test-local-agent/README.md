# DCP Local Agent Test

Test connecting a local agent to DCP Vault.

## Prerequisites

- DCP Desktop running and unlocked
- Python 3.9+ with `httpx` installed

## Steps

### 1. Install httpx

```bash
pip install httpx
```

### 2. Generate Pairing Token in Desktop

Open DCP Desktop > Connect page:
1. Enter agent name: `test-local-agent`
2. Select role preset (e.g., "Trading Bot" or "Custom")
3. Click "Generate Pairing Token"
4. Copy the token (starts with `dcp_pair_v1_...`)

### 3. Pair dcp-agent

```bash
cd /Users/iftakharrahmany/myproducts/dcp/packages/dcp-agent
node dist/index.js pair 'dcp_pair_v1_...'
```

### 4. Run dcp-agent proxy

```bash
cd /Users/iftakharrahmany/myproducts/dcp/packages/dcp-agent
node dist/index.js run
```

Keep this terminal open.

### 5. Run test agent

In a new terminal:

```bash
cd /Users/iftakharrahmany/myproducts/dcp/test-local-agent
python test_agent.py
```

## Expected Output

```
============================================================
DCP Local Agent Test
============================================================

Connecting to proxy at: http://127.0.0.1:8420

[1] Health Check
----------------------------------------
  Status: ok
  Agent ID: agent_xxx
  Agent Name: test-local-agent
  Vault ID: vault_xxx
  Connected: True

[2] Capabilities
----------------------------------------
  Name: dcp-agent
  Version: 0.2.0
  Tier: free
  Scopes: ['sign:solana', 'budget:check']

[3] Get Wallet Address (Solana)
----------------------------------------
  Chain: solana
  Address: 7xKx...

...
```

## Cleanup

```bash
rm -rf /Users/iftakharrahmany/myproducts/dcp/test-local-agent
```

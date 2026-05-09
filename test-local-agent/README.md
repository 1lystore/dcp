# DCP Local Agent Test

A small local test agent for checking the DCP agent proxy.

## Setup

Install the DCP packages:

```bash
npm install -g @dcprotocol/vault @dcprotocol/agent
```

Install the Python dependency:

```bash
pip install httpx
```

## Pair An Agent

Open DCP Desktop and create a pairing token for `test-local-agent`, then run:

```bash
dcp-agent pair 'dcp_pair_v1_...'
```

Start the local agent proxy:

```bash
dcp-agent run
```

Keep that terminal open.

## Run The Test

From this folder:

```bash
python test_agent.py
```

The test checks health, capabilities, Solana address access, budget checks, and a sample vault read request.

# DCP Python SDK

Python SDK for connecting AI agents to DCP Vault - secure wallet signing and credential access.

## Installation

```bash
pip install dcp-sdk
```

## Quick Start

### Connect to Local Proxy

First, start the DCP agent on your server:

```bash
# Pair the agent with your vault
dcp-agent pair 'dcp_pair_v1_...'

# Start the proxy
dcp-agent run
```

Then connect from Python:

```python
from dcp_sdk import DcpClient

# Connect to local proxy
client = DcpClient(base_url="http://localhost:8420")

# Get wallet address
result = client.get_address("solana")
print(f"Solana address: {result.address}")

# Sign a transaction
result = client.sign_tx(
    chain="solana",
    unsigned_tx="base64_encoded_transaction",
    amount=1.0,
    currency="SOL",
    description="Swap on Jupiter"
)
print(f"Signed TX: {result.signed_tx}")
```

### Connect via Pairing Grant

```python
from dcp_sdk import DcpClient

# Connect directly using pairing grant
client = DcpClient.from_pairing_grant("dcp_pair_v1_...")

# Use the client
address = client.get_address("solana")
```

## API Reference

### DcpClient

#### `get_address(chain)`

Get the wallet address for a blockchain.

```python
result = client.get_address("solana")
# result.chain = "solana"
# result.address = "5xYz..."
```

#### `budget_check(amount, currency, chain=None)`

Check if a transaction is within budget limits.

```python
result = client.budget_check(amount=10.0, currency="USDC")
# result.allowed = True
# result.remaining_daily = 90.0
# result.requires_approval = False
```

#### `sign_tx(chain, unsigned_tx, **kwargs)`

Sign a transaction using the vault wallet.

```python
result = client.sign_tx(
    chain="solana",
    unsigned_tx="base64_tx",
    amount=1.0,
    currency="SOL",
    description="Transfer to Alice"
)
# result.signed_tx = "base64_signed_tx"
# result.signature = "signature_hex"
```

#### `sign_message(chain, message, encoding="utf8")`

Sign an arbitrary message.

```python
result = client.sign_message(
    chain="solana",
    message="Hello, World!",
    encoding="utf8"
)
# result.signature = "signature_base64"
# result.public_key = "pubkey_base64"
```

#### `read(scope, fields=None)`

Read data from the vault.

```python
result = client.read("credentials.api.openai")
# result.scope = "credentials.api.openai"
# result.data = {"api_key": "sk-..."}
# result.sensitivity = "sensitive"
```

#### `write(scope, data)`

Write data to the vault.

```python
result = client.write(
    scope="credentials.api.github",
    data={"token": "ghp_..."}
)
# result.created = True
# result.updated = False
```

## Error Handling

```python
from dcp_sdk import DcpClient, DcpError

client = DcpClient()

try:
    result = client.sign_tx(chain="solana", unsigned_tx="...")
except DcpError as e:
    if e.code == "CONSENT_REQUIRED":
        print(f"User needs to approve: {e.details['consent_id']}")
    elif e.code == "BUDGET_EXCEEDED":
        print("Transaction exceeds daily budget")
    else:
        print(f"Error: {e.code} - {e.message}")
```

## Supported Chains

- `solana` - Solana mainnet
- `base` - Base L2
- `ethereum` - Ethereum mainnet

## License

Apache-2.0

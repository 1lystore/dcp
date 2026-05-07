"""
DCP SDK - Python client for DCP Vault

Connect AI agents to DCP Vault for secure wallet signing and credential access.

Usage:
    from dcp_sdk import DcpClient

    # Auto-configure from environment variables (recommended)
    # Reads DCP_PAIRING_TOKEN or DCP_URL
    client = DcpClient.from_env()

    # Or connect via pairing grant
    client = DcpClient.from_pairing_grant("dcp_pair_v1_...")

    # Or connect to local proxy (started by dcp-agent)
    client = DcpClient(base_url="http://localhost:8420")

    # Get wallet address
    address = client.get_address("solana")

    # Sign a transaction
    result = client.sign_tx(
        chain="solana",
        unsigned_tx="base64_encoded_tx",
        amount=1.0,
        currency="SOL",
        description="Swap on Jupiter"
    )

Relay Mode:
    For relay mode (cloud/remote vault access), use dcp-agent as a local proxy:
        $ dcp-agent pair <grant-token>
        $ dcp-agent run --daemon

    Then connect the SDK to the local proxy:
        client = DcpClient.from_env()  # Uses DCP_URL=http://localhost:8420
"""

from .client import DcpClient
from .types import (
    DcpError,
    Chain,
    SignResult,
    ReadResult,
    WriteResult,
    BudgetCheckResult,
)
from .pairing import (
    parse_pairing_grant,
    verify_pairing_grant,
    PairingGrant,
)

__version__ = "0.2.0"

__all__ = [
    "DcpClient",
    "DcpError",
    "Chain",
    "SignResult",
    "ReadResult",
    "WriteResult",
    "BudgetCheckResult",
    "parse_pairing_grant",
    "verify_pairing_grant",
    "PairingGrant",
]

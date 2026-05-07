"""
DCP Client

Main client class for interacting with DCP Vault.
"""

import os
import httpx
from typing import Any, Dict, List, Optional, Union

from .types import (
    DcpError,
    Chain,
    AddressResult,
    SignResult,
    SignMessageResult,
    ReadResult,
    WriteResult,
    BudgetCheckResult,
)
from .pairing import verify_pairing_grant, PairingGrant


# ============================================================================
# Client Configuration
# ============================================================================

DEFAULT_TIMEOUT = 30.0
DEFAULT_BASE_URL = "http://localhost:8420"


# ============================================================================
# DCP Client
# ============================================================================

class DcpClient:
    """
    DCP Vault client for AI agents.

    Provides secure wallet signing and credential access through
    the DCP Vault via local proxy or gateway.

    Usage:
        # Connect via local proxy (started by dcp-agent)
        client = DcpClient(base_url="http://localhost:8420")

        # Or connect via pairing grant
        client = DcpClient.from_pairing_grant("dcp_pair_v1_...")

        # Get wallet address
        result = client.get_address("solana")
        print(result.address)

        # Sign a transaction
        result = client.sign_tx(
            chain="solana",
            unsigned_tx="base64_tx",
            amount=1.0,
            currency="SOL"
        )
        print(result.signed_tx)
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        agent_name: Optional[str] = None,
        _grant: Optional[PairingGrant] = None,
    ):
        """
        Initialize the DCP client.

        Args:
            base_url: Base URL of the DCP proxy or gateway
            timeout: Request timeout in seconds
            agent_name: Name to identify this agent in audit logs
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.agent_name = agent_name or "python-sdk"
        self._grant = _grant
        self._client = httpx.Client(timeout=timeout)

    @classmethod
    def from_pairing_grant(cls, grant_token: str, **kwargs) -> "DcpClient":
        """
        Create a client from a pairing grant token.

        Args:
            grant_token: The dcp_pair_v1_... pairing grant
            **kwargs: Additional arguments passed to DcpClient

        Returns:
            Configured DcpClient instance

        Raises:
            DcpError: If the grant is invalid or expired
        """
        grant = verify_pairing_grant(grant_token)
        if grant is None:
            raise DcpError(
                "INVALID_GRANT",
                "Invalid pairing grant format or signature"
            )

        # Use gateway URL from grant
        base_url = kwargs.pop("base_url", grant.gateway_url)

        return cls(
            base_url=base_url,
            agent_name=grant.agent_name,
            _grant=grant,
            **kwargs
        )

    @classmethod
    def from_env(cls, **kwargs) -> "DcpClient":
        """
        Create a client from environment variables.

        Supports:
            DCP_PAIRING_TOKEN: Pairing grant token (dcp_pair_v1_...)
            DCP_URL: Base URL for local proxy (default: http://localhost:8420)
            DCP_AGENT_NAME: Agent name for audit logs
            DCP_TIMEOUT: Request timeout in seconds

        Priority:
            1. If DCP_PAIRING_TOKEN is set, use pairing grant
            2. Otherwise, connect to local proxy at DCP_URL

        Returns:
            Configured DcpClient instance

        Raises:
            DcpError: If no valid configuration found

        Example:
            # Set env vars:
            # export DCP_PAIRING_TOKEN="dcp_pair_v1_..."
            # or
            # export DCP_URL="http://localhost:8420"

            client = DcpClient.from_env()
        """
        # Check for pairing grant first
        pairing_token = os.environ.get("DCP_PAIRING_TOKEN")
        if pairing_token:
            return cls.from_pairing_grant(pairing_token, **kwargs)

        # Fall back to local proxy URL
        base_url = os.environ.get("DCP_URL", DEFAULT_BASE_URL)
        agent_name = os.environ.get("DCP_AGENT_NAME")
        timeout_str = os.environ.get("DCP_TIMEOUT")
        timeout = float(timeout_str) if timeout_str else DEFAULT_TIMEOUT

        return cls(
            base_url=base_url,
            timeout=timeout,
            agent_name=agent_name,
            **kwargs
        )

    def close(self) -> None:
        """Close the HTTP client"""
        self._client.close()

    def __enter__(self) -> "DcpClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # ========================================================================
    # Public API
    # ========================================================================

    def health(self) -> Dict[str, Any]:
        """
        Check if the vault/proxy is healthy.

        Returns:
            Health status including version and unlock state
        """
        return self._get("/health")

    def capabilities(self) -> Dict[str, Any]:
        """
        Get the capabilities of the connected vault/proxy.

        Returns:
            Capabilities including available routes and scopes
        """
        return self._get("/capabilities")

    def get_address(self, chain: Chain) -> AddressResult:
        """
        Get the wallet address for a blockchain.

        Args:
            chain: The blockchain (solana, base, ethereum)

        Returns:
            AddressResult with chain and address
        """
        data = self._get(f"/address/{chain}")
        return AddressResult(
            chain=data["chain"],
            address=data["address"],
        )

    def budget_check(
        self,
        amount: float,
        currency: str,
        chain: Optional[Chain] = None,
    ) -> BudgetCheckResult:
        """
        Check if a transaction amount is within budget limits.

        Args:
            amount: The transaction amount
            currency: Currency code (SOL, ETH, USDC, etc.)
            chain: Optional chain for chain-specific limits

        Returns:
            BudgetCheckResult with allowed status and remaining limits
        """
        params = {"amount": str(amount), "currency": currency}
        if chain:
            params["chain"] = chain

        data = self._get("/budget/check", params=params)

        return BudgetCheckResult(
            allowed=data["allowed"],
            remaining_daily=data.get("remaining_daily", 0),
            remaining_tx=data.get("remaining_tx", 0),
            requires_approval=data.get("requires_approval", False),
            reason=data.get("reason"),
        )

    def sign_tx(
        self,
        chain: Chain,
        unsigned_tx: str,
        amount: Optional[float] = None,
        currency: Optional[str] = None,
        description: Optional[str] = None,
        destination: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> SignResult:
        """
        Sign a transaction using the vault wallet.

        Args:
            chain: The blockchain (solana, base, ethereum)
            unsigned_tx: The unsigned transaction (base64 for Solana, JSON for EVM)
            amount: Transaction amount for budget tracking
            currency: Currency code for budget tracking
            description: Human-readable description for consent UI
            destination: Destination address
            idempotency_key: Unique key to prevent duplicate transactions

        Returns:
            SignResult with signed_tx, signature, and remaining budget

        Raises:
            DcpError: If signing fails or consent is required
        """
        body: Dict[str, Any] = {
            "chain": chain,
            "unsigned_tx": unsigned_tx,
        }
        if amount is not None:
            body["amount"] = amount
        if currency:
            body["currency"] = currency
        if description:
            body["description"] = description
        if destination:
            body["destination"] = destination
        if idempotency_key:
            body["idempotency_key"] = idempotency_key

        data = self._post("/v1/vault/sign", body)

        return SignResult(
            signed_tx=data["signed_tx"],
            signature=data["signature"],
            chain=data["chain"],
            remaining_daily=data.get("remaining_daily"),
            session_id=data.get("session_id"),
        )

    def sign_message(
        self,
        chain: Chain,
        message: str,
        encoding: str = "utf8",
        description: Optional[str] = None,
    ) -> SignMessageResult:
        """
        Sign an arbitrary message using the vault wallet.

        Args:
            chain: The blockchain (solana, base, ethereum)
            message: The message to sign
            encoding: Message encoding (utf8, hex, base64)
            description: Human-readable description for consent UI

        Returns:
            SignMessageResult with signature and public key

        Raises:
            DcpError: If signing fails or consent is required
        """
        body: Dict[str, Any] = {
            "chain": chain,
            "message": message,
            "encoding": encoding,
        }
        if description:
            body["description"] = description

        data = self._post("/v1/vault/sign_message", body)

        return SignMessageResult(
            signature=data["signature"],
            public_key=data["public_key"],
            chain=data["chain"],
            session_id=data.get("session_id"),
        )

    def sign_typed_data(
        self,
        chain: Chain,
        typed_data: Dict[str, Any],
        description: Optional[str] = None,
    ) -> SignMessageResult:
        """
        Sign EIP-712 typed data.

        Args:
            chain: The EVM chain (base, ethereum)
            typed_data: The EIP-712 typed data object
            description: Human-readable description for consent UI

        Returns:
            SignMessageResult with signature and public key

        Raises:
            DcpError: If signing fails or consent is required
        """
        body: Dict[str, Any] = {
            "chain": chain,
            "typed_data": typed_data,
        }
        if description:
            body["description"] = description

        data = self._post("/v1/vault/sign_typed_data", body)

        return SignMessageResult(
            signature=data["signature"],
            public_key=data["public_key"],
            chain=data["chain"],
            session_id=data.get("session_id"),
        )

    def read(
        self,
        scope: str,
        fields: Optional[List[str]] = None,
    ) -> ReadResult:
        """
        Read data from the vault.

        Args:
            scope: The scope to read (e.g., "credentials.api.openai")
            fields: Optional list of specific fields to return

        Returns:
            ReadResult with scope, data, and sensitivity level

        Raises:
            DcpError: If read fails or consent is required
        """
        body: Dict[str, Any] = {"scope": scope}
        if fields:
            body["fields"] = fields

        data = self._post("/v1/vault/read", body)

        return ReadResult(
            scope=data["scope"],
            data=data["data"],
            sensitivity=data["sensitivity"],
            is_reference=data.get("is_reference", False),
            session_id=data.get("session_id"),
        )

    def write(
        self,
        scope: str,
        data: Dict[str, Any],
    ) -> WriteResult:
        """
        Write data to the vault.

        Args:
            scope: The scope to write (e.g., "credentials.api.openai")
            data: The data to store

        Returns:
            WriteResult with scope and creation/update status

        Raises:
            DcpError: If write fails or consent is required
        """
        body = {"scope": scope, "data": data}
        result = self._post("/v1/vault/write", body)

        return WriteResult(
            scope=result["scope"],
            created=result.get("created", False),
            updated=result.get("updated", False),
            sensitivity=result.get("sensitivity", "standard"),
            session_id=result.get("session_id"),
        )

    # ========================================================================
    # Internal Methods
    # ========================================================================

    def _get(
        self,
        path: str,
        params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Make a GET request"""
        url = f"{self.base_url}{path}"
        response = self._client.get(url, params=params)
        return self._handle_response(response)

    def _post(
        self,
        path: str,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Make a POST request"""
        url = f"{self.base_url}{path}"
        response = self._client.post(url, json=body)
        return self._handle_response(response)

    def _handle_response(self, response: httpx.Response) -> Dict[str, Any]:
        """Handle HTTP response and raise errors if needed"""
        try:
            data = response.json()
        except Exception:
            raise DcpError(
                "CONNECTION_FAILED",
                f"Invalid response from server: {response.text[:200]}"
            )

        # Check for error response
        if "error" in data:
            error = data["error"]
            raise DcpError(
                error.get("code", "INTERNAL_ERROR"),
                error.get("message", "Unknown error"),
                error.get("details"),
            )

        # Check for consent required
        if data.get("requires_consent"):
            raise DcpError(
                "CONSENT_REQUIRED",
                data.get("message", "User consent required"),
                {
                    "consent_id": data.get("consent_id"),
                    "expires_at": data.get("expires_at"),
                }
            )

        return data

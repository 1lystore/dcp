"""
DCP SDK Types

Type definitions for the DCP SDK.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional
from enum import Enum


# ============================================================================
# Enums
# ============================================================================

Chain = Literal["solana", "base", "ethereum"]
Tier = Literal["free", "pro"]
Mode = Literal["gateway", "proxy", "mcp", "sdk"]


# ============================================================================
# Error Types
# ============================================================================

class DcpErrorCode(str, Enum):
    """DCP error codes"""
    VAULT_LOCKED = "VAULT_LOCKED"
    CONSENT_REQUIRED = "CONSENT_REQUIRED"
    CONSENT_DENIED = "CONSENT_DENIED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    RATE_LIMITED = "RATE_LIMITED"
    INVALID_GRANT = "INVALID_GRANT"
    GRANT_EXPIRED = "GRANT_EXPIRED"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class DcpError(Exception):
    """DCP SDK error with code and details"""

    def __init__(
        self,
        code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def __repr__(self) -> str:
        return f"DcpError(code={self.code!r}, message={self.message!r})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details,
            }
        }


# ============================================================================
# Result Types
# ============================================================================

@dataclass
class AddressResult:
    """Result of get_address operation"""
    chain: Chain
    address: str


@dataclass
class SignResult:
    """Result of sign_tx operation"""
    signed_tx: str
    signature: str
    chain: Chain
    remaining_daily: Optional[float] = None
    session_id: Optional[str] = None


@dataclass
class SignMessageResult:
    """Result of sign_message operation"""
    signature: str
    public_key: str
    chain: Chain
    session_id: Optional[str] = None


@dataclass
class ReadResult:
    """Result of read operation"""
    scope: str
    data: Dict[str, Any]
    sensitivity: str
    is_reference: bool
    session_id: Optional[str] = None


@dataclass
class WriteResult:
    """Result of write operation"""
    scope: str
    created: bool
    updated: bool
    sensitivity: str
    session_id: Optional[str] = None


@dataclass
class BudgetCheckResult:
    """Result of budget_check operation"""
    allowed: bool
    remaining_daily: float
    remaining_tx: float
    requires_approval: bool
    reason: Optional[str] = None


# ============================================================================
# Request Types
# ============================================================================

@dataclass
class SignTxRequest:
    """Request for sign_tx operation"""
    chain: Chain
    unsigned_tx: str
    amount: Optional[float] = None
    currency: Optional[str] = None
    description: Optional[str] = None
    destination: Optional[str] = None
    idempotency_key: Optional[str] = None


@dataclass
class SignMessageRequest:
    """Request for sign_message operation"""
    chain: Chain
    message: str
    encoding: Literal["utf8", "hex", "base64"] = "utf8"
    description: Optional[str] = None


@dataclass
class ReadRequest:
    """Request for read operation"""
    scope: str
    fields: Optional[List[str]] = None


@dataclass
class WriteRequest:
    """Request for write operation"""
    scope: str
    data: Dict[str, Any]

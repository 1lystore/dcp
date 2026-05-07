"""
DCP Pairing Grant Parser

Parse and verify signed pairing grants for agent authentication.
"""

import base64
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from .types import DcpError, Chain, Tier, Mode


# ============================================================================
# Constants
# ============================================================================

PAIRING_GRANT_PREFIX = "dcp_pair_v1_"
SESSION_TOKEN_PREFIX = "dcp_session_v1_"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class PairingGrant:
    """Decoded pairing grant data"""
    version: int
    grant_id: str
    vault_id: str
    agent_id: str
    agent_name: str
    mode: Mode
    vault_hpke_public_key: str
    vault_signing_public_key: str
    permission_scopes: List[str]
    budget: Dict[str, Any]
    tier: Tier
    relay_url: str
    gateway_url: str
    created_at: str
    expires_at: str


@dataclass
class EncodedPairingGrant:
    """Raw encoded pairing grant with signature"""
    payload: Dict[str, Any]
    signature: str


# ============================================================================
# Parsing Functions
# ============================================================================

def parse_pairing_grant(token: str) -> Optional[EncodedPairingGrant]:
    """
    Parse a pairing grant token without verification.

    Args:
        token: The dcp_pair_v1_... token string

    Returns:
        Decoded grant or None if invalid format
    """
    if not token.startswith(PAIRING_GRANT_PREFIX):
        return None

    try:
        # Extract base64url encoded part
        base64url_part = token[len(PAIRING_GRANT_PREFIX):]

        # Decode base64url (Python's urlsafe_b64decode handles this)
        # Add padding if needed
        padding = 4 - len(base64url_part) % 4
        if padding != 4:
            base64url_part += "=" * padding

        json_bytes = base64.urlsafe_b64decode(base64url_part)
        data = json.loads(json_bytes.decode("utf-8"))

        # Validate structure
        if "payload" not in data or "signature" not in data:
            return None

        if data["payload"].get("version") != 1:
            return None

        return EncodedPairingGrant(
            payload=data["payload"],
            signature=data["signature"],
        )
    except (ValueError, json.JSONDecodeError, KeyError):
        return None


def verify_pairing_grant(token: str) -> Optional[PairingGrant]:
    """
    Verify and decode a pairing grant.

    Checks:
    1. Valid format (dcp_pair_v1_ prefix)
    2. Valid Ed25519 signature
    3. Not expired

    Args:
        token: The dcp_pair_v1_... token string

    Returns:
        Verified PairingGrant or None if invalid

    Raises:
        DcpError: If the grant is expired
    """
    encoded = parse_pairing_grant(token)
    if encoded is None:
        return None

    try:
        # Extract public key from payload
        public_key_b64 = encoded.payload.get("vault_signing_public_key")
        if not public_key_b64:
            return None

        public_key_bytes = base64.b64decode(public_key_b64)
        if len(public_key_bytes) != 32:
            return None

        # Create canonical JSON for signature verification
        canonical = _canonical_json(encoded.payload)

        # Verify signature
        signature_bytes = base64.b64decode(encoded.signature)
        verify_key = VerifyKey(public_key_bytes)

        try:
            verify_key.verify(canonical.encode("utf-8"), signature_bytes)
        except BadSignatureError:
            return None

        # Check expiration
        expires_at = datetime.fromisoformat(
            encoded.payload["expires_at"].replace("Z", "+00:00")
        )
        if datetime.now(expires_at.tzinfo) > expires_at:
            raise DcpError(
                "GRANT_EXPIRED",
                "Pairing grant has expired",
                {"expires_at": encoded.payload["expires_at"]}
            )

        # Return verified grant
        return PairingGrant(
            version=encoded.payload["version"],
            grant_id=encoded.payload["grant_id"],
            vault_id=encoded.payload["vault_id"],
            agent_id=encoded.payload["agent_id"],
            agent_name=encoded.payload["agent_name"],
            mode=encoded.payload["mode"],
            vault_hpke_public_key=encoded.payload["vault_hpke_public_key"],
            vault_signing_public_key=encoded.payload["vault_signing_public_key"],
            permission_scopes=encoded.payload["permission_scopes"],
            budget=encoded.payload["budget"],
            tier=encoded.payload["tier"],
            relay_url=encoded.payload["relay_url"],
            gateway_url=encoded.payload["gateway_url"],
            created_at=encoded.payload["created_at"],
            expires_at=encoded.payload["expires_at"],
        )
    except (ValueError, KeyError) as e:
        return None


def _canonical_json(obj: Dict[str, Any]) -> str:
    """
    Create canonical JSON string for signing.

    Keys are sorted alphabetically for deterministic output.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def is_pairing_grant(token: str) -> bool:
    """Check if a string looks like a pairing grant"""
    return token.startswith(PAIRING_GRANT_PREFIX)


def is_session_token(token: str) -> bool:
    """Check if a string looks like a session token"""
    return token.startswith(SESSION_TOKEN_PREFIX)

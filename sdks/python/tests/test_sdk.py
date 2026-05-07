"""
DCP SDK Tests
"""

import pytest
from dcp_sdk import DcpClient, DcpError
from dcp_sdk.types import (
    AddressResult,
    SignResult,
    BudgetCheckResult,
    ReadResult,
    WriteResult,
)
from dcp_sdk.pairing import (
    parse_pairing_grant,
    is_pairing_grant,
    is_session_token,
    PAIRING_GRANT_PREFIX,
    SESSION_TOKEN_PREFIX,
)


# ============================================================================
# Pairing Tests
# ============================================================================

class TestPairing:
    def test_is_pairing_grant(self):
        assert is_pairing_grant(f"{PAIRING_GRANT_PREFIX}abc123")
        assert not is_pairing_grant("invalid_token")
        assert not is_pairing_grant(f"{SESSION_TOKEN_PREFIX}abc")

    def test_is_session_token(self):
        assert is_session_token(f"{SESSION_TOKEN_PREFIX}abc123")
        assert not is_session_token("invalid_token")
        assert not is_session_token(f"{PAIRING_GRANT_PREFIX}abc")

    def test_parse_invalid_grant(self):
        # Invalid prefix
        assert parse_pairing_grant("invalid") is None

        # Invalid base64
        assert parse_pairing_grant(f"{PAIRING_GRANT_PREFIX}!!!") is None


# ============================================================================
# Error Tests
# ============================================================================

class TestDcpError:
    def test_error_creation(self):
        error = DcpError("TEST_CODE", "Test message")
        assert error.code == "TEST_CODE"
        assert error.message == "Test message"
        assert error.details == {}

    def test_error_with_details(self):
        error = DcpError("RATE_LIMITED", "Too many requests", {"retry_after": 60})
        assert error.details["retry_after"] == 60

    def test_error_to_dict(self):
        error = DcpError("TEST", "Message", {"key": "value"})
        d = error.to_dict()
        assert d == {
            "error": {
                "code": "TEST",
                "message": "Message",
                "details": {"key": "value"},
            }
        }


# ============================================================================
# Client Tests (using pytest-httpx mock)
# ============================================================================

class TestDcpClient:
    def test_client_creation(self):
        client = DcpClient(base_url="http://localhost:8420")
        assert client.base_url == "http://localhost:8420"
        client.close()

    def test_client_context_manager(self):
        with DcpClient() as client:
            assert client.base_url == "http://localhost:8420"

    @pytest.mark.httpx_mock
    def test_health_check(self, httpx_mock):
        httpx_mock.add_response(json={
            "status": "ok",
            "version": "0.2.0",
            "unlocked": True,
        })

        with DcpClient() as client:
            result = client.health()
            assert result["status"] == "ok"

    @pytest.mark.httpx_mock
    def test_get_address(self, httpx_mock):
        httpx_mock.add_response(json={
            "chain": "solana",
            "address": "5xYz123...",
        })

        with DcpClient() as client:
            result = client.get_address("solana")
            assert isinstance(result, AddressResult)
            assert result.chain == "solana"
            assert result.address == "5xYz123..."

    @pytest.mark.httpx_mock
    def test_budget_check(self, httpx_mock):
        httpx_mock.add_response(json={
            "allowed": True,
            "remaining_daily": 90.0,
            "remaining_tx": 10.0,
            "requires_approval": False,
        })

        with DcpClient() as client:
            result = client.budget_check(10.0, "USDC")
            assert isinstance(result, BudgetCheckResult)
            assert result.allowed is True
            assert result.remaining_daily == 90.0

    @pytest.mark.httpx_mock
    def test_sign_tx(self, httpx_mock):
        httpx_mock.add_response(json={
            "signed_tx": "base64_signed",
            "signature": "sig123",
            "chain": "solana",
            "remaining_daily": 89.0,
        })

        with DcpClient() as client:
            result = client.sign_tx(
                chain="solana",
                unsigned_tx="base64_unsigned",
                amount=1.0,
                currency="SOL",
            )
            assert isinstance(result, SignResult)
            assert result.signed_tx == "base64_signed"
            assert result.signature == "sig123"

    @pytest.mark.httpx_mock
    def test_read(self, httpx_mock):
        httpx_mock.add_response(json={
            "scope": "credentials.api.openai",
            "data": {"api_key": "sk-test"},
            "sensitivity": "sensitive",
            "is_reference": False,
        })

        with DcpClient() as client:
            result = client.read("credentials.api.openai")
            assert isinstance(result, ReadResult)
            assert result.scope == "credentials.api.openai"
            assert result.data["api_key"] == "sk-test"

    @pytest.mark.httpx_mock
    def test_write(self, httpx_mock):
        httpx_mock.add_response(json={
            "scope": "credentials.api.github",
            "created": True,
            "updated": False,
            "sensitivity": "standard",
        })

        with DcpClient() as client:
            result = client.write("credentials.api.github", {"token": "ghp_test"})
            assert isinstance(result, WriteResult)
            assert result.created is True

    @pytest.mark.httpx_mock
    def test_error_response(self, httpx_mock):
        httpx_mock.add_response(json={
            "error": {
                "code": "SCOPE_VIOLATION",
                "message": "Access denied",
            }
        })

        with DcpClient() as client:
            with pytest.raises(DcpError) as exc_info:
                client.read("secret.data")
            assert exc_info.value.code == "SCOPE_VIOLATION"

    @pytest.mark.httpx_mock
    def test_consent_required(self, httpx_mock):
        httpx_mock.add_response(json={
            "requires_consent": True,
            "consent_id": "consent_123",
            "message": "User approval needed",
        })

        with DcpClient() as client:
            with pytest.raises(DcpError) as exc_info:
                client.sign_tx(chain="solana", unsigned_tx="tx")
            assert exc_info.value.code == "CONSENT_REQUIRED"
            assert exc_info.value.details["consent_id"] == "consent_123"

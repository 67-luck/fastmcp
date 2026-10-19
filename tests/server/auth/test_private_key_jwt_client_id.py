"""Regression tests for CIMD private_key_jwt client identification."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from fastmcp.server.auth.auth import (
    JWT_BEARER_ASSERTION_TYPE,
    PrivateKeyJWTClientAuthenticator,
)


@pytest.mark.anyio
async def test_private_key_jwt_can_derive_client_id_from_assertion_issuer():
    client_id = "https://client.example.com/metadata.json"
    authenticator = PrivateKeyJWTClientAuthenticator(
        provider=SimpleNamespace(get_client=AsyncMock()),
        cimd_manager=SimpleNamespace(validate_private_key_jwt=AsyncMock()),
        token_endpoint_url="https://mcp.example.com/token",
    )
    client = SimpleNamespace(
        client_id=client_id,
        token_endpoint_auth_method="private_key_jwt",
    )
    authenticator.provider.get_client.return_value = client
    request = SimpleNamespace(
        form=AsyncMock(
            return_value={
                "client_assertion_type": JWT_BEARER_ASSERTION_TYPE,
                # Header.payload.signature; only the payload is read before
                # validate_private_key_jwt performs full signature validation.
                "client_assertion": (
                    "eyJhbGciOiJIUzI1NiJ9."
                    "eyJpc3MiOiJodHRwczovL2NsaWVudC5leGFtcGxlLmNvbS9tZXRhZGF0YS5qc29uIn0."
                    "signature"
                ),
            }
        )
    )

    result = await authenticator.authenticate_request(request)

    assert result is client
    authenticator.provider.get_client.assert_awaited_once_with(client_id)
    authenticator._cimd_manager.validate_private_key_jwt.assert_awaited_once()

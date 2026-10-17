"""Credential-bearing API requests must never follow redirects."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.paloalto_firewall.api import PanOSClient, PanOSConnectionError


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("keygen", [False, True])
async def test_api_rejects_redirects(status, keygen) -> None:
    response = SimpleNamespace(
        status=status,
        text=AsyncMock(return_value='<response status="success"><result><key>key</key></result></response>'),
    )
    session = MagicMock()
    session.post.return_value.__aenter__.return_value = response
    client = PanOSClient(
        session, "fw.example", "seed-user", "seed-password", api_key=None if keygen else "key"
    )
    with pytest.raises(PanOSConnectionError, match=f"HTTP {status} redirect.*redirects are disabled"):
        if keygen:
            await client.generate_key()
        else:
            await client.op("<show><system><info/></system></show>")
    session.post.assert_called_once()
    kwargs = session.post.call_args.kwargs
    assert kwargs["allow_redirects"] is False
    if keygen:
        assert kwargs["data"]["password"] == "seed-password"
    else:
        assert kwargs["headers"] == {"X-PAN-KEY": "key"}
    assert not client._inflight

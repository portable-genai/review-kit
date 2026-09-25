"""A console reached through an identity-aware edge takes a bearer minted per submission.

The deployed consoles sit behind an IAP edge that accepts only a short-lived Google-signed token
minted for the edge's own audience. No environment variable can hold that, so the producer hands
the client a provider, and the client calls it once per submission and refuses a blank result
the way it refuses a blank environment variable.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest

from review_kit import Review, ReviewClient


def _review() -> Review:
    return Review(
        action="disburse_facility",
        subject="Acme Holdings (FICTIONAL)",
        maker="demo.analyst@bank.example",
        tenant="demo-bank",
        summary="Disburse SGD 2.5m facility",
        severity="high",
        required_approvals=1,
        case_ref="case-123",
        source_key="producer:demo-bank:case-123:item",
    )


class _Recorder:
    def __init__(self) -> None:
        self.headers: list[dict[str, str]] = []

    def __call__(
        self, url: str, body: bytes, headers: Mapping[str, str], timeout: float
    ) -> dict[str, Any]:
        self.headers.append(dict(headers))
        json.loads(body)
        return {"review_id": "rev-1", "tenant": "demo-bank", "state": "pending"}


@pytest.fixture(autouse=True)
def _no_static_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HUMAN_REVIEW_S2S_TOKEN", raising=False)
    monkeypatch.delenv("HUMAN_REVIEW_S2S_SIGNING_KEY", raising=False)


def test_a_remote_console_needs_no_static_token_when_a_provider_mints_one() -> None:
    transport = _Recorder()
    client = ReviewClient(
        "https://edge.example.test/apps/human-review-console/api",
        transport=transport,
        bearer_provider=lambda: "minted-for-the-edge",
    )
    client.submit(_review(), actor="producer")
    assert transport.headers[0]["Authorization"] == "Bearer minted-for-the-edge"


def test_the_provider_is_called_once_per_submission_and_never_at_construction() -> None:
    minted: list[str] = []

    def provider() -> str:
        minted.append(f"token-{len(minted)}")
        return minted[-1]

    transport = _Recorder()
    client = ReviewClient(
        "https://edge.example.test/api", transport=transport, bearer_provider=provider
    )
    assert minted == [], "constructing the client must not spend a token"
    client.submit(_review())
    client.submit(_review())
    assert [h["Authorization"] for h in transport.headers] == [
        "Bearer token-0",
        "Bearer token-1",
    ]


def test_a_blank_minted_token_is_refused_not_sent() -> None:
    transport = _Recorder()
    client = ReviewClient(
        "https://edge.example.test/api", transport=transport, bearer_provider=lambda: "  "
    )
    with pytest.raises(ValueError, match="blank"):
        client.submit(_review())
    assert transport.headers == []


def test_without_a_provider_a_remote_console_still_requires_the_static_token() -> None:
    with pytest.raises(ValueError, match="HUMAN_REVIEW_S2S_TOKEN"):
        ReviewClient("https://edge.example.test/api", transport=_Recorder())

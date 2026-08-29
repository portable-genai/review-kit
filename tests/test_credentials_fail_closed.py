"""An absent or blank S2S credential is refused, not read as consent to submit unauthenticated.

Neither credential may be a two-state read: ``os.environ.get(name, "")``, where "absent" and
"set to nothing" collapse into the same empty string and the empty string means "carry on without
it". Two concrete fail-opens follow from that read.

* A producer pointed at a REMOTE console with no ``HUMAN_REVIEW_S2S_TOKEN`` submits the
  review with no ``Authorization`` header at all, and only finds out at the far end (or,
  against a console whose own S2S policy is unconfigured, does not find out).
* A blank-but-set value counts as configured. An unstripped read, unlike
  ``hex_service_kit.s2s.client_headers`` which this file claims to stay wire-identical to, sends
  ``Authorization: Bearer`` with nothing behind it for ``HUMAN_REVIEW_S2S_TOKEN=" "``, and
  ``HUMAN_REVIEW_S2S_SIGNING_KEY=" "`` HMAC-signs the actor assertion with a blank,
  publicly guessable key: a signature that attests nothing while looking like it attests
  the submitter.

The loopback console keeps the zero-secret posture, because that is the same carve-out the
base-URL guard above it already makes and the receiving console's deliberate ``local`` profile
exists to serve.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from review_kit import Review, ReviewClient

_TOKEN_ENV = "HUMAN_REVIEW_S2S_TOKEN"
_KEY_ENV = "HUMAN_REVIEW_S2S_SIGNING_KEY"
_REMOTE = "https://review.internal"
_LOOPBACK = "http://localhost:8087"


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    monkeypatch.delenv(_KEY_ENV, raising=False)


def _review() -> Review:
    return Review(
        action="disburse_facility",
        subject="Acme Holdings (FICTIONAL)",
        maker="demo.analyst@bank.example",
        tenant="demo-bank",
        summary="Disburse SGD 2.5m facility",
        severity="high",
        required_approvals=2,
    )


def _capture() -> tuple[dict[str, Any], Any]:
    seen: dict[str, Any] = {}

    def transport(
        url: str, body: bytes, headers: Mapping[str, str], timeout: float
    ) -> dict[str, Any]:
        seen["headers"] = dict(headers)
        return {"review_id": "rev-1", "tenant": "demo-bank", "state": "pending"}

    return seen, transport


def test_a_remote_console_refuses_to_be_called_without_a_bearer() -> None:
    with pytest.raises(ValueError) as excinfo:
        ReviewClient(_REMOTE)
    assert _TOKEN_ENV in str(excinfo.value)


def test_the_refusal_happens_at_construction_not_at_the_far_end() -> None:
    """No request is built, so nothing depends on the console being reachable to find this out."""
    _, transport = _capture()
    with pytest.raises(ValueError, match=_TOKEN_ENV):
        ReviewClient(_REMOTE, transport=transport)


def test_a_blank_bearer_is_refused_rather_than_sent_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "   ")
    with pytest.raises(ValueError, match="blank"):
        ReviewClient(_REMOTE)


def test_a_blank_signing_key_is_refused_rather_than_used_to_sign(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A blank HMAC key is a key everyone knows, so the signature would attest nothing."""
    monkeypatch.setenv(_TOKEN_ENV, "fictional-demo-token")
    monkeypatch.setenv(_KEY_ENV, "  ")
    with pytest.raises(ValueError, match="blank"):
        ReviewClient(_REMOTE)


def test_a_loopback_console_keeps_the_zero_secret_posture() -> None:
    seen, transport = _capture()
    ReviewClient(_LOOPBACK, transport=transport).submit(_review(), actor="svc")
    assert "Authorization" not in seen["headers"]
    assert "X-S2S-Actor" not in seen["headers"]


def test_a_configured_bearer_is_sent_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "  fictional-demo-token\n")
    seen, transport = _capture()
    ReviewClient(_REMOTE, transport=transport).submit(_review())
    assert seen["headers"]["Authorization"] == "Bearer fictional-demo-token"


def test_a_configured_key_signs_the_actor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_TOKEN_ENV, "fictional-demo-token")
    monkeypatch.setenv(_KEY_ENV, "fictional-demo-key")
    seen, transport = _capture()
    ReviewClient(_REMOTE, transport=transport).submit(_review(), actor="case-engine")
    assert seen["headers"]["X-S2S-Actor"] == "case-engine"
    assert len(seen["headers"]["X-S2S-Actor-Sig"]) == 64


def test_an_unsigned_actor_is_omitted_rather_than_asserted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recorded choice, not an accident: an unsigned claim of who submitted is worse than none.

    The alternative directions were both rejected. Sending the actor unsigned would let any
    caller name a submitter. Refusing the submission would stop an escalation reaching a human
    over a header nothing verifies yet, which closes the wrong door: the review IS the control.
    """
    monkeypatch.setenv(_TOKEN_ENV, "fictional-demo-token")
    seen, transport = _capture()
    ReviewClient(_REMOTE, transport=transport).submit(_review(), actor="case-engine")
    assert seen["headers"]["Authorization"] == "Bearer fictional-demo-token"
    assert "X-S2S-Actor" not in seen["headers"]
    assert "X-S2S-Actor-Sig" not in seen["headers"]


def test_a_credential_cleared_after_construction_cannot_downgrade_a_live_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The resolution is per submit, so a long-lived client cannot keep serving after a change."""
    monkeypatch.setenv(_TOKEN_ENV, "fictional-demo-token")
    _, transport = _capture()
    client = ReviewClient(_REMOTE, transport=transport)
    monkeypatch.delenv(_TOKEN_ENV)
    with pytest.raises(ValueError, match=_TOKEN_ENV):
        client.submit(_review())


def test_a_custom_env_var_name_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    """Producers pass their own names, so the refusal must name the variable THEY set."""
    with pytest.raises(ValueError, match="CDD_S2S_TOKEN"):
        ReviewClient(_REMOTE, token_env="CDD_S2S_TOKEN", signing_key_env="CDD_S2S_SIGNING_KEY")

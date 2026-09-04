"""The review-submission client: POST a review to an human-review-console-compatible service intake,
S2S-authed.

Reuses the shared S2S transport hardening from ``hex-service-kit`` (the https-only base-URL guard
and the bearer / signed-actor headers) rather than re-implementing it. The HTTP transport is
pluggable so the client is unit-testable offline with no live server; the default is a small
stdlib ``urllib`` POST (no third-party HTTP dependency).

Every credential is resolved through :func:`_resolve_secret`, which distinguishes three states
(unset, set-and-blank, set-and-valid) rather than the two a bare ``os.environ.get(name, "")``
can see. Unset is not a member of the valid set: a console reachable over the network needs a
configured bearer, and the client refuses at construction rather than submitting the review
unauthenticated and discovering that at the far end. A set-but-blank value is refused outright,
never treated as configured, so a bearer is never sent empty and an actor is never HMAC-signed
with a guessable blank key. The loopback carve-out is the same one the base-URL guard already
makes: an ``http://localhost`` console is the zero-secret offline posture that the receiving
console's deliberate ``local`` profile exists to serve.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlparse

from .models import Review, ReviewSubmitted

#: A transport is (url, body, headers, timeout) -> parsed JSON dict. Injectable for testing.
Transport = Callable[[str, bytes, Mapping[str, str], float], dict[str, Any]]

_SERVICE_PATH = "/v1/service/reviews"
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# The S2S actor headers, kept byte-for-byte compatible with hex-service-kit's server verifier
# (``hex_service_kit.web.make_require_service_caller``) so human-review-console accepts what this
# client sends.
_ACTOR_HEADER = "X-S2S-Actor"
_ACTOR_SIG_HEADER = "X-S2S-Actor-Sig"


def _is_loopback(url: str) -> bool:
    """Is this console on the local machine, and therefore the zero-secret dev posture?"""
    return (urlparse(url).hostname or "") in _LOOPBACK_HOSTS


def _validate_base_url(url: str, *, service: str) -> str:
    """Return ``url`` without a trailing slash; refuse plaintext outside loopback (https-only).

    Self-contained (no hex-service-kit dependency) so this kit installs zero-dep and zero-cred like
    ``pii-kit``, avoiding the nested git+https resolution conflict a commons-on-commons dep causes.
    """
    stripped = url.rstrip("/")
    parsed = urlparse(stripped)
    host = parsed.hostname or ""
    if parsed.scheme == "https":
        return stripped
    if parsed.scheme == "http" and host in _LOOPBACK_HOSTS:
        return stripped
    raise ValueError(f"{service} base URL must be https outside loopback (got {url!r})")


def _resolve_secret(env_name: str, *, required: bool, purpose: str) -> str:
    """Resolve one credential in THREE states, where unset is not a member of the valid set.

    * unset: absent from the environment. Refused when ``required``; otherwise "" (the feature
      it enables is simply not used), because an absent variable is a state of its own and never
      a stand-in for a configured value.
    * set and blank (``""`` or whitespace): ALWAYS refused. A blank credential is a value someone
      believes they configured, and treating it as configured is how an empty bearer gets sent as
      ``Authorization: Bearer`` or a blank, publicly guessable key gets used to HMAC an actor
      assertion that then looks authenticated.
    * set and non-blank: returned stripped, exactly as ``hex_service_kit.s2s.client_headers``
      does, so the two stay wire-identical.

    This is the ONLY place in the package that reads the environment
    (``tests/test_env_single_source.py`` fails the build if a second reader appears).
    """
    raw = os.environ.get(env_name)
    if raw is None:
        if required:
            raise ValueError(
                f"{env_name} is not set, so {purpose} is unconfigured. An absent credential is "
                "not consent to submit unauthenticated: set it, or point the client at a "
                "loopback console for the offline zero-secret posture."
            )
        return ""
    value = raw.strip()
    if not value:
        raise ValueError(
            f"{env_name} is set but blank, which is refused rather than read as a configured "
            f"value for {purpose}. Unset it, or give it the real credential."
        )
    return value


def _client_headers(actor: str, *, token: str, signing_key: str) -> dict[str, str]:
    """Auth headers for one outbound S2S request: a bearer token, and an HMAC-signed actor.

    Both credentials arrive already resolved by :func:`_resolve_secret`, so a blank one cannot
    reach here. With no signing key the actor pair is OMITTED rather than sent unsigned: an
    unsigned assertion of who submitted the review is worth less than no assertion, and the
    receiving console reads the S2S caller, not this header, as the trust anchor today.
    """
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if actor and signing_key:
        signature = hmac.new(
            signing_key.encode("utf-8"), actor.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        headers[_ACTOR_HEADER] = actor
        headers[_ACTOR_SIG_HEADER] = signature
    return headers


class ReviewClientError(RuntimeError):
    """Raised when a review submission fails (non-2xx response or an unreachable console)."""


def _urllib_transport(
    url: str, body: bytes, headers: Mapping[str, str], timeout: float
) -> dict[str, Any]:  # pragma: no cover - exercised against a live server, not in the offline gate
    request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload: dict[str, Any] = json.loads(response.read().decode("utf-8"))
            return payload
    except urllib.error.HTTPError as exc:
        raise ReviewClientError(
            f"human-review-console review intake returned {exc.code}: {exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        raise ReviewClientError(
            f"human-review-console review intake unreachable: {exc.reason}"
        ) from exc


class ReviewClient:
    """Submit a review to an human-review-console-compatible console at ``base_url`` (rule R8's
    client half).
    """

    def __init__(
        self,
        base_url: str,
        *,
        service: str = "hrz7-review-console",
        token_env: str = "HUMAN_REVIEW_S2S_TOKEN",
        signing_key_env: str = "HUMAN_REVIEW_S2S_SIGNING_KEY",
        timeout: float = 10.0,
        transport: Transport | None = None,
    ) -> None:
        # https-only outside loopback; a plaintext non-loopback URL is refused at construction.
        self._base = _validate_base_url(base_url, service=service)
        self._token_env = token_env
        self._signing_key_env = signing_key_env
        # A console anywhere but this machine is reachable by something other than this process,
        # so it needs a bearer. Refusing HERE, beside the transport guard, turns a misconfigured
        # producer into a construction error rather than a review that silently leaves
        # unauthenticated and is rejected (or, on a misconfigured console, accepted) at the far
        # end. cdd-sow-research had hand-rolled exactly this rule around its own client; it belongs
        # in the
        # shared primitive so every producer inherits it.
        self._token_required = not _is_loopback(self._base)
        self._resolve_credentials()
        self._timeout = timeout
        self._transport: Transport = transport or _urllib_transport

    def _resolve_credentials(self) -> tuple[str, str]:
        """Resolve the bearer and signing key, refusing an unset or blank one where it matters.

        Re-read on every submit rather than cached at construction, so a credential cleared or
        blanked after start-up cannot leave a long-lived client silently downgraded.
        """
        token = _resolve_secret(
            self._token_env,
            required=self._token_required,
            purpose="the human-review-console service bearer",
        )
        signing_key = _resolve_secret(
            self._signing_key_env,
            required=False,
            purpose="signed-actor propagation",
        )
        return token, signing_key

    def submit(self, review: Review, *, actor: str = "") -> ReviewSubmitted:
        """Submit one review. ``actor`` is the submitting service's identity for the S2S header."""
        token, signing_key = self._resolve_credentials()
        headers = {
            "Content-Type": "application/json",
            **_client_headers(actor, token=token, signing_key=signing_key),
        }
        body = json.dumps(review.to_payload()).encode("utf-8")
        data = self._transport(self._base + _SERVICE_PATH, body, headers, self._timeout)
        try:
            return ReviewSubmitted(
                review_id=str(data["review_id"]),
                tenant=str(data.get("tenant", review.tenant)),
                state=str(data.get("state", "pending")),
            )
        except (KeyError, TypeError) as exc:
            raise ReviewClientError(f"malformed human-review-console response: {data!r}") from exc

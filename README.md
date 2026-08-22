# review-kit

The shared **producer half of dependency rule R8**: a small, domain-neutral client for routing a
`requires_human_review` escalation to an Hrz7-compatible Human-Review & Maker-Checker Console,
plus a transactional outbox. Every producer submits reviews the same way through this primitive
instead of copy-pasting an HTTP call into each repo (finding 1: extract, do not copy-paste).

Zero runtime dependencies (pure stdlib), exactly like `pii-kit`: a leaf commons that consumers
pin cannot itself pull another git+https commons without the nested tag-vs-SHA reference
conflicting with the consumer's own lockfile, so the small S2S client helpers (a stdlib `urllib`
POST, the https-only base-URL guard, and the bearer / HMAC-signed-actor headers) are inlined and
kept wire-compatible with `hex-service-kit`'s server verifier. The transport is pluggable, so the
client is unit-testable with no live server.

## Use

```python
from review_kit import Review, ReviewClient, InMemoryOutbox

client = ReviewClient("https://hrz7-review-console.internal")  # https-only off loopback

review = Review(
    action="disburse_facility",
    subject="Acme Holdings (FICTIONAL)",
    maker="demo.analyst@bank.example",   # who originated the underlying decision
    tenant="demo-bank",                  # the producing service asserts these; Hrz7 trusts the S2S caller
    severity="high",
    required_approvals=2,                # dual control
    case_ref="case-123",                 # optional link to an Hrz6 case
)

# Direct submit ...
result = client.submit(review, actor="hrz6-case-engine")
print(result.review_id, result.state)

# ... or via the outbox, so a submission survives Hrz7 being down.
outbox = InMemoryOutbox()
outbox.enqueue(review, actor="hrz6-case-engine")
outbox.flush(client)   # failed entries stay enqueued and retry on the next flush
```

The client POSTs to Hrz7's **service intake** (`POST /v1/service/reviews`), which is authenticated
as a trusted service caller (not the end user) and accepts the asserted `maker` + `tenant` in the
body. Per-hop OAuth2 token-exchange (on-behalf-of) is the deferred next layer; until then the
submitting service is the trust anchor on this path.

## Credentials fail closed

Both env vars are resolved in three states (unset, set-and-blank, set-and-valid) and unset is not
a member of the valid set:

| Console | `HRZ7_S2S_TOKEN` | Result |
|---|---|---|
| `https://...` (remote) | unset | **Refused at construction**, naming the variable. An absent credential is not consent to submit unauthenticated. |
| `https://...` (remote) | set, blank | **Refused.** A blank value is never read as configured, so no empty bearer is ever sent. |
| `https://...` (remote) | set | Sent stripped as `Authorization: Bearer ...`. |
| `http://localhost...` | unset | Allowed: the zero-secret offline posture, the same loopback carve-out the https-only base-URL guard makes. |

`HRZ7_S2S_SIGNING_KEY` follows the same rule for blank values (a blank HMAC key is a key everyone
knows). When it is unset the signed-actor pair is **omitted** rather than sent unsigned: an
unsigned claim of who submitted the review is worth less than no claim, and blocking the
submission would stop an escalation reaching a human over a header nothing verifies yet.

Credentials are re-resolved on every `submit`, so clearing one cannot leave a long-lived client
silently downgraded.

## Pin

```
review-kit @ git+https://github.com/portable-genai/review-kit@v0.0.1
```

Public, so consumers pin by tag with zero credentials, exactly like `pii-kit`, `hex-service-kit`
and `agent-eval-kit`. Apache-2.0. Synthetic, obviously fictional data only in examples.

# API reference

The container serves plain HTTP on port 8000. Public clients reach it through the
Cortex master at `https://<gateway>/challenge/bounty/<path>`; the master refuses
any path under `internal/` and forwards only the `content-type`, `accept` and
`authorization` headers.

Errors are JSON `{"error": "<reason>"}` with a stable, bounded reason. Upstream
bodies, tokens and request contents are never echoed. Unknown paths return
FastAPI's `404 {"detail": "Not Found"}`.

## Authentication

| Credential | File | Used by |
| --- | --- | --- |
| internal bearer | `CHALLENGE_INTERNAL_TOKEN_FILE` | `GET /internal/v1/get_weights` |
| operator bearer | `CHALLENGE_ADMIN_TOKEN_FILE` | `/v1/admin/*`, `GET /v1/reports*` |
| session | returned by `POST /v1/pair` | `POST /v1/reports` |

Bearer files are read on every request, so rotation needs no restart. A file must
be a regular, non-symlink file with no group or other permission bits. The header
is `Authorization: Bearer <token>` and is compared through SHA-256 digests in
constant time.

| Condition | Status | Reason |
| --- | --- | --- |
| file missing | 503 | `auth_unconfigured` |
| file readable by group or others, or not a regular file | 503 | `credential file must be private` |
| file empty, unreadable or over 8192 bytes | 503 | `credential file unavailable` |
| header missing or token wrong | 401 | `unauthorized` |

Authentication is checked before a body is read.

## Body limits

| Route | Limit |
| --- | --- |
| `POST /v1/pair`, `POST /v1/admin/pair-grants`, `POST /v1/admin/adjudicate` | 4096 bytes |
| `POST /v1/reports` | 262144 bytes |

The service stops reading at the limit and returns `413 <label> request too large`
before parsing, signature, session or feed work. A body that is not the exact
JSON schema (unknown fields, wrong types, strict typing) returns
`422 invalid <label> request`. Labels: `pair`, `pair grant`, `report`,
`adjudication`.

## Contract routes

### `GET /health`

Readiness. `200 {"ok": true}` when a validated feed snapshot is available (the
probe is shared: successes for 15 s, failures for 5 s, concurrent refreshes fail
fast) and the state database opens. Otherwise
`503 {"ok": false, "reason": "<reason>"}`. The supervisor only reports it.

### `GET /version`

Liveness. Always `200` once the process serves, with or without secrets:

```json
{"slug": "bounty", "version": "1.0.0", "contract": 1, "capabilities": ["get_weights", "proxy_routes"]}
```

### `GET /internal/v1/get_weights?epoch=<u64>`

Headers: `Authorization: Bearer <internal token>` and
`X-Platform-Challenge-Slug: bounty`.

```json
{
  "challenge_slug": "bounty",
  "epoch": 25316,
  "weights": {"5F...": 3, "5G...": 1},
  "full_share_mass": 10,
  "metadata": {"revision": "42", "published": 17, "valid": 4},
  "computed_at": "2026-09-24T12:00:00Z"
}
```

`weights` holds every author with at least one valid report in one fully
validated feed snapshot, keyed by SS58 hotkey, with integer counts. `metadata`
names the pinned publication revision, its report count and its valid count.
The first successful answer for an epoch is stored and every later call for that
epoch returns the same bytes, even during a feed outage.

| Status | Reason |
| --- | --- |
| 400 | `epoch must be a canonical u64` (missing, signed, leading zero, non-digit, > 2^64-1) |
| 401 | `unauthorized` |
| 403 | `challenge slug mismatch` |
| 503 | feed reason (for example `scoring unconfigured: set BOUNTY_BACKEND_PUBLIC_URL`, `backend public fetch failed: HTTP 503`, `backend public leaderboard and reports do not agree`); nothing is stored |
| 503 | `state unavailable`, `too many valid authors for one weight answer`, bearer file reasons |

## Public routes

### `GET /v1/status`

Always `200`. Reports `can_score` and `reason` from the shared feed probe,
`scoring_backend` (`backend_public` or `unconfigured`),
`backend_public_configured`, `scoring_version: 2`, `score_max`, the pairing
rules, the scoring constants (`points_per_valid_report: 1`,
`full_share_reports: 10`, population, window, severities), the quotas and the
terms text. The emission share is not reported: the Cortex owner decides it.

### `POST /v1/pair`

Body: `account_id` (`[A-Za-z0-9._:-]{1,128}`), `hotkey` (SS58 or 64-hex),
`nonce` (16 to 64 hex), `exp` (Unix seconds), `signature` (64-byte sr25519 hex,
optional `0x`), `terms_accepted`.

The signature is over `cortex-bounty-v1|{account_id}|{nonce}|{exp}` in the
Substrate signing context. On success, the nonce and the operator grant are
consumed and the account's previous session is revoked in one SQLite transaction.

`201 {"session", "session_id", "account_id", "miner_hotkey"}`; only the
session's SHA-256 is stored.

| Status | Reason |
| --- | --- |
| 400 | `invalid account_id`, `invalid nonce`, `invalid or expired pairing window`, `invalid hotkey or signature`, `invalid signature` |
| 401 | `signature verification failed` |
| 403 | `terms_required`, `pairing not authorized by account operator` |
| 409 | `nonce reused` (no session data; does not consume a grant) |
| 413, 422 | body limit, schema |
| 503 | `session secret unconfigured`, `session secret must hold at least 32 bytes`, private-file reasons |

### `POST /v1/reports`

Body: `session`, optional `hotkey`, `title` (at most 512 characters), `body` and
optional `repro_steps` (each at most 100000 characters).

`201 {"id", "miner_hotkey", "state", "fingerprint"}`. `state` is `pending`, or
`duplicate` when the normalized title and body match an earlier report.

Checks run in this order: feed configured, session, hotkey match, substance,
per-hotkey lock, quotas, an uncached feed read, session again (a re-pairing during
the read revokes it), then the insert with quotas rechecked in the transaction.

| Status | Reason |
| --- | --- |
| 400 | `invalid hotkey`, `title_and_body_required`, `title_and_body_must_differ`, `body must be at least 80 characters`, `repro_steps must be at least 20 characters`, `body_lacks_distinct_evidence` |
| 401 | `invalid_session` |
| 403 | `hotkey_mismatch` |
| 429 | `report validation already in progress for this hotkey`, `5 reports already awaiting adjudication for this hotkey (max 5)`, `one report per 60s per hotkey` |
| 413, 422 | body limit, schema |
| 503 | `scoring unconfigured: set BOUNTY_BACKEND_PUBLIC_URL`, any feed reason, session-secret reasons; no row is created |

## Operator routes

### `POST /v1/admin/pair-grants`

Body: `account_id`, `hotkey`, `expires_at` (Unix seconds, in the future and at
most 300 seconds ahead). Creates or refreshes the single-use grant for that exact
account and hotkey. `201 {"account_id", "miner_hotkey", "expires_at"}` with the
hotkey as 64-hex.

Errors: `400` (`invalid account_id`, `invalid hotkey`,
`pair grant must expire in the future`,
`pair grant must expire within 300 seconds`), `401`, `413`, `422`, `503`.

### `GET /v1/reports` and `GET /v1/reports/{id}`

`200 {"items": [row, ...]}` (newest first) or one row. A row has `id`,
`miner_hotkey`, `account_id`, `title`, `body`, `repro_steps`, `fingerprint`,
`state`, `adjudication`, `severity`, `duplicate_of` and `created_at`.
Unknown id: `404 not_found`.

### `POST /v1/admin/adjudicate`

Body: `report_id`, `verdict` (`valid`, `already_fixed_not_prod`,
`invalid_malicious`, `duplicate`), `severity` (required for `valid` only:
`trivial`, `minor`, `major`, `critical`), `duplicate_of` (required for
`duplicate` only). Returns `200` with the updated row. A `pending` report, or one
auto-marked `duplicate` at intake, can be adjudicated once.

| Status | Reason |
| --- | --- |
| 404 | `not_found` (report or `duplicate_of`) |
| 409 | `severity required for valid verdict`, `severity is only valid for a valid verdict`, `already adjudicated`, `duplicate_of required`, `report cannot duplicate itself`, `duplicate_of is only valid for duplicate verdicts` |
| 401, 413, 422, 503 | authentication, body limit, schema, configuration |

Local adjudications support triage only. They earn nothing until CortexLM/backend
publishes the report.

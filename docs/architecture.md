# Architecture

## Where it runs

```text
CortexLM/backend  ──public feed──▶  bounty container  ◀──get_weights──  Cortex master
 (adjudication,                      (this repo)          proxy /challenge/bounty/*
  publication)                       /data/bounty.sqlite3
```

The Cortex master's challenge supervisor runs `ghcr.io/cortexlm/bounty` as
`cortex-challenge-bounty` on the private `cortex-challenges` network. The
container never publishes a host port. It runs as UID 65532 with a read-only
root filesystem, no capabilities, a `/tmp` tmpfs, one named volume at `/data`
(created by the image with owner `65532:65532`) and read-only secrets under
`/run/secrets/`.

`bounty-challenge serve` is one uvicorn process on port 8000. It holds no
leaf-signing key. The master signs leaves; validators verify the sealed bundle
and never contact this container.

## Components

| Module | Role |
| --- | --- |
| `app.py` | routes, bounded body reads, error mapping |
| `service.py` | pairing, intake, weight answers, bearer checks |
| `feed.py` | CortexLM/backend public feed reader and validation |
| `store.py` | SQLite state (`BEGIN IMMEDIATE` for every write) |
| `settings.py` | environment and private secret files |
| `crypto.py` | SS58 codec and Substrate-context sr25519 verification |

## Startup without secrets

The supervisor canary starts the image with no secrets and a tmpfs `/data`, and
expects `/version` within 60 seconds. Nothing is read at startup: secret files
are read on each request that needs them, and the SQLite store opens on first
use. A missing secret or an unusable `/data` makes only the dependent routes
return `503`.

## The feed

CortexLM/backend adjudicates and publishes reports. This container only reads
`BOUNTY_BACKEND_PUBLIC_URL` (HTTPS, no credentials, no query, redirects not
followed):

1. `GET /v1/bounty/public/status` pins one immutable revision and its counters.
2. `GET /v1/bounty/public/leaderboard?revision=<r>`.
3. Every `GET /v1/bounty/public/reports?revision=<r>&limit=100[&cursor=…]` page
   until `has_more` is false.

A snapshot is accepted only when all of these hold: API version 1; adjudication
available; no unpriced valid report; no adjudication backlog on an empty
publication; one revision across every response; complete pagination with no
repeated cursor; unique report ids and leaderboard hotkeys; valid hotkeys;
nonempty evidence; severity present exactly on `valid`; every duplicate chain
ending at a non-duplicate report; and exact agreement between status counters,
the reports and the leaderboard. A truncated leaderboard must be an exact ranked
prefix of the ranking rebuilt from the reports.

Each response is capped at 8 MiB and the report set at 64 MiB. Transport, HTTP
404/408/409/425/429/5xx, JSON and revision-change errors get at most three
attempts inside one 30-second deadline; stable gates fail at once.

Reads are uncached for report intake and for `get_weights`. `/health` and
`/v1/status` share a probe cached 15 seconds on success and 5 seconds on failure.

## Epochs

The master calls `GET /internal/v1/get_weights?epoch=<n>` once per completed
epoch. The container answers from one validated snapshot and stores the exact
response bytes in the `bounty_epoch_weights` table of `/data/bounty.sqlite3`
before returning them. Every later call for that epoch returns the stored bytes,
so a retry or a master restart can never see a different answer. When the feed
fails, the response is `503`, nothing is stored, and the master burns the Bounty
share for that epoch.

Counts are cumulative over the whole publication; the epoch number only keys the
stored answer.

## Master interaction

| Direction | Route | Authentication |
| --- | --- | --- |
| master to container | `GET /internal/v1/get_weights` | internal bearer + `X-Platform-Challenge-Slug: bounty` |
| supervisor to container | `GET /version` (liveness), `GET /health` (readiness, reported only) | none |
| client to master to container | `ANY /challenge/bounty/<path>` | per route |

The master proxy refuses `internal/` paths, forwards only `content-type`,
`accept` and `authorization`, and limits bodies to its `proxy_body_limit`. This
container applies its own, smaller limits.

The container does not call `CHALLENGE_MASTER_URL`. Weights include every author
with a valid report, and the master restricts them to the sealed participant set.

## Auto-update

1. Every push to `main` runs CI, then builds one image, pushes
   `sha-<commit>` and `edge`, and attests that digest with GitHub build
   provenance.
2. An annotated tag `vX.Y.Z` on `main` aliases the existing `sha-<commit>`
   digest to `vX.Y.Z` and `stable` without rebuilding, so the attestation still
   covers it.
3. The supervisor polls the configured channel. For a new digest it checks the
   labels (`io.cortex.challenge.slug=bounty`, `io.cortex.challenge.contract=1`,
   `org.opencontainers.image.source`), the attestation, and a secretless canary's
   `/version`. It then replaces the container on the same volume and rolls back
   when `/version` does not answer.

The SQLite schema only grows with `CREATE TABLE IF NOT EXISTS`, so a rollback to
an earlier 1.x image keeps working on the same volume.

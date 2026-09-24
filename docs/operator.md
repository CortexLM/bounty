# Operator guide

## Registry entry

The Cortex master runs Bounty from its unsigned challenge registry
(`challenge-registry.toml`). The owner-signed trust root (`challenges.toml`)
separately decides whether `bounty` earns emission and its share. Field names
below follow the Cortex challenge-container contract; check the Cortex registry
reference for the exact table syntax and `resources` keys.

```toml
[[challenge]]
id = "bounty"
image = "ghcr.io/cortexlm/bounty"
channel = "stable"                              # or "edge"; `pin = "sha256:…"` freezes a digest
source = "https://github.com/CortexLM/bounty"    # must equal the image source label
poll_seconds = 300
proxy_body_limit = 1048576                      # the container enforces 262144 for reports
proxy_timeout_seconds = 30

[challenge.env]
BOUNTY_BACKEND_PUBLIC_URL = "https://<cortexlm-backend-public-host>"
```

The supervisor sets `CHALLENGE_SLUG=bounty`, `CHALLENGE_STATE_DIR=/data`,
`CHALLENGE_INTERNAL_TOKEN_FILE`, `CHALLENGE_ADMIN_TOKEN_FILE` and
`CHALLENGE_MASTER_URL` itself.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `BOUNTY_BACKEND_PUBLIC_URL` | unset | CortexLM/backend public API base. HTTPS, no credentials, query or fragment |
| `BOUNTY_SESSION_SECRET_FILE` | `/run/secrets/session.key` | HMAC key for pairing sessions |
| `CHALLENGE_SLUG` | `bounty` | any other value stops the process at startup |
| `CHALLENGE_STATE_DIR` | `/data` | holds `bounty.sqlite3` |
| `CHALLENGE_INTERNAL_TOKEN_FILE` | `/run/secrets/internal.token` | master bearer for `get_weights` |
| `CHALLENGE_ADMIN_TOKEN_FILE` | `/run/secrets/admin.token` | operator bearer |

Everything fails closed and nothing is read at startup:

- no feed URL, or an unsafe one: `/health`, report intake and `get_weights`
  return `503`, and no report row is created;
- no `admin.token`: operator routes return `503 auth_unconfigured`;
- no `internal.token`: `get_weights` returns `503 auth_unconfigured`, and the
  master burns the share for that epoch;
- no `session.key`: pairing and intake return `503`.

## Secrets

Put three files in `<BASE_CHALLENGE_SECRETS_DIR>/bounty/` on the master host. The
supervisor mounts that directory read-only at `/run/secrets/`. Each file must be a
regular file owned by UID 65532 with mode `0600`; a file readable by group or
others is refused with `503`.

| File | Content |
| --- | --- |
| `internal.token` | the bearer the master sends to `get_weights` |
| `admin.token` | the operator bearer for `/v1/admin/*` and report reads |
| `session.key` | at least 32 bytes: 32 raw bytes, or hex (for example 64 hex characters) |

```bash
dir="$BASE_CHALLENGE_SECRETS_DIR/bounty"
install -d -m 0700 -o 65532 -g 65532 "$dir"
umask 077
openssl rand -hex 32 > "$dir/admin.token"
openssl rand -hex 32 > "$dir/session.key"     # new deployments only; see migration below
chown 65532:65532 "$dir"/*.token "$dir/session.key"
```

Tokens are read on every request, so replacing a token file rotates it without a
restart. Replacing `session.key` revokes every existing session.

## Opening intake

1. `curl "$GATEWAY/challenge/bounty/v1/status"` shows `can_score: true`.
2. Grant and pair a test hotkey, then submit a substantive report.
3. Adjudicate it through the operator route.
4. Confirm that CortexLM/backend publishes a stable, matching snapshot and that
   the next epoch's weights include the test hotkey.

## Pairing grants

Verify out of band that the miner controls the Cortex Chat account, then:

```bash
curl --fail-with-body -H "Authorization: Bearer $(cat admin.token)" \
  -H 'Content-Type: application/json' \
  -d "{\"account_id\":\"$ACCOUNT\",\"hotkey\":\"$HOTKEY\",\"expires_at\":$(( $(date +%s) + 300 ))}" \
  "$GATEWAY/challenge/bounty/v1/admin/pair-grants"
```

A grant binds that exact account and hotkey, expires within 300 seconds, and is
consumed only by a successful pairing. Granting a different hotkey for a paired
account lets the miner replace the hotkey; the old session is revoked.

## Adjudication

```bash
auth="Authorization: Bearer $(cat admin.token)"
curl -H "$auth" "$GATEWAY/challenge/bounty/v1/reports"
curl -H "$auth" "$GATEWAY/challenge/bounty/v1/reports/by_0000000000000001"
curl -H "$auth" -H 'Content-Type: application/json' \
  -d '{"report_id":"by_0000000000000001","verdict":"valid","severity":"major"}' \
  "$GATEWAY/challenge/bounty/v1/admin/adjudicate"
```

Verdicts are `valid` (requires `severity`), `already_fixed_not_prod`,
`invalid_malicious` and `duplicate` (requires `duplicate_of`). These local rows
support triage only. They earn nothing until CortexLM/backend publishes the
report; this container does not export them.

## Release channels

| Tag | Moves | Use |
| --- | --- | --- |
| `sha-<commit>` | never | exact build of a `main` commit |
| `edge` | every push to `main` | staging |
| `vX.Y.Z` | never | a release |
| `stable` | every release | production |

To release, set `version` in `pyproject.toml` and add the `CHANGELOG.md` entry on
`main`, wait for the `images` workflow to publish `sha-<commit>`, then push an
annotated tag:

```bash
git tag -a v1.0.1 -m "v1.0.1" && git push origin v1.0.1
```

The `release` workflow points `v1.0.1` and `stable` at the same digest (no
rebuild) and creates the GitHub release. Every published digest has a GitHub
build-provenance attestation:

```bash
gh attestation verify oci://ghcr.io/cortexlm/bounty:stable --repo CortexLM/bounty
```

## Migrating from the in-process Cortex bounty

`bounty.sqlite3` keeps the exact schema of the Cortex in-process store
(`bounty_nonces`, `bounty_pair_grants`, `bounty_ids`, `bounty_sessions`,
`bounty_pairings`, `bounty_reports` and their indexes). The container only adds
`bounty_epoch_weights`. Session tokens are `HMAC-SHA256(session.key, …)` exactly
as before. A copied database with the same key keeps every pairing, session,
consumed nonce, pending grant, report and adjudication.

1. Stop the old master so nothing writes the database:

   ```bash
   docker compose --profile master stop gateway
   ```

2. Copy the session secret. The Cortex file (`BOUNTY_SESSION_SECRET_FILE`, usually
   `bounty-session.key` in the master secrets directory) becomes `session.key`
   unchanged:

   ```bash
   dir="$BASE_CHALLENGE_SECRETS_DIR/bounty"
   install -m 0600 -o 65532 -g 65532 "$BASE_MASTER_SECRETS_DIR/bounty-session.key" "$dir/session.key"
   ```

3. Create the Bounty volume before the supervisor starts the container, and copy
   the database through the SQLite backup API, which includes any content still in
   the WAL. Use the volume name your supervisor mounts at `/data` for `bounty`.
   `base-master-state` is the master state volume from
   `deploy/compose/role-master.yml`.

   ```bash
   BOUNTY_VOLUME=<bounty volume>
   docker volume create "$BOUNTY_VOLUME"
   docker run --rm -i --user 65532:65532 --network none --read-only --tmpfs /tmp \
     -v base-master-state:/old -v "$BOUNTY_VOLUME":/data \
     --entrypoint python ghcr.io/cortexlm/bounty:stable - <<'PY'
   import os, sqlite3
   dest = "/data/bounty.sqlite3"
   os.close(os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))  # never overwrite
   source = sqlite3.connect("/old/bounty.sqlite3")
   target = sqlite3.connect(dest)
   source.backup(target)
   assert target.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
   for table in ("bounty_nonces", "bounty_pair_grants", "bounty_sessions",
                 "bounty_pairings", "bounty_reports"):
       query = f"SELECT count(*) FROM {table}"
       old, new = source.execute(query).fetchone()[0], target.execute(query).fetchone()[0]
       assert old == new, (table, old, new)
       print(table, new)
   target.execute("PRAGMA journal_mode=WAL")
   target.close()
   source.close()
   PY
   ```

   The copy must stay a regular `0600` file owned by UID 65532 with one link; the
   container refuses anything else with `503 state unavailable`.

4. Add the registry entry and start the new master. Check that
   `GET /version` answers, that `GET /v1/reports` with the operator bearer lists
   the old reports, and that `/v1/status` shows `can_score: true`.

Keep the old `bounty.sqlite3` until the first epoch is sealed from the container.
To roll back, stop the container and start the old master on its untouched volume.
Nonces consumed and reports filed after the copy exist only in the container
database.

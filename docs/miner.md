# Bounty miner guide

Bounty accepts reproducible bug reports about the Cortex product and backend,
associated with your Bittensor hotkey. Only reports that the CortexLM/backend
public feed publishes as `valid` earn weight; see [scoring](scoring.md).

The production miner flow pairs and files reports in CortexLM/backend. The routes
below are served by this challenge container and reached through the Cortex
gateway at `https://<gateway>/challenge/bounty/`. Filing here does not publish a
report into the backend by itself.

Install the Cortex CLI from [CortexLM/cortex](https://github.com/CortexLM/cortex)
and get the gateway URL from the subnet operator.

## Check scoring availability

```bash
curl --fail-with-body "$GATEWAY/challenge/bounty/v1/status"
```

The response publishes the terms, quotas, scoring constants and `can_score`.
`can_score` reflects a recent validated feed snapshot: successes are cached for
15 seconds and failures for 5 seconds. Every report still performs its own
uncached feed check, so a report can return `503` after a successful status.

## Pair a dedicated account

Use a dedicated Cortex Chat mining account. Read these terms before passing
`--accept-terms`:

> By pairing a Bittensor hotkey to a Cortex Chat account for Bounty Challenge,
> you accept that this dedicated mining account, its logs, and its conversations
> may be used for research, to fix product and backend bugs, and to remunerate
> (or penalize) the bound miner hotkey. Do not pair a private personal account.

Ask the subnet operator to verify that you control the account and to authorize
the exact account and hotkey. The authorization is single-use and lasts at most
five minutes. Pairing without it, or after it expires, returns
`403 pairing not authorized by account operator`; ask for a new authorization
and retry with the same unspent nonce.

```bash
uv run cortex miner --gateway "$GATEWAY" \
  --wallet-name research --wallet-hotkey miner \
  bounty-pair --account-id "$CORTEX_ACCOUNT_ID" \
  --accept-terms --session-file ./bounty-session
```

For an encrypted hotkey add `--wallet-password-file /private/hotkey-password`
before `bounty-pair`. The CLI signs locally, posts to
`/challenge/bounty/v1/pair`, writes the session to a new `0600` file (it refuses
to overwrite one) and prints only `paired` and the hotkey. The session is a
secret bearer credential.

The request body is `account_id`, `hotkey` (SS58 or 64-hex), `nonce`, `exp`,
`signature` and `terms_accepted: true`. The signature covers the exact UTF-8
payload

```text
cortex-bounty-v1|{account_id}|{nonce}|{exp}
```

in sr25519's **Substrate** signing context (not the Cortex context used by Proof).
The nonce is 16 to 64 hexadecimal characters; the CLI uses 32 random ones and an
expiry five minutes ahead.

- Pairing returns `201` with the session. It consumes the authorization and the
  nonce.
- A nonce is single-use: retrying an accepted request returns `409 nonce reused`
  with no session data, also after a restart. That refusal does not consume a
  fresh authorization. If you lose the response or the session file, ask for a
  new authorization and pair with a new nonce.
- Pairing the same account again revokes its previous session, which then gets
  `401 invalid_session`. This includes an operator-authorized hotkey change.
- Sessions do not expire by age.
- The whole pairing body is limited to 4096 bytes (`413 pair request too large`).

## Submit a report

```bash
uv run cortex miner --gateway "$GATEWAY" \
  --wallet-name research --wallet-hotkey miner \
  bounty-report --session-file ./bounty-session \
  --title "Reproducible failure in the research upload path" \
  --body-file report.md --repro-file reproduction.md
```

The CLI posts `session`, `hotkey`, `title`, `body` and `repro_steps` to
`/challenge/bounty/v1/reports`. A supplied hotkey must match the paired one
(`403 hotkey_mismatch`).

| Limit | Value |
| --- | --- |
| Reports awaiting adjudication per hotkey | 5 |
| Minimum interval between reports | 60 seconds |
| Concurrent feed validations per hotkey | 1 |
| Minimum body length | 80 characters |
| Minimum reproduction length | 20 characters |
| Distinct body words of 3+ characters | 4 |
| Maximum request body | 262144 bytes |

An empty title or body, a title equal to the body, or thin content returns `400`.
A quota or a concurrent validation returns `429`, a schema error `422` and an
oversized body `413`. An unreadable or unconfigured feed returns `503` and stores
nothing.

Success returns `201` with `id`, `miner_hotkey`, `state` and `fingerprint`.
Acceptance into triage is not a reward. A report whose normalized title and body
match an earlier one is stored as `duplicate` of it and never takes a triage slot.

Report reads and adjudication are operator-only. There is no public report or
leaderboard route in this container.

# Scoring

Bounty uses scoring version 2 only. Version 1 (champion, precision, severity
impact and triage-noise gates) was retired in 1.0.0.

## Points

Each `valid` report in the pinned CortexLM/backend publication is worth one point
to its author, whatever its severity. A valid report must still carry a severity
(`trivial`, `minor`, `major` or `critical`). A publication with an unpriced valid
report cannot be scored.

| Adjudication | Points |
| --- | --- |
| `valid` with severity | 1 |
| `valid` without severity | none: the whole publication is refused |
| `already_fixed_not_prod` | 0 |
| `invalid_malicious` | 0 |
| `duplicate` | 0; the original report is counted once |

Counts cover the complete cumulative history at one immutable publication
revision. There is no epoch reset or rolling window. Local adjudications in this
container earn nothing until the backend publishes them.

## Weights

For an epoch, `GET /internal/v1/get_weights` returns every author with at least
one valid report, keyed by SS58 hotkey, with its integer count, and
`full_share_mass: 10`. The master then applies its owner policy.

Let `E` be the owner-policy participant set of the sealed metagraph, `n_i` the
count of author `i` (0 when absent), `N = sum(n_i for i in E)`, and `share` the
Bounty emission share from the owner-signed trust root. Authors outside `E`
(for example historical hotkeys no longer registered) are ignored and never
change `N`.

```text
Bounty payout   = share * min(N / 10, 1)
author i payout = share * n_i / max(10, N)
```

With a 30% share, five valid reports distribute 15% of subnet emission and ten or
more distribute 30%, proportionally across authors.

The master signs these as leaves:

| Owner algorithm | Leaf for author `i` |
| --- | --- |
| 2 | `n_i` as a raw count; the protocol applies `min(N, 10) / 10` |
| 1 or 3 | `floor(10^12 * n_i / D)` with `D = max(N, 10)`; UID0 receives `10^12 - sum(leaves)` |

## Burns

- Unused Bounty mass (`N < 10`) burns to UID0. It never moves to Proof or to
  other authors.
- An allocation to UID0 itself, or to an author without a UID, burns without
  increasing any other author.
- When `D = 0`, the whole share goes to UID0.
- When a burn is needed and UID0 is not in `E`, every leaf is
  `NoScore(ChallengeInternal)`.
- A `503` from `get_weights` (feed unreadable, inconsistent or unconfigured) makes
  the master emit `NoScore(ChallengeInternal)` for every expected hotkey, and the
  Bounty share burns for that epoch.

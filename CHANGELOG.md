# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-24

This release restarts the repository from scratch. The earlier project-bounty
platform code and SDK are gone; the repository now holds the Cortex Bounty
challenge, moved out of the Cortex master into its own container.

### Added

- Container contract 1: `GET /health` (feed readiness), `GET /version` and
  `GET /internal/v1/get_weights?epoch=`, authenticated by the internal bearer and
  the `X-Platform-Challenge-Slug` header.
- Weights are the valid-report count per SS58 hotkey with `full_share_mass: 10`.
  The first successful answer for an epoch is stored in SQLite and replayed
  byte for byte. A feed failure returns `503` and stores nothing.
- Image `ghcr.io/cortexlm/bounty` with tags `sha-<commit>`, `edge`, `vX.Y.Z` and
  `stable`, OCI and `io.cortex.challenge.*` labels, and GitHub build-provenance
  attestations.
- The container starts without any secret file or feed URL. Routes that need a
  missing secret return `503`.

### Changed

- Pairing, report intake, operator adjudication and the CortexLM/backend public
  feed reader keep their paths and behaviour. They are now served by the
  container and reached through `/challenge/bounty/` on the master.
- `bounty.sqlite3` keeps the schema of the Cortex in-process store. An existing
  database and session secret can be moved into the container unchanged.
- `/v1/status` reports `full_share_reports: 10` and no longer reports an emission
  share: the Cortex owner-signed trust root decides the share.

### Removed

- Scoring algorithm 1: the champion, precision, severity-impact and
  triage-noise gates. Scoring version 2 (one point per valid report) is the
  only scoring.
- The `/v1/status` fields `champion_hotkey` and `scoring.emission_share_bps`, and
  the `champion_verdict` field of operator report rows.

[1.0.0]: https://github.com/CortexLM/bounty/releases/tag/v1.0.0

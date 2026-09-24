"""Shared offline fixtures: a controllable clock, private secret files and a mock feed."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import sr25519

from bounty_challenge.crypto import decode_hotkey, encode_hotkey
from bounty_challenge.feed import PublicBackend
from bounty_challenge.settings import Settings

ADMIN_TOKEN = "operator-token"
INTERNAL_TOKEN = "master-token"
SESSION_SECRET = b"session-secret-for-tests" * 2


@dataclass
class Clock:
    now: int = 1_800_000_000

    def __call__(self) -> float:
        return self.now


def write_private(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.chmod(path, 0o600)
    return path


def make_settings(root: Path, *, secrets: bool = True, url: str | None = None) -> Settings:
    secret_dir = root / "secrets"
    if secrets:
        write_private(secret_dir / "internal.token", INTERNAL_TOKEN.encode() + b"\n")
        write_private(secret_dir / "admin.token", ADMIN_TOKEN.encode() + b"\n")
        write_private(secret_dir / "session.key", SESSION_SECRET)
    return Settings(
        state_dir=root / "data",
        internal_token_file=secret_dir / "internal.token",
        admin_token_file=secret_dir / "admin.token",
        session_secret_file=secret_dir / "session.key",
        backend_public_url=url,
    )


def published_report(report_id: str = "r1", **changes: Any) -> dict[str, Any]:
    return {
        "id": report_id,
        "hotkey": "ab" * 32,
        "status": "valid",
        "severity": "critical",
        "problem_found": "Unauthorized configuration change",
        "adjudicator": "operator",
        "justification": "Reproduced from an unauthenticated client",
        "created_at": "2026-09-16T00:00:00Z",
        "adjudicated_at": "2026-09-16T01:00:00Z",
        **changes,
    }


def feed_body(
    route: str,
    leaderboard: list[dict[str, Any]],
    reports: list[dict[str, Any]],
    *,
    revision: str = "1",
) -> dict[str, Any]:
    if route == "status":
        return {
            "api_version": 1,
            "revision": revision,
            "adjudication_available": True,
            "published": len(reports),
            "valid": sum(row["status"] == "valid" for row in reports),
            "duplicate": sum(row["status"] == "duplicate" for row in reports),
            "already_fixed_not_prod": sum(
                row["status"] == "already_fixed_not_prod" for row in reports
            ),
            "invalid_malicious": sum(row["status"] == "invalid_malicious" for row in reports),
            "hotkeys": len({row["hotkey"] for row in reports}),
            "awaiting_adjudication": 0,
            "unpriced_valid": 0,
        }
    if route == "leaderboard":
        return {"api_version": 1, "revision": revision, "items": leaderboard, "has_more": False}
    return {
        "api_version": 1,
        "revision": revision,
        "items": reports,
        "count": len(reports),
        "has_more": False,
        "next_cursor": None,
    }


@dataclass
class Upstream:
    """A mutable CortexLM/backend publication served through httpx.MockTransport."""

    status: int = 200
    revision: str = "1"
    leaderboard: list[dict[str, Any]] = field(default_factory=list)
    reports: list[dict[str, Any]] = field(default_factory=list)
    requests: int = 0

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if self.status != 200:
            return httpx.Response(self.status)
        route = request.url.path.rsplit("/", 1)[-1]
        body = feed_body(route, self.leaderboard, self.reports, revision=self.revision)
        return httpx.Response(200, json=body)

    def backend(self) -> PublicBackend:
        backend = PublicBackend(
            "https://backend.invalid", transport=httpx.MockTransport(self.handle)
        )
        backend._SNAPSHOT_RETRY_DELAY_SECONDS = 0
        # Tests mutate the publication between calls; never serve a cached probe.
        backend._PROBE_SUCCESS_TTL_SECONDS = 0
        backend._PROBE_FAILURE_TTL_SECONDS = 0
        return backend

    def publish(self, hotkey: str, count: int, *, prefix: str = "r") -> None:
        for index in range(count):
            self.reports.append(published_report(f"{prefix}{index}", hotkey=hotkey))
        self.leaderboard = _leaderboard(self.reports)


def _leaderboard(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for report in reports:
        if report["status"] == "valid":
            counts[report["hotkey"]] = counts.get(report["hotkey"], 0) + 1
    ranked = sorted(
        counts.items(), key=lambda item: (-item[1], encode_hotkey(decode_hotkey(item[0])))
    )
    return [{"hotkey": hotkey, "valid_count": count} for hotkey, count in ranked]


def signed_pair(
    account: str = "account-a", nonce: str = "12" * 16, *, seed_byte: int = 7
) -> dict[str, Any]:
    public, secret = sr25519.pair_from_seed(bytes([seed_byte]) * 32)
    expiry = 1_800_000_900
    challenge = f"cortex-bounty-v1|{account}|{nonce}|{expiry}".encode()
    return {
        "account_id": account,
        "hotkey": public.hex(),
        "nonce": nonce,
        "exp": expiry,
        "signature": sr25519.sign((public, secret), challenge).hex(),
        "terms_accepted": True,
    }


def report_body(session: str, number: int = 0) -> dict[str, Any]:
    return {
        "session": session,
        "title": f"Gateway accepts unauthorized request {number}",
        "body": f"Request {number} to the operator endpoint succeeds without credentials. "
        "An anonymous caller can change the backend configuration "
        "and invalidate the current bundle.",
        "repro_steps": "Call the operator endpoint without an Authorization header.",
    }


OPERATOR = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
MASTER = {"Authorization": f"Bearer {INTERNAL_TOKEN}", "X-Platform-Challenge-Slug": "bounty"}

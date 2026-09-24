"""Pairing, intake and weight answers; the external feed gates every report and weight."""

import asyncio
import hashlib
import hmac
import json
import re
import sqlite3
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from . import SLUG
from .crypto import decode_hotkey, verify_substrate
from .feed import BackendUnavailable, PublicSnapshot
from .settings import Settings, read_session_secret, read_token
from .store import BountyStore, Row, ServiceError, normalize_text

TERMS_TEXT = (
    "By pairing a Bittensor hotkey to a Cortex Chat account for Bounty Challenge, you accept "
    "that this dedicated mining account, its logs, and its conversations may be used for research, "
    "to fix product and backend bugs, and to remunerate (or penalize) the bound miner hotkey. "
    "Do not pair a private personal account."
)
PAIR_GRANT_MAX_TTL_SECONDS = 300
FULL_SHARE_REPORTS = 10
MAX_WEIGHT_ENTRIES = 65_536
MAX_PENDING_REPORTS = 5
MIN_REPORT_INTERVAL_SECONDS = 60
MIN_BODY_CHARS = 80
MIN_REPRO_CHARS = 20
_ACCOUNT_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,128}")


class Feed(Protocol):
    @property
    def configured(self) -> bool: ...

    async def probe(self) -> PublicSnapshot: ...

    async def fetch(self) -> PublicSnapshot: ...


class PairRequest(Protocol):
    account_id: str
    hotkey: str
    nonce: str
    exp: int
    signature: str
    terms_accepted: bool


class GrantRequest(Protocol):
    account_id: str
    hotkey: str
    expires_at: int


class ReportRequest(Protocol):
    session: str
    hotkey: str | None
    title: str
    body: str
    repro_steps: str | None


def validate_account_id(account: str) -> None:
    if not _ACCOUNT_ID_PATTERN.fullmatch(account):
        raise ServiceError(400, "invalid account_id")


def pair_payload(account: str, nonce: str, expiry: int) -> bytes:
    validate_account_id(account)
    if not re.fullmatch(r"[a-fA-F0-9]{16,64}", nonce):
        raise ServiceError(400, "invalid nonce")
    if not 0 < expiry <= 2**64 - 1:
        raise ServiceError(400, "invalid or expired pairing window")
    return f"cortex-bounty-v1|{account}|{nonce}|{expiry}".encode()


def validate_substance(title: str, body: str, repro: str) -> None:
    if not title.strip() or not body.strip():
        raise ServiceError(400, "title_and_body_required")
    if normalize_text(title) == normalize_text(body):
        raise ServiceError(400, "title_and_body_must_differ")
    if len(body.strip()) < MIN_BODY_CHARS:
        raise ServiceError(400, f"body must be at least {MIN_BODY_CHARS} characters")
    if len(repro.strip()) < MIN_REPRO_CHARS:
        raise ServiceError(400, f"repro_steps must be at least {MIN_REPRO_CHARS} characters")
    if len({token for token in normalize_text(body).split() if len(token) >= 3}) < 4:
        raise ServiceError(400, "body_lacks_distinct_evidence")


def _bearer_matches(authorization: str | None, expected: str) -> bool:
    if not authorization or not authorization.startswith("Bearer "):
        return False
    supplied = authorization[7:].strip()
    # Equal-length digests keep the comparison constant-time for any input length.
    return bool(supplied) and hmac.compare_digest(
        hashlib.sha256(supplied.encode()).digest(), hashlib.sha256(expected.encode()).digest()
    )


class BountyService:
    def __init__(
        self,
        settings: Settings,
        backend: Feed,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings, self.backend, self.clock = settings, backend, clock
        self._store: BountyStore | None = None
        self._store_lock = threading.Lock()
        self._submission_locks: dict[str, asyncio.Lock] = {}

    @property
    def store(self) -> BountyStore:
        """Open state on first use, so /version answers even when /data is unusable."""
        with self._store_lock:
            if self._store is None:
                try:
                    self._store = BountyStore(self.settings.state_dir / "bounty.sqlite3")
                except (OSError, RuntimeError, sqlite3.Error):
                    raise ServiceError(503, "state unavailable") from None
            return self._store

    def close(self) -> None:
        with self._store_lock:
            if self._store is not None:
                self._store.close()
                self._store = None

    def require_operator(self, authorization: str | None) -> None:
        if not _bearer_matches(authorization, read_token(self.settings.admin_token_file)):
            raise ServiceError(401, "unauthorized")

    def require_master(self, authorization: str | None, slug: str | None) -> None:
        if not _bearer_matches(authorization, read_token(self.settings.internal_token_file)):
            raise ServiceError(401, "unauthorized")
        if slug != SLUG:
            raise ServiceError(403, "challenge slug mismatch")

    def pair(self, body: PairRequest) -> Row:
        if not body.terms_accepted:
            raise ServiceError(403, "terms_required")
        payload = pair_payload(body.account_id, body.nonce, body.exp)
        now = int(self.clock())
        if now >= body.exp:
            raise ServiceError(400, "invalid or expired pairing window")
        try:
            hotkey = decode_hotkey(body.hotkey)
            signature = bytes.fromhex(body.signature.removeprefix("0x"))
        except ValueError:
            raise ServiceError(400, "invalid hotkey or signature") from None
        if len(signature) != 64:
            raise ServiceError(400, "invalid signature")
        if not verify_substrate(hotkey, payload, signature):
            raise ServiceError(401, "signature verification failed")
        secret = read_session_secret(self.settings.session_secret_file)
        return self.store.bind_pair(body.account_id, hotkey.hex(), body.nonce, now, secret)

    def grant_pair(self, body: GrantRequest) -> Row:
        validate_account_id(body.account_id)
        now = int(self.clock())
        if body.expires_at <= now:
            raise ServiceError(400, "pair grant must expire in the future")
        if body.expires_at > now + PAIR_GRANT_MAX_TTL_SECONDS:
            raise ServiceError(
                400, f"pair grant must expire within {PAIR_GRANT_MAX_TTL_SECONDS} seconds"
            )
        try:
            hotkey = decode_hotkey(body.hotkey).hex()
        except ValueError:
            raise ServiceError(400, "invalid hotkey") from None
        return self.store.grant_pair(body.account_id, hotkey, expires_at=body.expires_at, now=now)

    async def submit(self, body: ReportRequest) -> Row:
        if not self.backend.configured:
            raise ServiceError(503, "scoring unconfigured: set BOUNTY_BACKEND_PUBLIC_URL")
        secret = read_session_secret(self.settings.session_secret_file)
        pairing = self.store.lookup_session(body.session, secret)
        if body.hotkey:
            try:
                claimed = decode_hotkey(body.hotkey).hex()
            except ValueError:
                raise ServiceError(400, "invalid hotkey") from None
            if claimed != pairing["miner_hotkey"]:
                raise ServiceError(403, "hotkey_mismatch")
        repro = body.repro_steps or ""
        validate_substance(body.title, body.body, repro)
        hotkey = pairing["miner_hotkey"]
        lock = self._submission_locks.setdefault(hotkey, asyncio.Lock())
        if lock.locked():
            raise ServiceError(429, "report validation already in progress for this hotkey")
        async with lock:
            self.store.check_report_admission(pairing, int(self.clock()))
            try:
                await self.backend.fetch()
            except BackendUnavailable as error:
                raise ServiceError(503, str(error)) from None
            # A re-pairing during the feed read revokes this session before insert.
            pairing = self.store.lookup_session(body.session, secret)
            return self.store.insert_report(
                pairing, body.title, body.body, repro, int(self.clock())
            )

    async def weights(self, epoch: int) -> bytes:
        """The persisted answer for an epoch, else one computed from a fresh snapshot."""
        stored = self.store.epoch_weights(epoch)
        if stored is not None:
            return stored
        try:
            snapshot = await self.backend.fetch()
            counts = snapshot.valid_counts()
        except BackendUnavailable as error:
            raise ServiceError(503, str(error)) from None
        if len(counts) > MAX_WEIGHT_ENTRIES:
            raise ServiceError(503, "too many valid authors for one weight answer")
        answer = {
            "challenge_slug": SLUG,
            "epoch": epoch,
            "weights": counts,
            "full_share_mass": FULL_SHARE_REPORTS,
            "metadata": {
                "revision": snapshot.revision,
                "published": len(snapshot.reports),
                "valid": sum(counts.values()),
            },
            "computed_at": datetime.fromtimestamp(int(self.clock()), UTC)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        encoded = json.dumps(answer, separators=(",", ":")).encode()
        return self.store.save_epoch_weights(epoch, encoded)

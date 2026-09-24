"""Read the external CortexLM/backend public feed; never substitute local adjudications."""

import asyncio
from collections import Counter
from time import monotonic
from typing import Annotated, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError, model_validator

from .crypto import decode_hotkey, encode_hotkey

Severity = Literal["trivial", "minor", "major", "critical"]
Verdict = Literal["valid", "invalid_malicious", "duplicate", "already_fixed_not_prod"]


def _canonical_revision(value: str) -> str:
    if (
        not value
        or any(character not in "0123456789" for character in value)
        or (len(value) > 1 and value.startswith("0"))
        or len(value) > 19
        or int(value) > 2**63 - 1
    ):
        raise ValueError("revision must be a canonical non-negative i64")
    return value


Revision = Annotated[str, AfterValidator(_canonical_revision)]


class BackendUnavailable(Exception):
    """A public scoring snapshot cannot be trusted. Carries no upstream body."""


class _RetryableBackendUnavailable(BackendUnavailable):
    """A read-only snapshot attempt may succeed against the next rollout replica."""


class FeedModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)


class LeaderboardRow(FeedModel):
    hotkey: str
    valid_count: int = Field(ge=0, le=2**64 - 1)
    weight: int | None = Field(default=None, ge=0, le=2**64 - 1)

    @model_validator(mode="before")
    @classmethod
    def normalize_valid_count(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        if "valid_count" in value and "valid" in value and value["valid_count"] != value["valid"]:
            raise ValueError("leaderboard valid counters disagree")
        if "valid_count" not in value and "valid" in value:
            return {**value, "valid_count": value["valid"]}
        return value


class PublicReport(FeedModel):
    id: str = Field(min_length=1)
    hotkey: str
    status: Verdict
    problem_found: str
    adjudicator: str
    justification: str
    severity: Severity | None = None
    adjudicated_at: str
    created_at: str
    related_report_id: str | None = None


class PublicationStatus(FeedModel):
    api_version: Literal[1]
    revision: Revision
    adjudication_available: bool
    published: int = Field(ge=0, le=2**63 - 1)
    valid: int = Field(ge=0, le=2**63 - 1)
    duplicate: int = Field(ge=0, le=2**63 - 1)
    already_fixed_not_prod: int = Field(ge=0, le=2**63 - 1)
    invalid_malicious: int = Field(ge=0, le=2**63 - 1)
    hotkeys: int = Field(ge=0, le=2**63 - 1)
    awaiting_adjudication: int = Field(ge=0, le=2**63 - 1)
    unpriced_valid: int = Field(ge=0, le=2**63 - 1)


class LeaderboardPage(FeedModel):
    api_version: Literal[1]
    revision: Revision
    items: tuple[LeaderboardRow, ...]
    has_more: bool


class ReportPage(FeedModel):
    api_version: Literal[1]
    revision: Revision
    items: tuple[PublicReport, ...]
    count: int = Field(ge=0, le=100)
    has_more: bool
    next_cursor: str | None = Field(default=None, min_length=1, max_length=1024)


def _canonical(hotkey: str) -> str:
    try:
        return encode_hotkey(decode_hotkey(hotkey))
    except ValueError:
        raise BackendUnavailable("backend public invalid hotkey") from None


class PublicSnapshot(FeedModel):
    """One fully paginated publication at one revision."""

    revision: str
    leaderboard: tuple[LeaderboardRow, ...]
    reports: tuple[PublicReport, ...]

    @staticmethod
    def leaderboard_from_reports(reports: tuple[PublicReport, ...]) -> tuple[LeaderboardRow, ...]:
        valid: Counter[str] = Counter()
        authors = set()
        for report in reports:
            hotkey = _canonical(report.hotkey)
            authors.add(hotkey)
            if report.status == "valid":
                valid[hotkey] += 1
        return tuple(
            LeaderboardRow(hotkey=hotkey, valid_count=valid[hotkey])
            for hotkey in sorted(authors, key=lambda item: (-valid[item], item))
        )

    @staticmethod
    def validate_leaderboard_page(
        page: LeaderboardPage, complete: tuple[LeaderboardRow, ...]
    ) -> None:
        published = tuple((_canonical(row.hotkey), row.valid_count) for row in page.items)
        if len({hotkey for hotkey, _ in published}) != len(published):
            raise BackendUnavailable("backend public duplicate leaderboard hotkey")
        expected = tuple((row.hotkey, row.valid_count) for row in complete)
        if page.has_more:
            if (
                not published
                or len(published) >= len(expected)
                or published != expected[: len(published)]
            ):
                raise BackendUnavailable("backend public truncated leaderboard is inconsistent")
            return
        listed = {hotkey for hotkey, _ in published}
        if any(
            count > 0 and hotkey not in listed for hotkey, count in expected
        ) or published != tuple(row for row in expected if row[0] in listed):
            raise BackendUnavailable("backend public leaderboard and reports do not agree")

    def validate_publication(self) -> None:
        """A stable pair of responses can still be two permanently different revisions."""
        authors = [_canonical(report.hotkey) for report in self.reports]
        valid_counts = Counter(
            author
            for author, report in zip(authors, self.reports, strict=True)
            if report.status == "valid"
        )
        leaderboard = {_canonical(row.hotkey): row.valid_count for row in self.leaderboard}
        if len(leaderboard) != len(self.leaderboard):
            raise BackendUnavailable("backend public duplicate leaderboard hotkey")
        report_ids = {row.id for row in self.reports}
        if len(report_ids) != len(self.reports):
            raise BackendUnavailable("backend public duplicate report id")
        if any(
            not report.problem_found.strip()
            or not report.justification.strip()
            or not report.adjudicator.strip()
            for report in self.reports
        ):
            raise BackendUnavailable("backend public report evidence is incomplete")
        if any(
            (report.status == "valid") != (report.severity is not None) for report in self.reports
        ):
            raise BackendUnavailable("backend public report severity is inconsistent")
        if any(
            (report.status == "duplicate") != (report.related_report_id is not None)
            or report.related_report_id == report.id
            or (report.related_report_id is not None and report.related_report_id not in report_ids)
            for report in self.reports
        ):
            raise BackendUnavailable("backend public duplicate reference is invalid")
        by_id = {report.id: report for report in self.reports}
        rooted = {report.id for report in self.reports if report.status != "duplicate"}
        for report in self.reports:
            path: dict[str, None] = {}
            current = report
            while current.id not in rooted:
                if current.id in path:
                    raise BackendUnavailable(
                        "backend public duplicate chain has no non-duplicate root"
                    )
                path[current.id] = None
                current = by_id[current.related_report_id or ""]
            rooted.update(path)
        if any(leaderboard.get(k) != n for k, n in valid_counts.items()) or any(
            valid_counts.get(k, 0) != n for k, n in leaderboard.items()
        ):
            raise BackendUnavailable("backend public leaderboard and reports do not agree")

    def validate_status(self, status: PublicationStatus) -> None:
        counts: Counter[str] = Counter(report.status for report in self.reports)
        expected = {
            "valid": status.valid,
            "duplicate": status.duplicate,
            "already_fixed_not_prod": status.already_fixed_not_prod,
            "invalid_malicious": status.invalid_malicious,
        }
        if status.published != len(self.reports) or any(
            counts.get(verdict, 0) != count for verdict, count in expected.items()
        ):
            raise BackendUnavailable("backend public status and reports do not agree")
        if status.hotkeys != len({_canonical(report.hotkey) for report in self.reports}):
            raise BackendUnavailable("backend public status hotkey count does not agree")

    def valid_counts(self) -> dict[str, int]:
        """Scoring version 2: one point per valid report, keyed by canonical SS58."""
        self.validate_publication()
        counts = Counter(_canonical(r.hotkey) for r in self.reports if r.status == "valid")
        return dict(sorted(counts.items()))


class PublicBackend:
    """Read one immutable, fully paginated CortexLM/backend publication."""

    _MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    _MAX_REPORT_BYTES = 64 * 1024 * 1024
    _MAX_REPORT_PAGES = 10_000
    _SNAPSHOT_TIMEOUT_SECONDS = 30.0
    _SNAPSHOT_ATTEMPTS = 3
    _SNAPSHOT_RETRY_DELAY_SECONDS = 0.25
    _PROBE_SUCCESS_TTL_SECONDS = 15.0
    _PROBE_FAILURE_TTL_SECONDS = 5.0

    def __init__(
        self, base_url: str | None, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.base_url = (base_url or "").strip().rstrip("/")
        # A malformed URL fails closed at read time so /version stays live.
        self.config_error: str | None = None
        if self.base_url:
            parsed = urlsplit(self.base_url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                self.config_error = "backend public URL must be HTTPS without credentials or query"
        self.transport = transport
        self._probe_lock = asyncio.Lock()
        self._probe_snapshot: PublicSnapshot | None = None
        self._probe_success_until = 0.0
        self._probe_error: str | None = None
        self._probe_failure_until = 0.0

    @property
    def configured(self) -> bool:
        return bool(self.base_url) and self.config_error is None

    async def probe(self) -> PublicSnapshot:
        """Bound anonymous health probes without weakening intake or weight freshness."""
        now = monotonic()
        if self._probe_snapshot is not None and now < self._probe_success_until:
            return self._probe_snapshot
        if self._probe_error is not None and now < self._probe_failure_until:
            raise BackendUnavailable(self._probe_error)
        if self._probe_lock.locked():
            raise BackendUnavailable("backend public probe refresh already in progress")
        async with self._probe_lock:
            try:
                snapshot = await self.fetch()
            except BackendUnavailable as error:
                self._probe_snapshot = None
                self._probe_error = str(error)
                self._probe_failure_until = monotonic() + self._PROBE_FAILURE_TTL_SECONDS
                raise
            self._probe_snapshot = snapshot
            self._probe_success_until = monotonic() + self._PROBE_SUCCESS_TTL_SECONDS
            self._probe_error = None
            return snapshot

    async def fetch(self) -> PublicSnapshot:
        """An uncached, fully validated snapshot, or BackendUnavailable."""
        if not self.base_url:
            raise BackendUnavailable("scoring unconfigured: set BOUNTY_BACKEND_PUBLIC_URL")
        if self.config_error is not None:
            raise BackendUnavailable(self.config_error)
        try:
            async with asyncio.timeout(self._SNAPSHOT_TIMEOUT_SECONDS):
                last_error = BackendUnavailable("backend public snapshot attempt unavailable")
                for attempt in range(self._SNAPSHOT_ATTEMPTS):
                    if attempt:
                        await asyncio.sleep(self._SNAPSHOT_RETRY_DELAY_SECONDS * attempt)
                    try:
                        async with httpx.AsyncClient(
                            timeout=20,
                            transport=self.transport,
                            follow_redirects=False,
                            trust_env=False,
                            headers={"User-Agent": "cortex-bounty-challenge"},
                        ) as client:
                            return await self._fetch_once(client)
                    except _RetryableBackendUnavailable as error:
                        last_error = error
                    except (httpx.HTTPError, ValueError, ValidationError):
                        last_error = _RetryableBackendUnavailable(
                            "backend public fetch or JSON validation failed"
                        )
                raise last_error
        except TimeoutError:
            raise BackendUnavailable("backend public snapshot deadline exceeded") from None

    async def _fetch_once(self, client: httpx.AsyncClient) -> PublicSnapshot:
        status, _ = await self._read_model(client, "status", PublicationStatus)
        if not status.adjudication_available:
            raise BackendUnavailable("backend public adjudication is unavailable")
        if status.unpriced_valid:
            raise BackendUnavailable("backend public feed has unpriced valid reports")
        if status.awaiting_adjudication and not status.published:
            raise BackendUnavailable("backend public adjudication backlog has no published reports")
        leaderboard, _ = await self._read_model(
            client, "leaderboard", LeaderboardPage, params={"revision": status.revision}
        )
        if leaderboard.revision != status.revision:
            raise _RetryableBackendUnavailable("backend public leaderboard revision changed")
        reports = await self._read_reports(client, status.revision)
        complete = PublicSnapshot.leaderboard_from_reports(reports)
        snapshot = PublicSnapshot(revision=status.revision, leaderboard=complete, reports=reports)
        snapshot.validate_publication()
        PublicSnapshot.validate_leaderboard_page(leaderboard, complete)
        snapshot.validate_status(status)
        return snapshot

    async def _read_reports(
        self, client: httpx.AsyncClient, revision: str
    ) -> tuple[PublicReport, ...]:
        reports: list[PublicReport] = []
        cursor = None
        seen_cursors = set()
        total_bytes = 0
        for _ in range(self._MAX_REPORT_PAGES):
            params = {"limit": "100", "revision": revision}
            if cursor is not None:
                params["cursor"] = cursor
            page, size = await self._read_model(client, "reports", ReportPage, params=params)
            total_bytes += size
            if total_bytes > self._MAX_REPORT_BYTES:
                raise BackendUnavailable("backend public report snapshot is too large")
            if page.revision != revision:
                raise _RetryableBackendUnavailable("backend public report revision changed")
            if page.count != len(page.items):
                raise BackendUnavailable("backend public report page count is invalid")
            reports.extend(page.items)
            if not page.has_more:
                if page.next_cursor is not None:
                    raise BackendUnavailable("backend public terminal page has a cursor")
                return tuple(reports)
            if not page.items or page.next_cursor is None or page.next_cursor in seen_cursors:
                raise BackendUnavailable("backend public report pagination is invalid")
            seen_cursors.add(page.next_cursor)
            cursor = page.next_cursor
        raise BackendUnavailable("backend public report pagination exceeded the page limit")

    async def _read_model[Model: FeedModel](
        self,
        client: httpx.AsyncClient,
        route: str,
        model: type[Model],
        *,
        params: dict[str, str] | None = None,
    ) -> tuple[Model, int]:
        async with client.stream(
            "GET", f"{self.base_url}/v1/bounty/public/{route}", params=params
        ) as response:
            if not 200 <= response.status_code < 300:
                error = f"backend public fetch failed: HTTP {response.status_code}"
                if response.status_code in {404, 408, 409, 425, 429} or response.status_code >= 500:
                    raise _RetryableBackendUnavailable(error)
                raise BackendUnavailable(error)
            content = bytearray()
            async for part in response.aiter_bytes():
                if len(content) + len(part) > self._MAX_RESPONSE_BYTES:
                    raise BackendUnavailable("backend public response too large")
                content.extend(part)
            return model.model_validate_json(content), len(content)

"""HTTP surface: contract routes, public miner routes and operator routes."""

import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import SLUG, __version__
from .feed import BackendUnavailable, PublicBackend, Severity, Verdict
from .service import (
    FULL_SHARE_REPORTS,
    MAX_PENDING_REPORTS,
    MIN_BODY_CHARS,
    MIN_REPORT_INTERVAL_SECONDS,
    MIN_REPRO_CHARS,
    PAIR_GRANT_MAX_TTL_SECONDS,
    TERMS_TEXT,
    BountyService,
    Feed,
)
from .settings import Settings
from .store import Row, ServiceError

SMALL_WRITE_MAX_BODY_BYTES = 4096
REPORT_MAX_BODY_BYTES = 256 * 1024
SEVERITIES = ("trivial", "minor", "major", "critical")


class RequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PairBody(RequestBody):
    account_id: str = Field(max_length=128)
    hotkey: str = Field(max_length=128)
    nonce: str = Field(max_length=64)
    exp: int
    signature: str = Field(max_length=130)
    terms_accepted: bool


class PairGrantBody(RequestBody):
    account_id: str = Field(max_length=128)
    hotkey: str = Field(max_length=128)
    expires_at: int


class ReportBody(RequestBody):
    session: str = Field(max_length=128)
    hotkey: str | None = Field(default=None, max_length=128)
    title: str = Field(max_length=512)
    body: str = Field(max_length=100_000)
    repro_steps: str | None = Field(default=None, max_length=100_000)


class AdjudicateBody(RequestBody):
    report_id: str = Field(max_length=128)
    verdict: Verdict
    severity: Severity | None = None
    duplicate_of: str | None = Field(default=None, max_length=128)


def _request_openapi(model: type[RequestBody]) -> dict[str, Any]:
    return {
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": model.model_json_schema()}},
        }
    }


async def _read_request[Model: RequestBody](
    request: Request, model: type[Model], *, limit: int, label: str
) -> Model:
    """Stop reading at the limit: 413 comes before any parsing, signature or feed work."""
    encoded = bytearray()
    async for chunk in request.stream():
        if len(encoded) + len(chunk) > limit:
            raise ServiceError(413, f"{label} request too large")
        encoded.extend(chunk)
    try:
        return model.model_validate_json(bytes(encoded))
    except ValidationError:
        raise ServiceError(422, f"invalid {label} request") from None


def _epoch(raw: str | None) -> int:
    if raw is None or not raw.isascii() or not raw.isdigit() or (len(raw) > 1 and raw[0] == "0"):
        raise ServiceError(400, "epoch must be a canonical u64")
    epoch = int(raw)
    if epoch > 2**64 - 1:
        raise ServiceError(400, "epoch must be a canonical u64")
    return epoch


def create_app(
    settings: Settings,
    *,
    backend: Feed | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    service = BountyService(
        settings, backend or PublicBackend(settings.backend_public_url), clock=clock
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        service.close()

    app = FastAPI(
        title="Cortex Bounty challenge",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.service = service

    @app.exception_handler(ServiceError)
    async def service_error(_: Request, error: ServiceError) -> JSONResponse:
        return JSONResponse({"error": error.reason}, status_code=error.status)

    async def probe() -> str | None:
        try:
            await service.backend.probe()
        except BackendUnavailable as error:
            return str(error)
        return None

    @app.get("/health")
    async def health() -> JSONResponse:
        reason = await probe()
        if reason is None:
            try:
                _ = service.store
            except ServiceError as error:
                reason = error.reason
        if reason is not None:
            return JSONResponse({"ok": False, "reason": reason}, status_code=503)
        return JSONResponse({"ok": True})

    @app.get("/version")
    async def version() -> dict[str, Any]:
        return {
            "slug": SLUG,
            "version": __version__,
            "contract": 1,
            "capabilities": ["get_weights", "proxy_routes"],
        }

    @app.get("/internal/v1/get_weights")
    async def get_weights(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
        x_platform_challenge_slug: Annotated[str | None, Header()] = None,
    ) -> Response:
        service.require_master(authorization, x_platform_challenge_slug)
        epoch = _epoch(request.query_params.get("epoch"))
        return Response(await service.weights(epoch), media_type="application/json")

    @app.get("/v1/status")
    async def status() -> dict[str, Any]:
        reason = await probe()
        return {
            "challenge_id": SLUG,
            "scoring_version": 2,
            "score_max": 2**64 - 1,
            "scoring_backend": "backend_public" if service.backend.configured else "unconfigured",
            "can_score": reason is None,
            "reason": reason,
            "backend_public_configured": service.backend.configured,
            "pairing": {
                "requires_operator_grant": True,
                "grant_max_ttl_secs": PAIR_GRANT_MAX_TTL_SECONDS,
            },
            "scoring": {
                "paid_on": ["valid_report_count"],
                "points_per_valid_report": 1,
                "full_share_reports": FULL_SHARE_REPORTS,
                "population": "expected_metagraph_hotkeys",
                "window": "cumulative_published_history",
                "off_score_gates": [],
                "severities": list(SEVERITIES),
            },
            "quotas": {
                "max_pending_reports_per_hotkey": MAX_PENDING_REPORTS,
                "max_concurrent_feed_validations_per_hotkey": 1,
                "min_report_interval_secs": MIN_REPORT_INTERVAL_SECONDS,
                "min_report_body_chars": MIN_BODY_CHARS,
                "min_repro_chars": MIN_REPRO_CHARS,
                "max_report_request_bytes": REPORT_MAX_BODY_BYTES,
            },
            "terms": TERMS_TEXT,
        }

    @app.post("/v1/pair", status_code=201, openapi_extra=_request_openapi(PairBody))
    async def pair(request: Request) -> Row:
        body = await _read_request(
            request, PairBody, limit=SMALL_WRITE_MAX_BODY_BYTES, label="pair"
        )
        return service.pair(body)

    @app.post(
        "/v1/admin/pair-grants", status_code=201, openapi_extra=_request_openapi(PairGrantBody)
    )
    async def grant_pair(
        request: Request, authorization: Annotated[str | None, Header()] = None
    ) -> Row:
        service.require_operator(authorization)
        body = await _read_request(
            request, PairGrantBody, limit=SMALL_WRITE_MAX_BODY_BYTES, label="pair grant"
        )
        return service.grant_pair(body)

    @app.post("/v1/reports", status_code=201, openapi_extra=_request_openapi(ReportBody))
    async def submit(request: Request) -> Row:
        body = await _read_request(request, ReportBody, limit=REPORT_MAX_BODY_BYTES, label="report")
        row = await service.submit(body)
        return {key: row[key] for key in ("id", "miner_hotkey", "state", "fingerprint")}

    @app.get("/v1/reports")
    async def list_reports(authorization: Annotated[str | None, Header()] = None) -> Row:
        service.require_operator(authorization)
        return {"items": service.store.list_reports()}

    @app.get("/v1/reports/{report_id}")
    async def get_report(
        report_id: str, authorization: Annotated[str | None, Header()] = None
    ) -> Row:
        service.require_operator(authorization)
        return service.store.get_report(report_id)

    @app.post("/v1/admin/adjudicate", openapi_extra=_request_openapi(AdjudicateBody))
    async def adjudicate(
        request: Request, authorization: Annotated[str | None, Header()] = None
    ) -> Row:
        service.require_operator(authorization)
        body = await _read_request(
            request, AdjudicateBody, limit=SMALL_WRITE_MAX_BODY_BYTES, label="adjudication"
        )
        return service.store.adjudicate(
            body.report_id, body.verdict, body.severity, body.duplicate_of
        )

    return app

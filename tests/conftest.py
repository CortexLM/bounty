from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from support import Clock, Upstream, make_settings

from bounty_challenge.app import create_app
from bounty_challenge.service import BountyService
from bounty_challenge.settings import Settings


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def upstream() -> Upstream:
    return Upstream()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path, url="https://backend.invalid")


@pytest.fixture
def app(settings: Settings, upstream: Upstream, clock: Clock) -> FastAPI:
    return create_app(settings, backend=upstream.backend(), clock=clock)


@pytest.fixture
def svc(app: FastAPI) -> Iterator[BountyService]:
    service: BountyService = app.state.service
    yield service
    service.close()


@pytest.fixture
async def client(app: FastAPI, svc: BountyService) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client

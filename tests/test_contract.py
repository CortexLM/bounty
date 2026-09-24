"""Container contract v1: /health, /version, /internal/v1/get_weights, secretless canary."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from support import INTERNAL_TOKEN, MASTER, make_settings

from bounty_challenge import __version__
from bounty_challenge.app import create_app
from bounty_challenge.crypto import decode_hotkey, encode_hotkey
from bounty_challenge.settings import Settings

AUTHOR = "ab" * 32
OTHER = "cd" * 32


def ss58(hotkey: str) -> str:
    return encode_hotkey(decode_hotkey(hotkey))


async def test_version_reports_slug_contract_and_capabilities(client):
    response = await client.get("/version")

    assert response.status_code == 200
    assert response.json() == {
        "slug": "bounty",
        "version": __version__,
        "contract": 1,
        "capabilities": ["get_weights", "proxy_routes"],
    }


async def test_health_is_200_only_when_the_feed_probe_succeeds(client, upstream):
    healthy = await client.get("/health")
    upstream.status = 503
    unhealthy = await client.get("/health")

    assert healthy.status_code == 200 and healthy.json() == {"ok": True}
    assert unhealthy.status_code == 503
    assert unhealthy.json() == {"ok": False, "reason": "backend public fetch failed: HTTP 503"}


async def test_secretless_canary_answers_version_and_fails_closed(tmp_path):
    """No secret files, no feed URL: the process serves, dependent routes return 503."""
    settings = make_settings(tmp_path, secrets=False)
    app = create_app(settings)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        version = await client.get("/version")
        health = await client.get("/health")
        weights = await client.get("/internal/v1/get_weights?epoch=1", headers=MASTER)
        reports = await client.get("/v1/reports", headers={"Authorization": "Bearer x"})
        status = await client.get("/v1/status")
    app.state.service.close()

    assert version.status_code == 200
    assert health.status_code == 503
    assert health.json()["reason"] == "scoring unconfigured: set BOUNTY_BACKEND_PUBLIC_URL"
    assert weights.status_code == 503 and weights.json() == {"error": "auth_unconfigured"}
    assert reports.status_code == 503 and reports.json() == {"error": "auth_unconfigured"}
    assert status.json()["scoring_backend"] == "unconfigured"
    assert status.json()["can_score"] is False


async def test_unusable_state_directory_does_not_break_version(tmp_path, upstream):
    blocker = tmp_path / "file"
    blocker.write_text("")
    settings = make_settings(tmp_path, url="https://backend.invalid")
    settings = Settings(**{**settings.__dict__, "state_dir": blocker})
    app = create_app(settings, backend=upstream.backend())

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        version = await client.get("/version")
        health = await client.get("/health")
        weights = await client.get("/internal/v1/get_weights?epoch=1", headers=MASTER)

    assert version.status_code == 200
    assert health.status_code == 503 and health.json()["reason"] == "state unavailable"
    assert weights.status_code == 503 and weights.json() == {"error": "state unavailable"}


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong", "X-Platform-Challenge-Slug": "bounty"},
        {"Authorization": INTERNAL_TOKEN, "X-Platform-Challenge-Slug": "bounty"},
        {"Authorization": "Bearer ", "X-Platform-Challenge-Slug": "bounty"},
        {"Authorization": "Bearer operator-token", "X-Platform-Challenge-Slug": "bounty"},
    ],
)
async def test_get_weights_requires_the_internal_bearer(client, upstream, headers):
    response = await client.get("/internal/v1/get_weights?epoch=1", headers=headers)

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}
    assert upstream.requests == 0


@pytest.mark.parametrize("slug", [None, "proof", "Bounty", ""])
async def test_get_weights_requires_the_matching_slug(client, upstream, slug):
    headers = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}
    if slug is not None:
        headers["X-Platform-Challenge-Slug"] = slug

    response = await client.get("/internal/v1/get_weights?epoch=1", headers=headers)

    assert response.status_code == 403
    assert upstream.requests == 0


@pytest.mark.parametrize("epoch", ["", "-1", "01", "1.0", "x", str(2**64), "１"])
async def test_get_weights_requires_a_canonical_u64_epoch(client, epoch):
    response = await client.get(f"/internal/v1/get_weights?epoch={epoch}", headers=MASTER)

    assert response.status_code == 400


async def test_get_weights_without_epoch_is_400(client):
    assert (await client.get("/internal/v1/get_weights", headers=MASTER)).status_code == 400


async def test_get_weights_returns_valid_counts_with_full_share_mass(client, upstream):
    upstream.publish(AUTHOR, 3, prefix="a")
    upstream.publish(OTHER, 1, prefix="o")
    upstream.reports.append(
        {
            **upstream.reports[0],
            "id": "dup",
            "status": "duplicate",
            "severity": None,
            "related_report_id": "a0",
        }
    )
    upstream.reports.append(
        {
            **upstream.reports[0],
            "id": "bad",
            "hotkey": "ef" * 32,
            "status": "invalid_malicious",
            "severity": None,
        }
    )

    response = await client.get(f"/internal/v1/get_weights?epoch={2**64 - 1}", headers=MASTER)

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    body = response.json()
    assert body["challenge_slug"] == "bounty"
    assert body["epoch"] == 2**64 - 1
    assert body["weights"] == {ss58(AUTHOR): 3, ss58(OTHER): 1}
    assert all(type(weight) is int for weight in body["weights"].values())
    assert body["full_share_mass"] == 10
    assert body["metadata"] == {"revision": "1", "published": 6, "valid": 4}
    assert body["computed_at"] == "2027-01-15T08:00:00Z"


async def test_get_weights_replays_the_first_answer_per_epoch(client, upstream, clock):
    upstream.publish(AUTHOR, 1)
    first = await client.get("/internal/v1/get_weights?epoch=7", headers=MASTER)
    upstream.publish(OTHER, 2, prefix="o")
    upstream.revision = "2"
    clock.now += 3600

    replay = await client.get("/internal/v1/get_weights?epoch=7", headers=MASTER)
    upstream.status = 503
    during_outage = await client.get("/internal/v1/get_weights?epoch=7", headers=MASTER)
    upstream.status = 200
    next_epoch = await client.get("/internal/v1/get_weights?epoch=8", headers=MASTER)

    assert first.status_code == replay.status_code == during_outage.status_code == 200
    assert replay.content == first.content == during_outage.content
    assert next_epoch.json()["weights"] == {ss58(AUTHOR): 1, ss58(OTHER): 2}
    assert next_epoch.json()["metadata"]["revision"] == "2"


async def test_replay_survives_a_restart(svc, client, upstream):
    upstream.publish(AUTHOR, 1)
    first = await client.get("/internal/v1/get_weights?epoch=3", headers=MASTER)
    svc.close()
    upstream.publish(OTHER, 1, prefix="o")

    replay = await client.get("/internal/v1/get_weights?epoch=3", headers=MASTER)

    assert replay.content == first.content


@pytest.mark.parametrize(
    "break_feed",
    [
        lambda upstream: setattr(upstream, "status", 503),
        lambda upstream: upstream.leaderboard.append({"hotkey": OTHER, "valid_count": 9}),
    ],
)
async def test_feed_failure_is_503_and_persists_nothing(svc, client, upstream, break_feed):
    upstream.publish(AUTHOR, 1)
    break_feed(upstream)

    failed = await client.get("/internal/v1/get_weights?epoch=5", headers=MASTER)

    assert failed.status_code == 503
    assert "backend public" in failed.json()["error"]
    assert svc.store.epoch_weights(5) is None
    upstream.status = 200
    upstream.leaderboard = [{"hotkey": AUTHOR, "valid_count": 1}]
    recovered = await client.get("/internal/v1/get_weights?epoch=5", headers=MASTER)
    assert recovered.json()["weights"] == {ss58(AUTHOR): 1}


async def test_unconfigured_feed_is_503_for_weights(tmp_path):
    settings = make_settings(tmp_path)
    app = create_app(settings)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/internal/v1/get_weights?epoch=1", headers=MASTER)
    app.state.service.close()

    assert response.status_code == 503
    assert response.json() == {"error": "scoring unconfigured: set BOUNTY_BACKEND_PUBLIC_URL"}


async def test_empty_publication_answers_empty_weights(client):
    response = await client.get("/internal/v1/get_weights?epoch=1", headers=MASTER)

    assert response.status_code == 200
    assert response.json()["weights"] == {}
    assert response.json()["full_share_mass"] == 10


def test_settings_reject_a_foreign_slug():
    with pytest.raises(SystemExit, match="must be 'bounty'"):
        Settings.from_env({"CHALLENGE_SLUG": "proof"})


def test_settings_defaults_match_the_contract():
    settings = Settings.from_env({})

    assert settings.state_dir == Path("/data")
    assert settings.internal_token_file == Path("/run/secrets/internal.token")
    assert settings.admin_token_file == Path("/run/secrets/admin.token")
    assert settings.session_secret_file == Path("/run/secrets/session.key")
    assert settings.backend_public_url is None


def test_serve_starts_without_secrets_and_answers_version(tmp_path):
    """The real entry point, as the supervisor canary runs it: no secrets, empty /data."""
    env = {
        "PATH": os.environ["PATH"],
        "CHALLENGE_SLUG": "bounty",
        "CHALLENGE_STATE_DIR": str(tmp_path / "data"),
        "CHALLENGE_INTERNAL_TOKEN_FILE": str(tmp_path / "missing" / "internal.token"),
        "CHALLENGE_ADMIN_TOKEN_FILE": str(tmp_path / "missing" / "admin.token"),
        "BOUNTY_SESSION_SECRET_FILE": str(tmp_path / "missing" / "session.key"),
    }
    port = 18_000 + os.getpid() % 1000
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "bounty_challenge.cli",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                response = httpx.get(f"http://127.0.0.1:{port}/version", timeout=1)
                break
            except httpx.TransportError:
                if process.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError(process.stdout.read().decode()) from None
                time.sleep(0.1)
        health = httpx.get(f"http://127.0.0.1:{port}/health", timeout=5)
    finally:
        process.terminate()
        process.wait(timeout=10)

    assert json.loads(response.content)["slug"] == "bounty"
    assert health.status_code == 503
    assert "server" not in response.headers

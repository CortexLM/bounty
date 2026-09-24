"""Public and operator routes with real sr25519 signatures, SQLite and ASGI."""

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest
from support import (
    MASTER,
    OPERATOR,
    make_settings,
    report_body,
    signed_pair,
    write_private,
)

from bounty_challenge.app import create_app
from bounty_challenge.crypto import decode_hotkey, encode_hotkey
from bounty_challenge.feed import PublicBackend


async def pair(client):
    payload = signed_pair()
    await grant_pair(client, payload)
    response = await client.post("/v1/pair", json=payload)
    assert response.status_code == 201, response.text
    return response.json()["session"]


async def grant_pair(client, payload, expires_at=1_800_000_300):
    response = await client.post(
        "/v1/admin/pair-grants",
        headers=OPERATOR,
        json={
            "account_id": payload["account_id"],
            "hotkey": payload["hotkey"],
            "expires_at": expires_at,
        },
    )
    assert response.status_code == 201, response.text
    return response


def test_bounded_write_routes_keep_their_openapi_request_schemas(app):
    schema = app.openapi()

    expected = {
        "/v1/pair": "PairBody",
        "/v1/admin/pair-grants": "PairGrantBody",
        "/v1/reports": "ReportBody",
        "/v1/admin/adjudicate": "AdjudicateBody",
    }
    for path, title in expected.items():
        body = schema["paths"][path]["post"]["requestBody"]
        assert body["required"] is True
        assert body["content"]["application/json"]["schema"]["title"] == title


async def test_adjudication_is_durable_but_only_published_backend_rows_are_paid(
    svc, client, clock, upstream
):
    session = await pair(client)
    reports = []
    for number in range(3):
        response = await client.post("/v1/reports", json=report_body(session, number))
        assert response.status_code == 201, response.text
        verdict = await client.post(
            "/v1/admin/adjudicate",
            headers=OPERATOR,
            json={"report_id": response.json()["id"], "verdict": "valid", "severity": "major"},
        )
        assert verdict.status_code == 200, verdict.text
        reports.append(verdict.json())
        clock.now += 60

    assert svc.store.get_report(reports[0]["id"])["severity"] == "major"
    hotkey = signed_pair()["hotkey"]
    local_only = await client.get("/internal/v1/get_weights?epoch=1", headers=MASTER)
    assert local_only.json()["weights"] == {}
    upstream.reports = [
        {
            "id": row["id"],
            "hotkey": hotkey,
            "status": "valid",
            "severity": "major",
            "problem_found": row["title"],
            "justification": "Reproduced with an unauthorized request",
            "adjudicator": "operator",
            "adjudicated_at": "2026-09-16T00:00:00Z",
            "created_at": "2026-09-16T00:00:00Z",
        }
        for row in reports
    ]
    upstream.leaderboard = [{"hotkey": hotkey, "valid_count": 3}]

    published = await client.get("/internal/v1/get_weights?epoch=2", headers=MASTER)

    assert published.json()["weights"] == {encode_hotkey(decode_hotkey(hotkey)): 3}


@pytest.mark.parametrize(
    "payload,error",
    [
        ({"verdict": "valid"}, "severity required for valid verdict"),
        (
            {"verdict": "invalid_malicious", "severity": "critical"},
            "severity is only valid for a valid verdict",
        ),
        ({"verdict": "duplicate"}, "duplicate_of required"),
        ({"verdict": "already_fixed_not_prod", "duplicate_of": "x"}, "duplicate_of is only"),
    ],
)
async def test_adjudication_validates_severity_and_duplicate_references(
    svc, client, payload, error
):
    session = await pair(client)
    report = (await client.post("/v1/reports", json=report_body(session))).json()

    response = await client.post(
        "/v1/admin/adjudicate", headers=OPERATOR, json={"report_id": report["id"], **payload}
    )

    assert response.status_code == 409
    assert response.json()["error"].startswith(error)
    assert svc.store.get_report(report["id"])["state"] == "pending"


async def test_adjudicated_reports_cannot_be_adjudicated_again(client):
    session = await pair(client)
    report = (await client.post("/v1/reports", json=report_body(session))).json()
    body = {"report_id": report["id"], "verdict": "invalid_malicious"}

    first = await client.post("/v1/admin/adjudicate", headers=OPERATOR, json=body)
    second = await client.post("/v1/admin/adjudicate", headers=OPERATOR, json=body)

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json() == {"error": "already adjudicated"}


async def test_adjudicating_an_unknown_report_returns_404(client):
    response = await client.post(
        "/v1/admin/adjudicate",
        headers=OPERATOR,
        json={"report_id": "by_missing", "verdict": "invalid_malicious"},
    )

    assert response.status_code == 404


@pytest.mark.parametrize("configured,status", [(False, 200), (True, 503)])
async def test_unavailable_scoring_refuses_report_before_any_row(
    svc, client, upstream, configured, status
):
    session = await pair(client)
    upstream.status = status
    if not configured:
        svc.backend = PublicBackend(None)

    response = await client.post("/v1/reports", json=report_body(session))

    assert response.status_code == 503
    assert svc.store.list_reports() == []


@pytest.mark.parametrize("mutation,status", [("signature", 401), ("terms", 403), ("expiry", 400)])
async def test_pairing_rejects_forgery_missing_terms_and_expired_challenge(
    client, mutation, status
):
    payload = signed_pair()
    await grant_pair(client, payload)
    if mutation == "signature":
        payload["signature"] = "00" * 64
    elif mutation == "terms":
        payload["terms_accepted"] = False
    else:
        payload["exp"] = 1

    response = await client.post("/v1/pair", json=payload)

    assert response.status_code == status


@pytest.mark.parametrize(
    "change,error",
    [
        ({"account_id": "bad account"}, "invalid account_id"),
        ({"nonce": "zz" * 16}, "invalid nonce"),
        ({"nonce": "12"}, "invalid nonce"),
        ({"hotkey": "not-a-hotkey"}, "invalid hotkey or signature"),
        ({"signature": "00"}, "invalid signature"),
    ],
)
async def test_pairing_rejects_malformed_fields(client, change, error):
    response = await client.post("/v1/pair", json={**signed_pair(), **change})

    assert response.status_code == 400
    assert response.json() == {"error": error}


async def test_pairing_accepts_an_ss58_hotkey(client):
    payload = signed_pair()
    await grant_pair(client, payload)
    payload["hotkey"] = encode_hotkey(bytes.fromhex(payload["hotkey"]))

    response = await client.post("/v1/pair", json=payload)

    assert response.status_code == 201
    assert response.json()["miner_hotkey"] == signed_pair()["hotkey"]


async def test_first_pairing_requires_an_operator_grant_without_burning_the_nonce(client):
    payload = signed_pair()

    refused = await client.post("/v1/pair", json=payload)
    await grant_pair(client, payload)
    accepted = await client.post("/v1/pair", json=payload)

    assert refused.status_code == 403
    assert refused.json() == {"error": "pairing not authorized by account operator"}
    assert accepted.status_code == 201
    assert set(accepted.json()) == {"session", "session_id", "account_id", "miner_hotkey"}


async def test_pair_grant_requires_operator_authentication(client):
    payload = signed_pair()

    response = await client.post(
        "/v1/admin/pair-grants",
        headers={"Authorization": "Bearer wrong"},
        json={
            "account_id": payload["account_id"],
            "hotkey": payload["hotkey"],
            "expires_at": 1_800_000_300,
        },
    )

    assert response.status_code == 401


async def test_pair_grant_authentication_precedes_body_parsing(client):
    response = await client.post(
        "/v1/admin/pair-grants",
        headers={"Authorization": "Bearer wrong", "Content-Type": "application/json"},
        content=b"{not-json",
    )

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}


async def test_pair_grant_body_has_a_hard_size_limit(client):
    response = await client.post(
        "/v1/admin/pair-grants",
        headers={**OPERATOR, "Content-Type": "application/json"},
        content=b" " * 4097,
    )

    assert response.status_code == 413
    assert response.json() == {"error": "pair grant request too large"}


@pytest.mark.parametrize(
    "route,size,error",
    [
        ("/v1/pair", 4097, "pair request too large"),
        ("/v1/reports", 256 * 1024 + 1, "report request too large"),
    ],
)
async def test_public_bounty_writes_have_hard_body_limits(client, route, size, error):
    response = await client.post(
        route, headers={"Content-Type": "application/json"}, content=b" " * size
    )

    assert response.status_code == 413
    assert response.json() == {"error": error}


@pytest.mark.parametrize(
    "route,label",
    [("/v1/pair", "pair"), ("/v1/reports", "report")],
)
async def test_schema_failures_are_422_without_echoing_input(client, route, label):
    response = await client.post(route, json={"unexpected": "secret-value"})

    assert response.status_code == 422
    assert response.json() == {"error": f"invalid {label} request"}


async def test_adjudication_authentication_precedes_bounded_body_parsing(client):
    unauthorized = await client.post(
        "/v1/admin/adjudicate",
        headers={"Authorization": "Bearer wrong", "Content-Type": "application/json"},
        content=b"{not-json",
    )
    oversized = await client.post(
        "/v1/admin/adjudicate",
        headers={**OPERATOR, "Content-Type": "application/json"},
        content=b" " * 4097,
    )

    assert unauthorized.status_code == 401
    assert unauthorized.json() == {"error": "unauthorized"}
    assert oversized.status_code == 413
    assert oversized.json() == {"error": "adjudication request too large"}


async def test_expired_pair_grant_does_not_authorize_or_burn_nonce(client, clock):
    payload = signed_pair()
    await grant_pair(client, payload, expires_at=clock.now + 1)
    clock.now += 1

    refused = await client.post("/v1/pair", json=payload)
    await grant_pair(client, payload, expires_at=clock.now + 300)
    accepted = await client.post("/v1/pair", json=payload)

    assert refused.status_code == 403
    assert accepted.status_code == 201


async def test_successful_pairing_consumes_its_operator_grant(client):
    payload = signed_pair()
    await grant_pair(client, payload)
    assert (await client.post("/v1/pair", json=payload)).status_code == 201

    response = await client.post("/v1/pair", json=signed_pair(nonce="34" * 16))

    assert response.status_code == 403
    assert response.json() == {"error": "pairing not authorized by account operator"}


async def test_pair_retry_refuses_used_nonce_without_returning_session_data(client):
    payload = signed_pair()
    await grant_pair(client, payload)

    first = await client.post("/v1/pair", json=payload)
    retry = await client.post("/v1/pair", json=payload)

    assert first.status_code == 201
    assert retry.status_code == 409
    assert retry.json() == {"error": "nonce reused"}


@pytest.mark.parametrize(
    "account,seed_byte", [("account-b", 7), ("account-b", 8), ("account-a", 8)]
)
async def test_used_nonce_refuses_different_identity_without_consuming_its_grant(
    client, account, seed_byte
):
    original_session = await pair(client)
    payload = signed_pair(account, seed_byte=seed_byte)
    await grant_pair(client, payload)

    reused = await client.post("/v1/pair", json=payload)
    fresh = signed_pair(account, nonce="34" * 16, seed_byte=seed_byte)
    retry = await client.post("/v1/pair", json=fresh)

    assert reused.status_code == 409
    assert reused.json() == {"error": "nonce reused"}
    assert retry.status_code == 201
    retained = await client.post("/v1/reports", json=report_body(original_session))
    assert retained.status_code == (401 if account == "account-a" else 201)


@pytest.mark.parametrize("offset,error", [(301, "within 300 seconds"), (0, "in the future")])
async def test_pair_grant_expiry_is_bounded_to_five_minutes(client, clock, offset, error):
    payload = signed_pair()

    response = await client.post(
        "/v1/admin/pair-grants",
        headers=OPERATOR,
        json={
            "account_id": payload["account_id"],
            "hotkey": payload["hotkey"],
            "expires_at": clock.now + offset,
        },
    )

    assert response.status_code == 400
    assert error in response.json()["error"]


async def test_restart_preserves_sessions_nonces_reports_and_quotas(svc, client, clock):
    session = await pair(client)
    created = (await client.post("/v1/reports", json=report_body(session))).json()
    svc.close()  # the next request reopens bounty.sqlite3, as a new container would

    repeated_pair = await client.post("/v1/pair", json=signed_pair())
    repeated_report = await client.post("/v1/reports", json=report_body(session, 1))

    assert repeated_pair.status_code == 409
    assert repeated_pair.json() == {"error": "nonce reused"}
    assert repeated_report.status_code == 429
    assert svc.store.get_report(created["id"])["state"] == "pending"
    clock.now += 60
    assert (await client.post("/v1/reports", json=report_body(session, 1))).status_code == 201


async def test_repairing_an_account_revokes_its_previous_session(client):
    first = await pair(client)
    payload = signed_pair(nonce="34" * 16)
    await grant_pair(client, payload)
    reused = await client.post("/v1/pair", json=signed_pair())
    replacement = await client.post("/v1/pair", json=payload)

    old_report = await client.post("/v1/reports", json=report_body(first))
    new_report = await client.post(
        "/v1/reports", json=report_body(replacement.json()["session"], 1)
    )

    assert reused.status_code == 409
    assert replacement.status_code == 201
    assert old_report.status_code == 401
    assert old_report.json() == {"error": "invalid_session"}
    assert new_report.status_code == 201


async def test_repairing_during_feed_validation_revokes_the_inflight_session(svc, client, clock):
    old_session = await pair(client)
    original_fetch = svc.backend.fetch

    async def fetch_after_repair():
        replacement = signed_pair(nonce="34" * 16)
        svc.grant_pair(
            SimpleNamespace(
                account_id=replacement["account_id"],
                hotkey=replacement["hotkey"],
                expires_at=clock.now + 300,
            )
        )
        svc.pair(SimpleNamespace(**replacement))
        return await original_fetch()

    svc.backend.fetch = fetch_after_repair

    response = await client.post("/v1/reports", json=report_body(old_session))

    assert response.status_code == 401
    assert response.json() == {"error": "invalid_session"}
    assert svc.store.list_reports() == []


async def test_operator_granted_hotkey_replacement_revokes_the_existing_session(client):
    original = await pair(client)

    payload = signed_pair(nonce="34" * 16, seed_byte=8)
    await grant_pair(client, payload)
    replacement = await client.post("/v1/pair", json=payload)
    revoked = await client.post("/v1/reports", json=report_body(original))
    accepted = await client.post("/v1/reports", json=report_body(replacement.json()["session"], 1))

    assert replacement.status_code == 201
    assert replacement.json()["miner_hotkey"] == payload["hotkey"]
    assert revoked.status_code == 401
    assert accepted.status_code == 201


async def test_status_probes_the_external_feed_instead_of_claiming_configured_is_ready(
    client, upstream
):
    upstream.status = 503

    status = await client.get("/v1/status")

    body = status.json()
    assert status.status_code == 200
    assert body["backend_public_configured"] is True
    assert body["scoring_backend"] == "backend_public"
    assert body["can_score"] is False
    assert "fetch failed" in body["reason"]
    assert body["pairing"] == {"requires_operator_grant": True, "grant_max_ttl_secs": 300}
    assert body["quotas"] == {
        "max_pending_reports_per_hotkey": 5,
        "max_concurrent_feed_validations_per_hotkey": 1,
        "min_report_interval_secs": 60,
        "min_report_body_chars": 80,
        "min_repro_chars": 20,
        "max_report_request_bytes": 256 * 1024,
    }


async def test_status_publishes_v2_scoring_without_an_emission_share(client):
    body = (await client.get("/v1/status")).json()

    assert body["can_score"] is True and body["reason"] is None
    assert body["scoring_version"] == 2
    assert body["scoring"] == {
        "paid_on": ["valid_report_count"],
        "points_per_valid_report": 1,
        "full_share_reports": 10,
        "population": "expected_metagraph_hotkeys",
        "window": "cumulative_published_history",
        "off_score_gates": [],
        "severities": ["trivial", "minor", "major", "critical"],
    }
    assert "emission_share_bps" not in json.dumps(body)
    assert body["terms"].startswith("By pairing a Bittensor hotkey")


async def test_successful_status_cache_never_masks_an_intake_outage(svc, client, upstream):
    svc.backend._PROBE_SUCCESS_TTL_SECONDS = 60
    session = await pair(client)
    assert (await client.get("/v1/status")).json()["can_score"] is True
    upstream.status = 503

    response = await client.post("/v1/reports", json=report_body(session))

    assert response.status_code == 503
    assert svc.store.list_reports() == []


async def test_concurrent_reports_from_one_hotkey_start_only_one_feed_snapshot(svc, client):
    session = await pair(client)
    entered = asyncio.Event()
    release = asyncio.Event()

    class BlockingBackend:
        configured = True
        reads = 0

        async def fetch(self):
            self.reads += 1
            entered.set()
            await release.wait()

    backend = BlockingBackend()
    svc.backend = backend
    first = asyncio.create_task(client.post("/v1/reports", json=report_body(session)))
    await entered.wait()
    try:
        second = await asyncio.wait_for(
            client.post("/v1/reports", json=report_body(session, 1)), timeout=0.1
        )
    except TimeoutError:
        second = None
    finally:
        release.set()
    first_response = await first

    assert first_response.status_code == 201
    assert second is not None and second.status_code == 429
    assert backend.reads == 1


async def test_duplicate_of_closed_report_never_reopens_triage(svc, client, clock):
    session = await pair(client)
    original = (await client.post("/v1/reports", json=report_body(session))).json()
    await client.post(
        "/v1/admin/adjudicate",
        headers=OPERATOR,
        json={"report_id": original["id"], "verdict": "invalid_malicious"},
    )
    clock.now += 60
    payload = report_body(session)
    payload["title"] = "  " + payload["title"].upper() + "  "

    duplicate = await client.post("/v1/reports", json=payload)

    assert duplicate.status_code == 201
    assert duplicate.json()["state"] == "duplicate"
    assert duplicate.json()["fingerprint"] == original["fingerprint"]
    assert svc.store.get_report(duplicate.json()["id"])["duplicate_of"] == original["id"]


async def test_report_reads_require_operator_and_public_routes_do_not_exist(client):
    session = await pair(client)
    report = (await client.post("/v1/reports", json=report_body(session))).json()

    responses = [
        await client.get("/v1/reports"),
        await client.get(f"/v1/reports/{report['id']}"),
        await client.get("/v1/public/reports"),
    ]

    assert [response.status_code for response in responses] == [401, 401, 404]
    assert all("repro_steps" not in response.text for response in responses)


async def test_operator_reads_reports(client):
    session = await pair(client)
    report = (await client.post("/v1/reports", json=report_body(session))).json()

    listing = await client.get("/v1/reports", headers=OPERATOR)
    single = await client.get(f"/v1/reports/{report['id']}", headers=OPERATOR)
    missing = await client.get("/v1/reports/by_missing", headers=OPERATOR)

    assert [row["id"] for row in listing.json()["items"]] == [report["id"]]
    assert single.json()["repro_steps"].startswith("Call the operator endpoint")
    assert missing.status_code == 404


async def test_pending_quota_and_substance_rejections_do_not_create_rows(svc, client, clock):
    session = await pair(client)
    thin = report_body(session)
    thin["body"] = "fabricated " * 10
    assert (await client.post("/v1/reports", json=thin)).status_code == 400
    for index in range(5):
        assert (
            await client.post("/v1/reports", json=report_body(session, index))
        ).status_code == 201
        clock.now += 60

    response = await client.post("/v1/reports", json=report_body(session, 6))

    assert response.status_code == 429
    assert len(svc.store.list_reports()) == 5


@pytest.mark.parametrize(
    "change,error",
    [
        ({"title": " "}, "title_and_body_required"),
        ({"title": "SAME text", "body": "same   TEXT"}, "title_and_body_must_differ"),
        ({"body": "short but distinct words here"}, "body must be at least 80 characters"),
        ({"repro_steps": "too short"}, "repro_steps must be at least 20 characters"),
        ({"repro_steps": None}, "repro_steps must be at least 20 characters"),
    ],
)
async def test_substance_checks(svc, client, change, error):
    session = await pair(client)

    response = await client.post("/v1/reports", json={**report_body(session), **change})

    assert response.status_code == 400
    assert response.json() == {"error": error}
    assert svc.store.list_reports() == []


async def test_reports_are_rate_limited_per_hotkey(client, clock):
    session = await pair(client)
    assert (await client.post("/v1/reports", json=report_body(session))).status_code == 201
    clock.now += 59

    response = await client.post("/v1/reports", json=report_body(session, 1))

    assert response.status_code == 429
    assert response.json() == {"error": "one report per 60s per hotkey"}


@pytest.mark.parametrize("mutation,status", [("session", 401), ("hotkey", 403), ("bad", 400)])
async def test_report_cannot_impersonate_another_hotkey(svc, client, mutation, status):
    session = await pair(client)
    body = report_body(session)
    if mutation == "session":
        body["session"] = "00" * 32
    elif mutation == "hotkey":
        body["hotkey"] = "ab" * 32
    else:
        body["hotkey"] = "not-a-hotkey"

    response = await client.post("/v1/reports", json=body)

    assert response.status_code == status
    assert svc.store.list_reports() == []


async def test_matching_hotkey_is_accepted_in_either_spelling(client):
    session = await pair(client)
    body = report_body(session)
    body["hotkey"] = encode_hotkey(bytes.fromhex(signed_pair()["hotkey"]))

    assert (await client.post("/v1/reports", json=body)).status_code == 201


async def test_missing_admin_token_never_exposes_private_reports(tmp_path, upstream):
    settings = make_settings(tmp_path, url="https://backend.invalid")
    settings.admin_token_file.unlink()
    app = create_app(settings, backend=upstream.backend())

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        responses = [
            await client.get("/v1/reports"),
            await client.post("/v1/admin/pair-grants", json={}),
            await client.post("/v1/admin/adjudicate", json={}),
        ]
    app.state.service.close()

    assert all(response.status_code == 503 for response in responses)
    assert all(response.json() == {"error": "auth_unconfigured"} for response in responses)


async def test_readable_admin_token_file_is_refused(settings, client):
    settings.admin_token_file.chmod(0o644)

    response = await client.get("/v1/reports", headers=OPERATOR)

    assert response.status_code == 503
    assert response.json() == {"error": "credential file must be private"}


async def test_admin_token_rotation_takes_effect_without_restart(settings, client):
    write_private(settings.admin_token_file, b"rotated-token")

    old = await client.get("/v1/reports", headers=OPERATOR)
    new = await client.get("/v1/reports", headers={"Authorization": "Bearer rotated-token"})

    assert old.status_code == 401
    assert new.status_code == 200


async def test_missing_session_secret_refuses_pairing_and_reports(settings, client):
    payload = signed_pair()
    await grant_pair(client, payload)
    settings.session_secret_file.unlink()

    paired = await client.post("/v1/pair", json=payload)
    retried = await client.post("/v1/reports", json=report_body("00" * 32))

    assert paired.status_code == 503
    assert paired.json() == {"error": "session secret unconfigured"}
    assert retried.status_code == 503


@pytest.mark.parametrize("content", [b"short", b"ab" * 15])
async def test_short_session_secret_is_refused(settings, client, content):
    write_private(settings.session_secret_file, content)
    payload = signed_pair()
    await grant_pair(client, payload)

    response = await client.post("/v1/pair", json=payload)

    assert response.status_code == 503
    assert response.json() == {"error": "session secret must hold at least 32 bytes"}


async def test_hex_session_secret_matches_its_raw_bytes(settings, client):
    """A 64-hex file (the Cortex master format) yields the raw 32-byte key."""
    raw = b"k" * 32
    write_private(settings.session_secret_file, raw.hex().encode() + b"\n")
    session = await pair(client)
    write_private(settings.session_secret_file, raw)

    response = await client.post("/v1/reports", json=report_body(session))

    assert response.status_code == 201

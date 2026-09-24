"""Reject inconsistent publications before they can produce any weight."""

import asyncio
import hashlib

import httpx
import pytest
import sr25519
from support import feed_body, published_report

from bounty_challenge.crypto import decode_hotkey, encode_hotkey
from bounty_challenge.feed import BackendUnavailable, PublicBackend

HOTKEY = "ab" * 32
CURRENT_HOTKEY = sr25519.pair_from_seed(bytes([7]) * 32)[0].hex()
HISTORICAL_HOTKEY = sr25519.pair_from_seed(bytes([8]) * 32)[0].hex()


def ss58(hotkey: str) -> str:
    return encode_hotkey(decode_hotkey(hotkey))


def backend_for(leaderboard, reports, /, **tokens):
    def handle(request):
        route = request.url.path.rsplit("/", 1)[-1]
        body = feed_body(
            route,
            leaderboard,
            reports,
            revision=tokens.get(route, tokens.get("status", "1")),
        )
        return httpx.Response(200, json=body)

    return PublicBackend("https://backend.invalid", transport=httpx.MockTransport(handle))


def mock_backend(handle) -> PublicBackend:
    return PublicBackend("https://backend.invalid", transport=httpx.MockTransport(handle))


@pytest.mark.parametrize(
    "url",
    [
        "http://backend.invalid",
        "https://user:pass@backend.invalid",
        "https://backend.invalid/?token=x",
        "https://backend.invalid/#fragment",
        "https://",
    ],
)
async def test_unsafe_feed_url_fails_closed_without_network(url):
    backend = PublicBackend(url, transport=httpx.MockTransport(lambda request: 1 / 0))

    assert backend.configured is False
    with pytest.raises(BackendUnavailable, match="HTTPS without credentials"):
        await backend.fetch()


async def test_unconfigured_feed_is_unavailable():
    with pytest.raises(BackendUnavailable, match="unconfigured"):
        await PublicBackend(None).fetch()


@pytest.mark.parametrize(
    "leaderboard,reports,tokens",
    [
        ([{"hotkey": HOTKEY, "valid_count": 2}], [published_report()], {}),
        ([], [published_report()], {}),
        ([{"hotkey": HOTKEY, "valid_count": 1}] * 2, [published_report()], {}),
        ([{"hotkey": HOTKEY, "valid_count": 2}], [published_report()] * 2, {}),
        (
            [{"hotkey": HOTKEY, "valid_count": 1}],
            [published_report()],
            {"leaderboard": "2", "reports": "3"},
        ),
        ([{"hotkey": "invalid", "valid_count": 1}], [published_report(hotkey="invalid")], {}),
    ],
)
async def test_stable_but_incoherent_feed_is_refused(leaderboard, reports, tokens):
    backend = backend_for(leaderboard, reports, **tokens)

    with pytest.raises(BackendUnavailable):
        await backend.fetch()


async def test_moving_feed_cannot_be_mistaken_for_stable_scores():
    def handle(request):
        route = request.url.path.rsplit("/", 1)[-1]
        revision = "1" if route == "status" else "2"
        return httpx.Response(200, json=feed_body(route, [], [], revision=revision))

    with pytest.raises(BackendUnavailable, match="revision changed"):
        await mock_backend(handle).fetch()


async def test_transient_json_and_revision_rollout_errors_are_retried():
    status_reads = 0

    def handle(request):
        nonlocal status_reads
        route = request.url.path.rsplit("/", 1)[-1]
        if route == "status":
            status_reads += 1
            if status_reads == 1:
                return httpx.Response(200, content=b"{")
        revision = "2" if route == "leaderboard" and status_reads == 2 else "1"
        return httpx.Response(200, json=feed_body(route, [], [], revision=revision))

    backend = mock_backend(handle)
    backend._SNAPSHOT_RETRY_DELAY_SECONDS = 0

    snapshot = await backend.fetch()

    assert snapshot.reports == ()
    assert snapshot.revision == "1"
    assert status_reads == 3


async def test_transient_failures_stop_after_the_bounded_attempt_count():
    requests = 0

    def unavailable(request):
        nonlocal requests
        requests += 1
        return httpx.Response(503)

    backend = mock_backend(unavailable)
    backend._SNAPSHOT_RETRY_DELAY_SECONDS = 0

    with pytest.raises(BackendUnavailable, match="HTTP 503"):
        await backend.fetch()

    assert requests == backend._SNAPSHOT_ATTEMPTS


async def test_non_retryable_http_status_fails_immediately():
    requests = 0

    def forbidden(request):
        nonlocal requests
        requests += 1
        return httpx.Response(403)

    with pytest.raises(BackendUnavailable, match="HTTP 403"):
        await mock_backend(forbidden).fetch()

    assert requests == 1


async def test_ignored_metadata_does_not_make_a_stable_feed_unreadable():
    request_number = 0

    def handle(request):
        nonlocal request_number
        request_number += 1
        route = request.url.path.rsplit("/", 1)[-1]
        body = feed_body(route, [], [])
        body["generated_at"] = request_number
        return httpx.Response(200, json=body)

    snapshot = await mock_backend(handle).fetch()

    assert snapshot.valid_counts() == {}


async def test_backend_public_leaderboard_valid_field_is_supported():
    snapshot = await backend_for([{"hotkey": HOTKEY, "valid": 1}], [published_report()]).fetch()

    assert snapshot.leaderboard[0].valid_count == 1


async def test_v2_counts_every_valid_report_without_precision_severity_or_champion_gates():
    other = "02" * 32
    historical = "03" * 32
    reports = [
        published_report(id="a", severity="trivial"),
        published_report(id="b", hotkey=other, severity="critical"),
        published_report(id="c", hotkey=other, severity="minor"),
        published_report(id="old", hotkey=historical),
        *[
            published_report(id=f"invalid-{index}", status="invalid_malicious", severity=None)
            for index in range(5)
        ],
        published_report(id="duplicate", status="duplicate", severity=None, related_report_id="a"),
        published_report(id="fixed", status="already_fixed_not_prod", severity=None),
    ]
    backend = backend_for(
        [
            {"hotkey": other, "valid": 2},
            {"hotkey": historical, "valid": 1},
            {"hotkey": HOTKEY, "valid": 1},
        ],
        reports,
    )

    counts = (await backend.fetch()).valid_counts()

    # Historical authors stay in the answer; the master ignores hotkeys outside E.
    assert counts == {ss58(HOTKEY): 1, ss58(other): 2, ss58(historical): 1}


async def test_ss58_and_hex_spellings_of_one_hotkey_count_together():
    reports = [
        published_report("r1", hotkey=CURRENT_HOTKEY),
        published_report("r2", hotkey=ss58(CURRENT_HOTKEY)),
    ]

    def handle(request):
        route = request.url.path.rsplit("/", 1)[-1]
        body = feed_body(route, [{"hotkey": CURRENT_HOTKEY, "valid": 2}], reports)
        if route == "status":
            body["hotkeys"] = 1
        return httpx.Response(200, json=body)

    counts = (await mock_backend(handle).fetch()).valid_counts()

    assert counts == {ss58(CURRENT_HOTKEY): 2}


async def test_backend_rejects_conflicting_leaderboard_count_aliases():
    backend = backend_for([{"hotkey": HOTKEY, "valid": 1, "valid_count": 2}], [published_report()])

    with pytest.raises(BackendUnavailable):
        await backend.fetch()


@pytest.mark.parametrize("revision", ["-1", "01", "x1", "1x", str(2**63)])
async def test_backend_rejects_noncanonical_or_out_of_range_revisions(revision):
    with pytest.raises(BackendUnavailable):
        await backend_for([], [], status=revision).fetch()


async def test_backend_report_read_uses_the_largest_supported_page():
    seen = []

    def handle(request):
        seen.append(request.url)
        route = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=feed_body(route, [], []))

    await mock_backend(handle).fetch()

    report_reads = [url for url in seen if url.path.endswith("/reports")]
    assert report_reads and all(url.params.get("limit") == "100" for url in report_reads)


async def test_backend_reads_every_report_page_at_the_status_revision():
    seen = []
    reports = [published_report("r1"), published_report("r2")]

    def handle(request):
        seen.append(request.url)
        route = request.url.path.rsplit("/", 1)[-1]
        body = feed_body(route, [{"hotkey": HOTKEY, "valid": 2}], reports, revision="7")
        if route == "reports":
            cursor = request.url.params.get("cursor")
            body.update(
                items=[reports[1] if cursor else reports[0]],
                count=1,
                has_more=cursor is None,
                next_cursor="next" if cursor is None else None,
            )
        return httpx.Response(200, json=body)

    snapshot = await mock_backend(handle).fetch()

    assert [report.id for report in snapshot.reports] == ["r1", "r2"]
    assert snapshot.revision == "7"
    report_reads = [url for url in seen if url.path.endswith("/reports")]
    assert [url.params.get("revision") for url in report_reads] == ["7", "7"]
    assert [url.params.get("cursor") for url in report_reads] == [None, "next"]


@pytest.mark.parametrize(
    "page",
    [
        {"items": [], "count": 1, "has_more": False, "next_cursor": None},
        {"items": [], "count": 0, "has_more": False, "next_cursor": "unexpected"},
        {"items": [], "count": 0, "has_more": True, "next_cursor": "next"},
        {"items": [published_report()], "count": 1, "has_more": True, "next_cursor": None},
    ],
)
async def test_backend_rejects_malformed_report_pagination(page):
    def handle(request):
        route = request.url.path.rsplit("/", 1)[-1]
        body = feed_body(route, [], [])
        if route == "reports":
            body.update(page)
        return httpx.Response(200, json=body)

    with pytest.raises(BackendUnavailable, match="page count|pagination|terminal"):
        await mock_backend(handle).fetch()


async def test_backend_rejects_a_repeated_report_cursor():
    def handle(request):
        route = request.url.path.rsplit("/", 1)[-1]
        if route != "reports":
            return httpx.Response(200, json=feed_body(route, [], []))
        report_id = "r2" if request.url.params.get("cursor") else "r1"
        body = feed_body(route, [], [published_report(report_id)])
        body.update(has_more=True, next_cursor="repeated")
        return httpx.Response(200, json=body)

    with pytest.raises(BackendUnavailable, match="pagination"):
        await mock_backend(handle).fetch()


async def test_backend_reconstructs_truncated_leaderboard_from_complete_reports():
    hotkeys = [hashlib.sha256(str(index).encode()).hexdigest() for index in range(1001)]
    reports = [published_report(f"r{index}", hotkey=hotkey) for index, hotkey in enumerate(hotkeys)]
    ordered = sorted(ss58(hotkey) for hotkey in hotkeys)

    def handle(request):
        route = request.url.path.rsplit("/", 1)[-1]
        body = feed_body(route, [], reports)
        if route == "leaderboard":
            body["items"] = [{"hotkey": hotkey, "valid": 1} for hotkey in ordered[:1000]]
            body["has_more"] = True
        elif route == "reports":
            cursor = request.url.params.get("cursor")
            page = int(cursor.removeprefix("page-")) if cursor else 0
            items = reports[page * 100 : (page + 1) * 100]
            has_more = (page + 1) * 100 < len(reports)
            body.update(
                items=items,
                count=len(items),
                has_more=has_more,
                next_cursor=f"page-{page + 1}" if has_more else None,
            )
        return httpx.Response(200, json=body)

    snapshot = await mock_backend(handle).fetch()

    assert len(snapshot.leaderboard) == 1001
    assert {decode_hotkey(row.hotkey).hex() for row in snapshot.leaderboard} == set(hotkeys)
    assert all(row.valid_count == 1 for row in snapshot.leaderboard)
    assert sum(snapshot.valid_counts().values()) == 1001


async def test_backend_rejects_an_inconsistent_truncated_leaderboard_prefix():
    reports = [published_report("r1"), published_report("r2", hotkey=CURRENT_HOTKEY)]

    def handle(request):
        route = request.url.path.rsplit("/", 1)[-1]
        body = feed_body(route, [], reports)
        if route == "leaderboard":
            body["items"] = [{"hotkey": HOTKEY, "valid": 2}]
            body["has_more"] = True
        return httpx.Response(200, json=body)

    with pytest.raises(BackendUnavailable, match="truncated leaderboard"):
        await mock_backend(handle).fetch()


async def test_backend_enforces_per_response_and_complete_report_size_limits():
    backend = backend_for([], [])
    backend._MAX_RESPONSE_BYTES = 32
    with pytest.raises(BackendUnavailable, match="response too large"):
        await backend.fetch()

    backend = backend_for([], [])
    backend._MAX_REPORT_BYTES = 1
    with pytest.raises(BackendUnavailable, match="snapshot is too large"):
        await backend.fetch()


@pytest.mark.parametrize(
    "change,reason",
    [({"adjudication_available": False}, "adjudication"), ({"unpriced_valid": 1}, "unpriced")],
)
async def test_backend_status_must_be_ready_and_fully_priced(change, reason):
    requests = 0

    def handle(request):
        nonlocal requests
        requests += 1
        route = request.url.path.rsplit("/", 1)[-1]
        body = feed_body(route, [], [], revision="0")
        if route == "status":
            body.update(change)
        return httpx.Response(200, json=body)

    with pytest.raises(BackendUnavailable, match=reason):
        await mock_backend(handle).fetch()

    assert requests == 1, "a stable gate is not retried"


async def test_backend_refuses_an_empty_publication_with_a_waiting_backlog():
    def handle(request):
        route = request.url.path.rsplit("/", 1)[-1]
        body = feed_body(route, [], [])
        if route == "status":
            body["awaiting_adjudication"] = 1
        return httpx.Response(200, json=body)

    with pytest.raises(BackendUnavailable, match="backlog"):
        await mock_backend(handle).fetch()


@pytest.mark.parametrize(
    "change,reason",
    [({"published": 2}, "status and reports"), ({"hotkeys": 2}, "hotkey count")],
)
async def test_status_counters_must_agree_with_the_reports(change, reason):
    def handle(request):
        route = request.url.path.rsplit("/", 1)[-1]
        body = feed_body(route, [{"hotkey": HOTKEY, "valid": 1}], [published_report()])
        if route == "status":
            body.update(change)
        return httpx.Response(200, json=body)

    with pytest.raises(BackendUnavailable, match=reason):
        await mock_backend(handle).fetch()


async def test_backend_snapshot_has_one_global_deadline():
    entered = asyncio.Event()

    async def stalled(request):
        entered.set()
        await asyncio.Event().wait()

    backend = mock_backend(stalled)
    backend._SNAPSHOT_TIMEOUT_SECONDS = 0.01

    with pytest.raises(BackendUnavailable, match="deadline"):
        await backend.fetch()
    assert entered.is_set()


async def test_public_probe_reuses_a_short_cache_but_fetch_does_not():
    requests = 0
    available = True

    def handle(request):
        nonlocal requests
        requests += 1
        if not available:
            return httpx.Response(503)
        route = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=feed_body(route, [], []))

    backend = mock_backend(handle)

    await backend.probe()
    await backend.probe()
    assert requests == 3

    available = False
    backend._SNAPSHOT_RETRY_DELAY_SECONDS = 0
    with pytest.raises(BackendUnavailable, match="HTTP 503"):
        await backend.fetch()


async def test_public_probe_refuses_parallel_refresh_without_duplicate_upstream_reads():
    entered = asyncio.Event()
    release = asyncio.Event()
    requests = 0

    async def handle(request):
        nonlocal requests
        requests += 1
        route = request.url.path.rsplit("/", 1)[-1]
        if route == "status":
            entered.set()
            await release.wait()
        return httpx.Response(200, json=feed_body(route, [], []))

    backend = mock_backend(handle)
    first = asyncio.create_task(backend.probe())
    await entered.wait()

    with pytest.raises(BackendUnavailable, match="refresh already in progress"):
        await backend.probe()

    assert requests == 1
    release.set()
    await first


async def test_public_probe_caches_failures_briefly():
    requests = 0

    def unavailable(request):
        nonlocal requests
        requests += 1
        return httpx.Response(503)

    backend = mock_backend(unavailable)
    backend._SNAPSHOT_RETRY_DELAY_SECONDS = 0

    for _ in range(2):
        with pytest.raises(BackendUnavailable, match="HTTP 503"):
            await backend.probe()

    assert requests == backend._SNAPSHOT_ATTEMPTS, "a failure is cached after bounded retries"


async def test_unpriced_valid_is_a_gate_even_after_three_priced_reports():
    reports = [published_report(f"r{index}") for index in range(3)]
    reports.append(published_report("unpriced", severity=None))

    with pytest.raises(BackendUnavailable, match="severity"):
        await backend_for([{"hotkey": HOTKEY, "valid_count": 4}], reports).fetch()


async def test_nonvalid_public_report_cannot_publish_a_severity():
    backend = backend_for([], [published_report(status="duplicate", severity="critical")])

    with pytest.raises(BackendUnavailable, match="severity"):
        await backend.fetch()


@pytest.mark.parametrize(
    "report",
    [
        published_report(status="duplicate", severity=None),
        published_report(status="duplicate", severity=None, related_report_id="missing"),
        published_report(status="duplicate", severity=None, related_report_id="r1"),
        published_report(related_report_id="other"),
    ],
)
async def test_backend_rejects_invalid_duplicate_references(report):
    with pytest.raises(BackendUnavailable, match="duplicate reference"):
        await backend_for([], [report]).fetch()


async def test_backend_rejects_a_duplicate_cycle_without_a_root_report():
    reports = [
        published_report("r1", status="duplicate", severity=None, related_report_id="r2"),
        published_report("r2", status="duplicate", severity=None, related_report_id="r1"),
    ]

    with pytest.raises(BackendUnavailable, match="non-duplicate root"):
        await backend_for([], reports).fetch()


async def test_backend_accepts_a_duplicate_chain_with_a_root_report():
    reports = [
        published_report("r1", status="duplicate", severity=None, related_report_id="r2"),
        published_report("r2", status="duplicate", severity=None, related_report_id="r3"),
        published_report("r3"),
    ]

    snapshot = await backend_for([{"hotkey": HOTKEY, "valid": 1}], reports).fetch()

    assert [report.id for report in snapshot.reports] == ["r1", "r2", "r3"]
    assert snapshot.valid_counts() == {ss58(HOTKEY): 1}, "the original is counted once"


async def test_rejected_reports_earn_no_weight():
    reports = [
        published_report("m", status="invalid_malicious", severity=None),
        published_report("f", status="already_fixed_not_prod", severity=None),
    ]

    assert (await backend_for([], reports).fetch()).valid_counts() == {}


async def test_leaderboard_weight_cannot_invent_evidence():
    reports = [published_report(f"r{index}", justification="") for index in range(3)]
    backend = backend_for([{"hotkey": HOTKEY, "valid_count": 3, "weight": 1_000_000}], reports)

    with pytest.raises(BackendUnavailable, match="evidence"):
        await backend.fetch()


@pytest.mark.parametrize("field", ["problem_found", "justification", "adjudicator"])
async def test_blank_public_evidence_makes_the_feed_unavailable(field):
    backend = backend_for([{"hotkey": HOTKEY, "valid": 1}], [published_report(**{field: " "})])

    with pytest.raises(BackendUnavailable, match="evidence"):
        await backend.fetch()


@pytest.mark.parametrize("body", [b"not json", b'{"items":{}}', b'{"items":[{}]}'])
async def test_unparseable_feed_is_a_scoring_outage(body):
    backend = mock_backend(lambda request: httpx.Response(200, content=body))
    backend._SNAPSHOT_RETRY_DELAY_SECONDS = 0

    with pytest.raises(BackendUnavailable):
        await backend.fetch()


async def test_redirects_are_not_followed():
    def redirect(request):
        return httpx.Response(302, headers={"Location": "https://elsewhere.invalid/"})

    with pytest.raises(BackendUnavailable, match="HTTP 302"):
        await mock_backend(redirect).fetch()

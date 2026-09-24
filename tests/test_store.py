"""Persistence guarantees that span independent connections, restarts and the old schema."""

import hashlib
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from bounty_challenge.store import BountyStore, ServiceError, report_fingerprint, session_token

# The in-process Cortex store (snapshot src/cortex/bounty/store.py) created exactly this.
CORTEX_SCHEMA = """
    CREATE TABLE IF NOT EXISTS bounty_nonces (nonce TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS bounty_pair_grants (
        account_id TEXT NOT NULL,
        miner_hotkey TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        granted_at INTEGER NOT NULL,
        PRIMARY KEY (account_id, miner_hotkey)
    );
    CREATE TABLE IF NOT EXISTS bounty_ids (id INTEGER PRIMARY KEY AUTOINCREMENT);
    CREATE TABLE IF NOT EXISTS bounty_sessions (
        session_id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
        account_id TEXT NOT NULL, miner_hotkey TEXT NOT NULL, bound_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS bounty_pairings (
        account_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES bounty_sessions(session_id)
    );
    CREATE TABLE IF NOT EXISTS bounty_reports (
        id TEXT PRIMARY KEY, miner_hotkey TEXT NOT NULL, account_id TEXT NOT NULL,
        title TEXT NOT NULL, body TEXT NOT NULL, repro_steps TEXT NOT NULL,
        fingerprint TEXT NOT NULL, state TEXT NOT NULL, adjudication TEXT,
        severity TEXT, duplicate_of TEXT REFERENCES bounty_reports(id),
        created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS bounty_reports_miner
        ON bounty_reports(miner_hotkey, state, created_at);
    CREATE INDEX IF NOT EXISTS bounty_reports_fingerprint
        ON bounty_reports(fingerprint, id);
"""


def schema(path: Path) -> dict[str, str]:
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE name LIKE 'bounty_%' ORDER BY name"
        ).fetchall()
    return {name: " ".join(sql.split()) for name, sql in rows}


def test_legacy_schema_is_unchanged_and_only_the_epoch_table_is_added(tmp_path):
    legacy = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(legacy) as connection:
        connection.executescript(CORTEX_SCHEMA)
    BountyStore(tmp_path / "new.sqlite3").close()

    created = schema(tmp_path / "new.sqlite3")

    assert set(created) - set(schema(legacy)) == {"bounty_epoch_weights"}
    assert {name: sql for name, sql in created.items() if name != "bounty_epoch_weights"} == (
        schema(legacy)
    )


def test_a_copied_cortex_database_keeps_sessions_nonces_and_reports(tmp_path):
    """Session tokens and fingerprints match golden values computed by the Cortex store."""
    secret = b"s" * 32
    hotkey = "ab" * 32
    token = session_token(secret, "bs_0000000000000002", "account-a", hotkey)
    assert token == "0941b1c79d72588078beba0aed06bed736d67e8a93b54a2d10a4a0c3e0fd94d2"
    assert report_fingerprint("Title", "Body text") == (
        "51ddb3a4df5df6520f8fbc76669bebcc4e7281bb61f1af0a2df2011c3fac6060"
    )
    path = tmp_path / "bounty.sqlite3"
    path.touch(mode=0o600)
    with sqlite3.connect(path) as connection:
        connection.executescript(CORTEX_SCHEMA)
        connection.execute("INSERT INTO bounty_ids VALUES (1), (2), (3)")
        connection.execute("INSERT INTO bounty_nonces VALUES (?)", ("12" * 16,))
        connection.execute(
            "INSERT INTO bounty_sessions VALUES (?,?,?,?,?)",
            (
                "bs_0000000000000002",
                hashlib.sha256(token.encode()).hexdigest(),
                "account-a",
                hotkey,
                1,
            ),
        )
        connection.execute(
            "INSERT INTO bounty_pairings VALUES (?,?)", ("account-a", "bs_0000000000000002")
        )
        connection.execute(
            "INSERT INTO bounty_reports VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "by_0000000000000003",
                hotkey,
                "account-a",
                "Title",
                "Body text",
                "steps",
                report_fingerprint("Title", "Body text"),
                "pending",
                None,
                None,
                None,
                1,
            ),
        )
    os.chmod(path, 0o600)

    store = BountyStore(path)
    try:
        assert store.lookup_session(token, secret)["miner_hotkey"] == hotkey
        store.grant_pair("account-a", hotkey, expires_at=200, now=100)
        with pytest.raises(ServiceError, match="nonce reused"):
            store.bind_pair("account-a", hotkey, "12" * 16, 100, secret)
        assert store.get_report("by_0000000000000003")["state"] == "pending"
        duplicate = store.insert_report(
            {"miner_hotkey": "cd" * 32, "account_id": "b"}, "title", "body text", "r", 100
        )
        assert duplicate["id"] == "by_0000000000000004"
        assert duplicate["duplicate_of"] == "by_0000000000000003"
    finally:
        store.close()


@pytest.mark.parametrize("mode", [0o644, 0o640])
def test_state_file_must_be_private(tmp_path, mode):
    path = tmp_path / "bounty.sqlite3"
    path.touch()
    os.chmod(path, mode)

    with pytest.raises(RuntimeError, match="private"):
        BountyStore(path)


def test_state_file_must_not_be_a_symlink(tmp_path):
    target = tmp_path / "elsewhere.sqlite3"
    target.touch(mode=0o600)
    (tmp_path / "bounty.sqlite3").symlink_to(target)

    with pytest.raises(RuntimeError, match="unsafe"):
        BountyStore(tmp_path / "bounty.sqlite3")


def test_new_state_file_is_created_private(tmp_path):
    BountyStore(tmp_path / "data" / "bounty.sqlite3").close()

    assert (tmp_path / "data" / "bounty.sqlite3").stat().st_mode & 0o777 == 0o600


def test_two_connections_cannot_race_the_same_hotkey_rate_limit(tmp_path):
    path = tmp_path / "bounty.sqlite3"
    stores = [BountyStore(path), BountyStore(path)]
    barrier = Barrier(2)
    pairing = {"miner_hotkey": "ab" * 32, "account_id": "account"}

    def submit(index):
        barrier.wait(timeout=5)
        try:
            stores[index].insert_report(pairing, f"title {index}", "body", "reproduce", 100)
            return 201
        except ServiceError as exc:
            return exc.status

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(submit, range(2)))

        assert sorted(outcomes) == [201, 429]
        assert len(stores[0].list_reports()) == 1
    finally:
        for store in stores:
            store.close()


def test_two_connections_cannot_consume_the_same_pairing_nonce(tmp_path):
    path = tmp_path / "bounty.sqlite3"
    stores = [BountyStore(path), BountyStore(path)]
    barrier = Barrier(2)
    stores[0].grant_pair("account", "ab" * 32, expires_at=200, now=100)

    def bind(index):
        barrier.wait(timeout=5)
        try:
            result = stores[index].bind_pair("account", "ab" * 32, "12" * 16, 100, b"s" * 32)
            return 201, result
        except ServiceError as exc:
            return exc.status, {"error": exc.reason}

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(bind, range(2)))

        assert sorted(status for status, _ in outcomes) == [201, 409]
        refusal = next(body for status, body in outcomes if status == 409)
        assert refusal == {"error": "nonce reused"}
        accepted = next(body for status, body in outcomes if status == 201)
        assert stores[0].lookup_session(accepted["session"], b"s" * 32)["account_id"] == "account"
    finally:
        for store in stores:
            store.close()


def test_failed_session_insert_rolls_back_the_grant_and_nonce_across_restart(tmp_path):
    path = tmp_path / "bounty.sqlite3"
    store = BountyStore(path)
    store.grant_pair("account", "ab" * 32, expires_at=200, now=100)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TRIGGER fail_session BEFORE INSERT ON bounty_sessions "
            "BEGIN SELECT RAISE(ABORT, 'session write failed'); END"
        )
    try:
        with pytest.raises(sqlite3.IntegrityError, match="session write failed"):
            store.bind_pair("account", "ab" * 32, "12" * 16, 100, b"s" * 32)
    finally:
        store.close()
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER fail_session")

    restarted = BountyStore(path)
    try:
        result = restarted.bind_pair("account", "ab" * 32, "12" * 16, 100, b"s" * 32)

        assert restarted.lookup_session(result["session"], b"s" * 32)["account_id"] == "account"
        with pytest.raises(ServiceError, match="nonce reused") as repeated:
            restarted.bind_pair("account", "ab" * 32, "12" * 16, 100, b"s" * 32)
        assert repeated.value.status == 409
        with pytest.raises(ServiceError, match="pairing not authorized") as spent_grant:
            restarted.bind_pair("account", "ab" * 32, "34" * 16, 100, b"s" * 32)
        assert spent_grant.value.status == 403
    finally:
        restarted.close()


def test_two_connections_cannot_consume_one_pair_grant_with_different_nonces(tmp_path):
    path = tmp_path / "bounty.sqlite3"
    stores = [BountyStore(path), BountyStore(path)]
    barrier = Barrier(2)
    stores[0].grant_pair("account", "ab" * 32, expires_at=200, now=100)

    def bind(index):
        barrier.wait(timeout=5)
        try:
            stores[index].bind_pair("account", "ab" * 32, f"{index + 1:02x}" * 16, 100, b"s" * 32)
            return 201
        except ServiceError as exc:
            return exc.status

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(bind, range(2)))

        assert sorted(outcomes) == [201, 403]
    finally:
        for store in stores:
            store.close()


def test_first_epoch_answer_wins_across_connections_and_restarts(tmp_path):
    path = tmp_path / "bounty.sqlite3"
    first, second = BountyStore(path), BountyStore(path)
    try:
        assert first.save_epoch_weights(2**64 - 1, b"first") == b"first"
        assert second.save_epoch_weights(2**64 - 1, b"second") == b"first"
    finally:
        first.close()
        second.close()
    restarted = BountyStore(path)
    try:
        assert restarted.epoch_weights(2**64 - 1) == b"first"
        assert restarted.epoch_weights(0) is None
    finally:
        restarted.close()

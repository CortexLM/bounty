"""Transactional SQLite state: pairing replay protection, reports, quotas, epoch answers."""

import hashlib
import hmac
import os
import sqlite3
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

Row = dict[str, Any]


class ServiceError(Exception):
    """A stable public refusal: HTTP status plus a bounded reason, never upstream bodies."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def normalize_text(text: str) -> str:
    # ASCII-only lowering keeps the fingerprint contract of earlier Bounty releases.
    return " ".join(text.split()).translate(
        str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
    )


def report_fingerprint(title: str, body: str) -> str:
    return hashlib.sha256(
        b"base-bounty-report-v1"
        + normalize_text(title).encode()
        + b"\xff"
        + normalize_text(body).encode()
    ).hexdigest()


def session_token(secret: bytes, session_id: str, account: str, hotkey: str) -> str:
    payload = b"base-bounty-session-v1\x00" + b"\x00".join(
        value.encode() for value in (session_id, account, hotkey)
    )
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def _prepare_database(path: Path) -> None:
    """Create or validate a private regular file without following links."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        try:
            descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            os.fchmod(descriptor, 0o600)
        except FileExistsError:
            descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError(f"{path}: unsafe SQLite state path") from error
    try:
        metadata = os.fstat(descriptor)
        # ponytail: the parent directory mode is not checked because the canary
        # mounts a 1777 tmpfs at /data and the container runs a single UID.
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise RuntimeError(f"{path}: SQLite state must be a private 0600 file with one link")
    finally:
        os.close(descriptor)


class BountyStore:
    """Every write uses BEGIN IMMEDIATE, including quota and duplicate checks."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        _prepare_database(self.path)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None, timeout=10
        )
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA foreign_keys=ON")
        # The first six tables keep the schema of the in-process Cortex store, so
        # an existing bounty.sqlite3 can be copied into /data unchanged.
        self._db.executescript("""
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
            CREATE TABLE IF NOT EXISTS bounty_epoch_weights (
                epoch TEXT PRIMARY KEY, body BLOB NOT NULL
            );
        """)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def _next_id(self, prefix: str) -> str:
        cursor = self._db.execute("INSERT INTO bounty_ids DEFAULT VALUES")
        return f"{prefix}_{cursor.lastrowid:016x}"

    def grant_pair(self, account: str, hotkey: str, *, expires_at: int, now: int) -> Row:
        if expires_at <= now:
            raise ServiceError(400, "pair grant must expire in the future")
        with self._transaction() as db:
            db.execute("DELETE FROM bounty_pair_grants WHERE expires_at<=?", (now,))
            db.execute(
                "INSERT INTO bounty_pair_grants "
                "(account_id, miner_hotkey, expires_at, granted_at) VALUES (?,?,?,?) "
                "ON CONFLICT(account_id, miner_hotkey) DO UPDATE SET "
                "expires_at=excluded.expires_at, granted_at=excluded.granted_at",
                (account, hotkey, expires_at, now),
            )
        return {"account_id": account, "miner_hotkey": hotkey, "expires_at": expires_at}

    def bind_pair(self, account: str, hotkey: str, nonce: str, now: int, secret: bytes) -> Row:
        """Consume nonce and grant and replace the account session in one transaction."""
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM bounty_nonces WHERE nonce=?", (nonce,)).fetchone():
                raise ServiceError(409, "nonce reused")
            consumed = db.execute(
                "DELETE FROM bounty_pair_grants "
                "WHERE account_id=? AND miner_hotkey=? AND expires_at>?",
                (account, hotkey, now),
            )
            if consumed.rowcount != 1:
                raise ServiceError(403, "pairing not authorized by account operator")
            db.execute("INSERT INTO bounty_nonces VALUES (?)", (nonce,))
            session_id = self._next_id("bs")
            token = session_token(secret, session_id, account, hotkey)
            db.execute(
                "INSERT INTO bounty_sessions VALUES (?,?,?,?,?)",
                (session_id, hashlib.sha256(token.encode()).hexdigest(), account, hotkey, now),
            )
            db.execute(
                "INSERT INTO bounty_pairings VALUES (?,?) ON CONFLICT(account_id) "
                "DO UPDATE SET session_id=excluded.session_id",
                (account, session_id),
            )
        return {
            "session": token,
            "session_id": session_id,
            "account_id": account,
            "miner_hotkey": hotkey,
        }

    def lookup_session(self, token: str, secret: bytes) -> Row:
        with self._lock:
            row = self._db.execute(
                "SELECT s.* FROM bounty_sessions s "
                "JOIN bounty_pairings p ON p.account_id=s.account_id AND p.session_id=s.session_id "
                "WHERE s.token_hash=?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            ).fetchone()
        if row is None or not hmac.compare_digest(
            token,
            session_token(secret, row["session_id"], row["account_id"], row["miner_hotkey"]),
        ):
            raise ServiceError(401, "invalid_session")
        return {key: row[key] for key in ("account_id", "miner_hotkey", "session_id", "bound_at")}

    @staticmethod
    def _check_report_admission(db: sqlite3.Connection, hotkey: str, now: int) -> None:
        pending = db.execute(
            "SELECT count(*) FROM bounty_reports WHERE miner_hotkey=? AND state='pending'",
            (hotkey,),
        ).fetchone()[0]
        if pending >= 5:
            raise ServiceError(
                429, "5 reports already awaiting adjudication for this hotkey (max 5)"
            )
        last = db.execute(
            "SELECT max(created_at) FROM bounty_reports WHERE miner_hotkey=?", (hotkey,)
        ).fetchone()[0]
        if last is not None and now - last < 60:
            raise ServiceError(429, "one report per 60s per hotkey")

    def check_report_admission(self, pairing: Row, now: int) -> None:
        with self._lock:
            self._check_report_admission(self._db, pairing["miner_hotkey"], now)

    def insert_report(self, pairing: Row, title: str, body: str, repro: str, now: int) -> Row:
        fingerprint = report_fingerprint(title, body)
        hotkey = pairing["miner_hotkey"]
        with self._transaction() as db:
            self._check_report_admission(db, hotkey, now)
            original = db.execute(
                "SELECT id FROM bounty_reports WHERE fingerprint=? ORDER BY id LIMIT 1",
                (fingerprint,),
            ).fetchone()
            report_id = self._next_id("by")
            db.execute(
                "INSERT INTO bounty_reports VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    report_id,
                    hotkey,
                    pairing["account_id"],
                    title,
                    body,
                    repro,
                    fingerprint,
                    "duplicate" if original else "pending",
                    "duplicate" if original else None,
                    None,
                    original["id"] if original else None,
                    now,
                ),
            )
            return self.get_report(report_id)

    def get_report(self, report_id: str) -> Row:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM bounty_reports WHERE id=?", (report_id,)
            ).fetchone()
        if row is None:
            raise ServiceError(404, "not_found")
        return dict(row)

    def list_reports(self) -> list[Row]:
        # ponytail: unpaginated operator listing; add cursor pagination once the
        # table outgrows one response.
        with self._lock:
            return [
                dict(row)
                for row in self._db.execute("SELECT * FROM bounty_reports ORDER BY id DESC")
            ]

    def adjudicate(
        self, report_id: str, verdict: str, severity: str | None, duplicate_of: str | None
    ) -> Row:
        if verdict == "valid" and severity is None:
            raise ServiceError(409, "severity required for valid verdict")
        if verdict != "valid" and severity is not None:
            raise ServiceError(409, "severity is only valid for a valid verdict")
        with self._transaction() as db:
            row = self.get_report(report_id)
            if row["state"] != "pending" and row["adjudication"] != "duplicate":
                raise ServiceError(409, "already adjudicated")
            if verdict == "duplicate":
                if not duplicate_of:
                    raise ServiceError(409, "duplicate_of required")
                if duplicate_of == report_id:
                    raise ServiceError(409, "report cannot duplicate itself")
                self.get_report(duplicate_of)
            elif duplicate_of is not None:
                raise ServiceError(409, "duplicate_of is only valid for duplicate verdicts")
            db.execute(
                "UPDATE bounty_reports SET state=?, adjudication=?, severity=?, duplicate_of=? "
                "WHERE id=?",
                (verdict, verdict, severity, duplicate_of, report_id),
            )
            return self.get_report(report_id)

    # Epochs are u64, beyond SQLite's signed INTEGER, so the key is canonical decimal text.
    def epoch_weights(self, epoch: int) -> bytes | None:
        with self._lock:
            row = self._db.execute(
                "SELECT body FROM bounty_epoch_weights WHERE epoch=?", (str(epoch),)
            ).fetchone()
        return None if row is None else bytes(row["body"])

    def save_epoch_weights(self, epoch: int, body: bytes) -> bytes:
        """Persist the first answer for an epoch and return whichever answer won."""
        # ponytail: one row per answered epoch, never pruned; prune epochs older
        # than the master's replay horizon if /data growth ever matters.
        with self._transaction() as db:
            db.execute(
                "INSERT INTO bounty_epoch_weights VALUES (?,?) ON CONFLICT(epoch) DO NOTHING",
                (str(epoch), body),
            )
            stored = db.execute(
                "SELECT body FROM bounty_epoch_weights WHERE epoch=?", (str(epoch),)
            ).fetchone()
        return bytes(stored["body"])

    def close(self) -> None:
        with self._lock:
            self._db.close()

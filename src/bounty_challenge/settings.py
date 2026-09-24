"""Environment settings and private secret files, read lazily per use."""

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from . import SLUG
from .store import ServiceError


@dataclass(frozen=True)
class Settings:
    state_dir: Path
    internal_token_file: Path
    admin_token_file: Path
    session_secret_file: Path
    backend_public_url: str | None

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Settings":
        env = dict(os.environ if env is None else env)
        slug = env.get("CHALLENGE_SLUG", SLUG)
        if slug != SLUG:
            raise SystemExit(f"CHALLENGE_SLUG must be {SLUG!r}, got {slug!r}")
        return cls(
            state_dir=Path(env.get("CHALLENGE_STATE_DIR", "/data")),
            internal_token_file=Path(
                env.get("CHALLENGE_INTERNAL_TOKEN_FILE", "/run/secrets/internal.token")
            ),
            admin_token_file=Path(
                env.get("CHALLENGE_ADMIN_TOKEN_FILE", "/run/secrets/admin.token")
            ),
            session_secret_file=Path(
                env.get("BOUNTY_SESSION_SECRET_FILE", "/run/secrets/session.key")
            ),
            backend_public_url=env.get("BOUNTY_BACKEND_PUBLIC_URL") or None,
        )


def read_private_file(path: Path, *, missing: str, limit: int = 8192) -> bytes:
    """Read a regular, owner-only file without following links; 503 otherwise."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise ServiceError(503, missing) from None
    except OSError:
        raise ServiceError(503, "credential file unavailable") from None
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise ServiceError(503, "credential file must be private")
        value = stream.read(limit + 1)
    if not value or len(value) > limit:
        raise ServiceError(503, "credential file unavailable")
    return value


def read_token(path: Path) -> str:
    try:
        token = read_private_file(path, missing="auth_unconfigured").decode().strip()
    except UnicodeError:
        raise ServiceError(503, "credential file unavailable") from None
    if not token:
        raise ServiceError(503, "credential file unavailable")
    return token


def read_session_secret(path: Path) -> bytes:
    """Decode the key exactly as the Cortex master did, so existing sessions stay valid.

    Cortex accepted exactly 32 raw bytes, else 64 hex characters. This also
    accepts longer hex or raw keys (never shorter than 32 bytes).
    """
    raw = read_private_file(path, missing="session secret unconfigured")
    if len(raw) == 32:
        return raw
    try:
        secret = bytes.fromhex(raw.decode().strip().removeprefix("0x"))
    except (UnicodeError, ValueError):
        secret = raw
    if len(secret) < 32:
        raise ServiceError(503, "session secret must hold at least 32 bytes")
    return secret

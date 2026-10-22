"""Explicit auth-only reuse for newly isolated Claude worktrees.

No environment changes happen here. A successful prepare() returns the only
directory eligible for CLAUDE_SECURESTORAGE_CONFIG_DIR. The launcher must keep
the marker outside the child sandbox and stop jobs using the migration source
or destination before migrating.
Credential values are never returned, logged, or included in exception text.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import math
import os
from pathlib import Path
import re
import stat

from .core import Blocked
from . import isolated_preferences as safe


MARKER = "enabled.json"
STORE = "store"
CREDENTIALS = ".credentials.json"
LOCK = ".auth-migration.lock"
LIMIT = 65536
ENABLED = {"schema": 1, "enabled": True, "storage": STORE}
OAUTH_FIELDS = frozenset(("accessToken", "refreshToken", "expiresAt",
                         "refreshTokenExpiresAt", "scopes", "subscriptionType",
                         "rateLimitTier"))
_ERROR = "隔离认证共享状态缺失、损坏或权限不安全，已阻止启动；不会退回其他账号目录。"


def _exists(directory, name):
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _base(project):
    base = Path(project.base).absolute()
    if base.resolve() != base or Path(project.home).absolute().resolve() != Path(project.home).absolute():
        raise ValueError("aliased authentication base")
    return base


def _open_lock(directory):
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    for _ in range(4):
        try:
            return os.open(LOCK, flags, dir_fd=directory)
        except FileNotFoundError:
            try:
                return os.open(LOCK, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
            except (FileExistsError, FileNotFoundError):
                continue
    raise ValueError("authentication migration lock changed")


@contextmanager
def _scope(project):
    base = _base(project)
    descriptors = []
    try:
        base_fd = safe._open_dir(base)
        descriptors.append(base_fd)
        if not _exists(base_fd, ".runtime"):
            yield None, None
            return
        runtime = safe._open_dir(".runtime", parent=base_fd)
        descriptors.append(runtime)
        lock = _open_lock(runtime)
        descriptors.append(lock)
        safe._check(os.fstat(lock), private=True, limit=4096)
        fcntl.flock(lock, fcntl.LOCK_EX)
        opened = os.fstat(lock)
        entry = os.stat(LOCK, dir_fd=runtime, follow_symlinks=False)
        safe._check(entry, private=True, limit=4096)
        if (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino):
            raise ValueError("authentication lock replaced")
        auth = None
        if _exists(runtime, "auth"):
            auth = safe._open_dir("auth", parent=runtime, private=True)
            descriptors.append(auth)
        yield runtime, auth
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _token(value):
    return (isinstance(value, str) and 0 < len(value) <= 16384
            and all(32 < ord(character) < 127 for character in value))


def _expiry(value):
    # Expired access tokens are valid migration input: the native client owns
    # normal OAuth refresh, including refreshTokenExpiresAt when present.
    return (type(value) in (int, float) and math.isfinite(value) and value > 0)


def _oauth(data, *, source=False):
    if not isinstance(data, dict) or not isinstance(data.get("claudeAiOauth"), dict):
        raise ValueError("missing isolated OAuth credentials")
    raw = data["claudeAiOauth"]
    if not source and (set(data) != {"claudeAiOauth"} or set(raw) - OAUTH_FIELDS):
        raise ValueError("non-authentication data in shared storage")
    result = {key: raw[key] for key in OAUTH_FIELDS if key in raw}
    if not _token(result.get("accessToken")) or not _expiry(result.get("expiresAt")):
        raise ValueError("invalid isolated access token")
    if source and not _token(result.get("refreshToken")):
        raise ValueError("migration source needs a complete refresh credential")
    if "refreshToken" in result and result["refreshToken"] is not None and not _token(result["refreshToken"]):
        raise ValueError("invalid isolated refresh token")
    if "refreshTokenExpiresAt" in result and result["refreshTokenExpiresAt"] is not None and not _expiry(result["refreshTokenExpiresAt"]):
        raise ValueError("invalid refresh expiry")
    scopes = result.get("scopes")
    if (not isinstance(scopes, list) or len(scopes) > 64
            or any(not isinstance(scope, str) or not scope or len(scope) > 256
                   or any(ord(c) <= 32 or ord(c) >= 127 for c in scope) for scope in scopes)):
        raise ValueError("invalid OAuth scopes")
    for field in ("subscriptionType", "rateLimitTier"):
        value = result.get(field)
        if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value)):
            raise ValueError("invalid subscription category")
    return {"claudeAiOauth": result}


def _enabled(auth):
    if auth is None:
        return False, False
    marker, marker_state = safe._read(auth, MARKER, private=True, limit=4096)
    if marker_state is None:
        raise ValueError("authentication directory exists without opt-in marker")
    if marker != ENABLED or type(marker.get("schema")) is not int or marker.get("enabled") is not True:
        raise ValueError("invalid authentication opt-in marker")
    if _exists(auth, STORE + ".lock"):
        lock_info = os.stat(STORE + ".lock", dir_fd=auth, follow_symlinks=False)
        # Native proper-lockfile uses a directory (often mode 0755). It is not
        # secret storage, but must not be an alias or writable by other users.
        safe._check(lock_info, directory=stat.S_ISDIR(lock_info.st_mode), limit=4096)
    store = safe._open_dir(STORE, parent=auth, private=True)
    try:
        data, fingerprint = safe._read(store, CREDENTIALS, private=True, limit=LIMIT)
        if fingerprint is not None and data:
            _oauth(data)
    finally:
        os.close(store)
    return True, fingerprint is not None and bool(data)


def prepare(project) -> Path | None:
    """Validate opt-in storage and return its directory, or None when disabled."""
    try:
        if getattr(project, "workspace", None) is not None:
            from . import keychain_auth
            if project.workspace_config is None:
                raise ValueError("missing workspace authentication scope")
            return keychain_auth.workspace_storage(project.workspace_config, project.workspace)
        with _scope(project) as (_, auth):
            if not _enabled(auth)[0]:
                return None
            return _base(project) / ".runtime" / "auth" / STORE
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise Blocked(_ERROR) from None


def status(project) -> dict:
    """Return only status booleans; corruption is an error, never 'disabled'."""
    try:
        if getattr(project, "workspace", None) is not None:
            store = prepare(project)
            fd = safe._open_dir(store, private=True)
            try:
                data, state = safe._read(fd, CREDENTIALS, private=True, limit=LIMIT)
                if state is not None and data:
                    _oauth(data, source=True)
                return {"enabled": True, "credential_present": state is not None and bool(data),
                        "workspace": project.workspace}
            finally:
                os.close(fd)
        with _scope(project) as (_, auth):
            enabled, present = _enabled(auth)
            return {"enabled": enabled, "credential_present": present}
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise Blocked(_ERROR) from None


def _source(project, source_home):
    base = _base(project)
    home = Path(source_home).absolute()
    if home.resolve() != home:
        raise ValueError("aliased migration source")
    parts = home.relative_to(base / ".runtime").parts
    if not (parts == (project.name, "home") or
            (len(parts) == 4 and parts[0] == project.name and parts[1] == "worktrees"
             and re.fullmatch(r"[a-f0-9]{64}", parts[2]) and parts[3] == "home")):
        raise ValueError("source is not a new isolated HOME")
    descriptors = []
    try:
        current = safe._open_dir(base)
        descriptors.append(current)
        for part in (".runtime", *parts, ".claude"):
            current = safe._open_dir(part, parent=current, private=part in ("home", ".claude"))
            descriptors.append(current)
        data, fingerprint = safe._read(current, CREDENTIALS, private=True, limit=LIMIT)
        if fingerprint is None:
            raise ValueError("isolated source has no credentials")
        return _oauth(data, source=True)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def migrate(project, *, source_home: Path, confirmed_new_isolated_home: bool = False) -> bool:
    """One-time opt-in migration; stop jobs using this source/destination first.

    The explicit confirmation concerns the *new isolated* account, never the
    original user's ~/.claude. Existing enabled storage is validated and left
    intact. Incomplete storage fails closed and requires deliberate recovery.
    Source files are never modified or removed.
    """
    try:
        if getattr(project, "workspace", None) is not None:
            raise ValueError("legacy shared migration is not available for workspace accounts")
        if confirmed_new_isolated_home is not True:
            raise ValueError("explicit new-isolated-account confirmation required")
        with _scope(project) as (runtime, auth):
            if _enabled(auth)[0]:
                return False
            # Read and validate source before creating a store. A crash after
            # credentials but before marker cannot silently enable or fall back.
            data = _source(project, source_home)
            if runtime is None:
                raise ValueError("migration runtime does not exist")
            os.mkdir("auth", 0o700, dir_fd=runtime)
            auth = safe._open_dir("auth", parent=runtime, private=True)
            try:
                os.mkdir(STORE, 0o700, dir_fd=auth)
                store = safe._open_dir(STORE, parent=auth, private=True)
                try:
                    safe._write(store, CREDENTIALS, data, None)
                finally:
                    os.close(store)
                safe._write(auth, MARKER, ENABLED, None)
            finally:
                os.close(auth)
            return True
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise Blocked(_ERROR) from None

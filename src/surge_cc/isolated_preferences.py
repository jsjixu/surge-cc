"""Reuse UI onboarding preferences without sharing a Claude data directory.

The trusted launcher calls this outside the child sandbox. The template remains
outside every child HOME; only three allowlisted preference values can cross the
boundary. Authentication, project trust, history and integrations never do.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat

from .core import Blocked


TEMPLATE = "preferences.json"
LOCK = ".preferences.lock"
CONFIG = ".claude.json"
SETTINGS = "settings.json"
THEMES = frozenset(("auto", "dark", "light", "dark-daltonized",
                    "light-daltonized", "dark-ansi", "light-ansi"))
VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?\Z")
MAX_CONFIG = 4 * 1024 * 1024
MAX_TEMPLATE = 4096
_ERROR = "隔离偏好文件无效、正在变化或权限不安全，已停止偏好同步。"


def _fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_nlink, info.st_uid)


def _check(info, *, directory=False, private=False, limit=MAX_CONFIG):
    valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not valid or info.st_uid != os.getuid()
            or info.st_mode & (0o077 if private else 0o022)
            or (not directory and (info.st_nlink != 1 or info.st_size > limit))):
        raise ValueError("unsafe preference metadata")


def _open_dir(path, *, parent=None, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        _check(os.fstat(fd), directory=True, private=private)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_lock(directory):
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    # Opening an existing lock separately from exclusive creation also avoids
    # macOS's occasional ENOENT during simultaneous O_CREAT opens.
    for _ in range(4):
        try:
            return os.open(LOCK, flags, dir_fd=directory)
        except FileNotFoundError:
            try:
                return os.open(LOCK, flags | os.O_CREAT | os.O_EXCL, 0o600,
                               dir_fd=directory)
            except (FileExistsError, FileNotFoundError):
                continue
    raise ValueError("preference lock changed during creation")


@contextmanager
def _scope(project):
    """Pin validated directory descriptors, including the non-child lock root."""
    base, home = Path(project.base).absolute(), Path(project.home).absolute()
    if base.resolve() != base or home.resolve() != home:
        raise ValueError("aliased preference directory")
    relative = home.relative_to(base / ".runtime")
    parts = relative.parts
    # Account-scoped homes preserve the original project/worktree root while
    # keeping mutable CLI configuration and history separate between accounts.
    original_parts = parts
    if len(parts) >= 3 and parts[-3] == "accounts":
        if (getattr(project, "workspace", None) != parts[-2]
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", parts[-2])):
            raise ValueError("unexpected workspace preference home")
        original_parts = (*parts[:-3], "home")
    if not (original_parts == (project.name, "home") or
            (len(original_parts) == 4 and original_parts[0] == project.name and original_parts[1] == "worktrees"
             and re.fullmatch(r"[a-f0-9]{64}", original_parts[2]) and original_parts[3] == "home")):
        raise ValueError("unexpected preference home")
    descriptors = []
    try:
        base_fd = _open_dir(base)
        descriptors.append(base_fd)
        runtime_fd = _open_dir(".runtime", parent=base_fd)
        descriptors.append(runtime_fd)
        current = runtime_fd
        for part in parts:
            current = _open_dir(part, parent=current)
            descriptors.append(current)
        config_fd = _open_dir(".claude", parent=current, private=True)
        descriptors.append(config_fd)
        lock_fd = _open_lock(runtime_fd)
        descriptors.append(lock_fd)
        _check(os.fstat(lock_fd), private=True, limit=MAX_TEMPLATE)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        opened = os.fstat(lock_fd)
        current_lock = os.stat(LOCK, dir_fd=runtime_fd, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (current_lock.st_dev, current_lock.st_ino):
            raise ValueError("replaced preference lock")
        _check(current_lock, private=True, limit=MAX_TEMPLATE)
        yield runtime_fd, config_fd
    finally:
        # Closing the lock releases it even if a validation or write failed.
        for fd in reversed(descriptors):
            os.close(fd)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read(directory, name, *, private=False, limit=MAX_CONFIG):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return {}, None
    try:
        before = os.fstat(fd)
        _check(before, private=private, limit=limit)
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ValueError("oversized preference data")
        after = os.fstat(fd)
        entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if _fingerprint(before) != _fingerprint(after) or _fingerprint(after) != _fingerprint(entry):
            raise ValueError("preference data changed while reading")
        data = json.loads(b"".join(chunks), object_pairs_hook=_unique_object)
        if not isinstance(data, dict):
            raise ValueError("expected preference object")
        # Python versions differ in JSON parser recursion limits. Bound depth
        # explicitly so malformed deeply nested state cannot pass on one host.
        pending = [(data, 0)]
        while pending:
            value, depth = pending.pop()
            if depth > 128:
                raise ValueError("preference data nesting is too deep")
            if isinstance(value, dict):
                pending.extend((item, depth + 1) for item in value.values())
            elif isinstance(value, list):
                pending.extend((item, depth + 1) for item in value)
        return data, _fingerprint(after)
    finally:
        os.close(fd)


def _unchanged(directory, name, expected):
    try:
        actual = _fingerprint(os.stat(name, dir_fd=directory, follow_symlinks=False))
    except FileNotFoundError:
        actual = None
    if actual != expected:
        raise ValueError("preference destination changed concurrently")


def _write(directory, name, data, expected):
    """Atomic, private replace after a change check; never truncate originals."""
    encoded = (json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
    if len(encoded) > (MAX_TEMPLATE if name == TEMPLATE else MAX_CONFIG):
        raise ValueError("oversized preference output")
    temporary = ".surge-cc-preferences-" + secrets.token_hex(12) + ".tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        _unchanged(directory, name, expected)
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def _template(directory):
    data, fingerprint = _read(directory, TEMPLATE, private=True, limit=MAX_TEMPLATE)
    if fingerprint is None:
        return {}, None
    allowed = {"schema", "hasCompletedOnboarding", "lastOnboardingVersion", "theme"}
    if (set(data) - allowed or type(data.get("schema")) is not int or data["schema"] != 1
            or data.get("hasCompletedOnboarding") is not True
            or ("lastOnboardingVersion" in data and not _version(data["lastOnboardingVersion"]))
            or ("theme" in data and not _theme(data["theme"]))):
        raise ValueError("invalid preference template")
    return data, fingerprint


def _theme(value):
    return isinstance(value, str) and value in THEMES


def _version(value):
    return isinstance(value, str) and len(value) <= 64 and VERSION.fullmatch(value) is not None


def prepare(project) -> bool:
    """Fill missing UI preferences only. Call before starting the native child.

    Existing values, including an explicit incomplete-onboarding flag, win.
    Returns whether any current-HOME preference file was updated. The lock
    serializes this module's writers; concurrent native writes are detected by
    metadata checks and should be avoided by invoking before the child starts.
    """
    try:
        with _scope(project) as (runtime, current):
            source, _ = _template(runtime)
            if not source:
                return False
            config, config_state = _read(current, CONFIG, private=True)
            settings, settings_state = _read(current, SETTINGS)
            new_config, new_settings = dict(config), dict(settings)
            new_config.setdefault("hasCompletedOnboarding", True)
            if new_config["hasCompletedOnboarding"] is True and "lastOnboardingVersion" in source:
                new_config.setdefault("lastOnboardingVersion", source["lastOnboardingVersion"])
            if "theme" in source:
                new_settings.setdefault("theme", source["theme"])
            # Validate both files before replacing either. A crash between the
            # two independent atomic writes is harmless and repaired next run.
            _unchanged(current, CONFIG, config_state)
            _unchanged(current, SETTINGS, settings_state)
            changed = False
            if new_config != config:
                _write(current, CONFIG, new_config, config_state)
                changed = True
            if new_settings != settings:
                _write(current, SETTINGS, new_settings, settings_state)
                changed = True
            return changed
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise Blocked(_ERROR) from None


def record(project) -> bool:
    """Record completed onboarding from this isolated HOME, never another HOME.

    The source is parsed only to select the explicit UI allowlist. No source
    file, account object, credentials, project entry, identifier or history is
    copied. Returns whether the private launcher template changed.
    """
    try:
        with _scope(project) as (runtime, current):
            source, _ = _read(current, CONFIG, private=True)
            if source.get("hasCompletedOnboarding") is not True:
                return False
            settings, _ = _read(current, SETTINGS)
            previous, state = _template(runtime)
            result = dict(previous) if previous else {"schema": 1, "hasCompletedOnboarding": True}
            if _version(source.get("lastOnboardingVersion")):
                result["lastOnboardingVersion"] = source["lastOnboardingVersion"]
            if _theme(settings.get("theme")):
                result["theme"] = settings["theme"]
            if result == previous:
                return False
            _write(runtime, TEMPLATE, result, state)
            return True
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise Blocked(_ERROR) from None


def theme(project) -> str | None:
    """Return only a validated theme for the launcher's explicit --settings."""
    try:
        with _scope(project) as (runtime, current):
            settings, _ = _read(current, SETTINGS)
            value = settings.get("theme")
            if _theme(value):
                return value
            source, _ = _template(runtime)
            return source.get("theme")
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise Blocked(_ERROR) from None

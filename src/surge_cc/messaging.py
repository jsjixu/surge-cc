"""Opt-in local peer messaging, scoped to a registered project and account.

Only sockets and live discovery metadata are shared, never an entire HOME.
The short runtime path prevents native Unix socket length fallback to /tmp.
The trusted launcher prepares this namespace before applying Seatbelt.
"""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

from .core import Blocked
from . import isolation, isolated_preferences as safe, shared_history


MARKER = "messaging.json"
IPC_ROOT = Path("/private/tmp") / ("surge-cc-ipc-" + str(os.getuid()))
MAX_MARKER = 1024 * 1024
_ERROR = "同项目通信目录无法验证，已阻止启动；请先退出同一工作树的旧 Claude，再重试。"


@dataclass(frozen=True)
class Scope:
    runtime: Path
    sockets: Path
    sessions: Path


def enabled(project) -> bool:
    try:
        with shared_history._tree(project.base) as tree:
            runtime = tree.open(tree.root, ".runtime", optional=True)
            if runtime is None:
                return False
            marker, state = safe._read(runtime, MARKER, private=True, limit=MAX_MARKER)
            if state is None:
                return False
            if (set(marker) != {"schema", "projects"} or type(marker["schema"]) is not int
                    or marker["schema"] != 1 or not isinstance(marker["projects"], list)):
                raise ValueError("invalid messaging opt-in")
            shared_history._binding(project)
            registry = json.loads(isolation._safe_file(
                Path(project.workspace_config).parent / isolation.REGISTRY_NAME,
                private=True, limit=MAX_MARKER), object_pairs_hook=safe._unique_object)
            if registry.get("root") != str(project.base):
                raise ValueError("registry root changed")
            registered = {entry["id"]: entry for entry in registry["projects"]}
            seen = set()
            for entry in marker["projects"]:
                if (not isinstance(entry, dict) or set(entry) != {"id", "path"}
                        or not isinstance(entry["id"], str)
                        or not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", entry["id"])
                        or entry["id"] in seen):
                    raise ValueError("invalid project opt-in")
                name = entry["id"]
                expected = str(project.base / "projects" / name)
                if (entry["path"] != expected or name not in registered
                        or registered[name].get("path") != expected
                        or registered[name].get("home") != str(project.base / ".runtime" / name / "home")):
                    raise ValueError("unregistered opt-in")
                seen.add(name)
            tree.verify()
            safe._unchanged(runtime, MARKER, state)
            return project.name in seen
    except Blocked:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise Blocked(_ERROR) from None


def _identity(project):
    workspace, _ = shared_history._binding(project)
    return {"schema": 1, "project": str(project.registered_root),
            "config": str(project.workspace_config), "workspace": workspace}


def _open(project, *, create):
    if not enabled(project):
        return None
    identity = _identity(project)
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:32]
    root = Path(IPC_ROOT)
    runtime = root / digest
    result = Scope(runtime, runtime / "cc-socks", runtime / "sessions")
    if (root != root.absolute() or root.resolve() != root
            or len(os.fsencode(result.sockets / "2147483647.sock")) > 103):
        raise ValueError("unsafe or overlong socket root")
    if create:
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            pass
    # No symlink-following mkdir, and pinned descriptors for every owned parent.
    with shared_history._tree(root) as tree:
        safe._check(os.fstat(tree.root), directory=True, private=True)
        lock = safe._open_lock(tree.root) if create else None
        try:
            if lock is not None:
                safe._check(os.fstat(lock), private=True, limit=4096)
                fcntl.flock(lock, fcntl.LOCK_EX)
                current = os.stat(safe.LOCK, dir_fd=tree.root, follow_symlinks=False)
                if safe._fingerprint(current) != safe._fingerprint(os.fstat(lock)):
                    raise ValueError("changed runtime lock")
            fd = tree.open(tree.root, digest, private=True, create=create)
            binding, state = safe._read(fd, "binding.json", private=True, limit=4096)
            if state is None and create:
                safe._write(fd, "binding.json", identity, state)
                binding, state = safe._read(fd, "binding.json", private=True, limit=4096)
            if binding != identity or state is None:
                raise ValueError("scope binding mismatch")
            tree.open(fd, "cc-socks", private=True, create=create)
            tree.open(fd, "sessions", private=True, create=create)
            tree.verify()
            safe._unchanged(fd, "binding.json", state)
        finally:
            if lock is not None:
                os.close(lock)
    return result


def _checked(project, *, create):
    try:
        return _open(project, create=create)
    except Blocked:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise Blocked(_ERROR) from None


def prepare_scope(project) -> Scope | None:
    return _checked(project, create=True)


def scope(project) -> Scope | None:
    return _checked(project, create=False)


def _check_stopped(directory):
    entries = os.listdir(directory)
    if len(entries) > 10000:
        raise ValueError("oversized legacy peer directory")
    for name in entries:
        match = re.fullmatch(r"([1-9][0-9]{0,9})(?:\.json|\.[a-f0-9]{64}\.key)", name)
        if not match:
            raise ValueError("unexpected legacy peer data")
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        safe._check(info, private=True)
        try:
            os.kill(int(match[1]), 0)
        except ProcessLookupError:
            pass
        else:
            raise ValueError("legacy peer is still running")


def prepare(project) -> Scope | None:
    target = prepare_scope(project)
    if target is None:
        return None
    try:
        # Reuse the outside-HOME lock: simultaneous starts never replace a peer
        # directory being prepared by another launcher. No PID data is imported.
        with safe._scope(project) as (_, config):
            try:
                entry = os.stat("sessions", dir_fd=config, follow_symlinks=False)
            except FileNotFoundError:
                entry = None
            if entry is not None and stat.S_ISDIR(entry.st_mode):
                old = safe._open_dir("sessions", parent=config, private=True)
                try:
                    _check_stopped(old)
                    current = os.stat("sessions", dir_fd=config, follow_symlinks=False)
                    if (shared_history._identity(os.fstat(old)) != shared_history._identity(entry)
                            or shared_history._identity(current) != shared_history._identity(entry)):
                        raise ValueError("legacy registry changed")
                    backup = "sessions-before-messaging-" + secrets.token_hex(8)
                    os.rename("sessions", backup, src_dir_fd=config, dst_dir_fd=config)
                    moved = os.stat(backup, dir_fd=config, follow_symlinks=False)
                    if shared_history._identity(moved) != shared_history._identity(entry):
                        raise ValueError("legacy registry replaced during backup")
                finally:
                    os.close(old)
                entry = None
            if entry is None:
                os.symlink(str(target.sessions), "sessions", dir_fd=config)
                entry = os.stat("sessions", dir_fd=config, follow_symlinks=False)
            if (not stat.S_ISLNK(entry.st_mode) or entry.st_uid != os.getuid()
                    or os.readlink("sessions", dir_fd=config) != str(target.sessions)
                    or scope(project) != target):
                raise ValueError("unexpected peer registry link")
        return target
    except Blocked:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise Blocked(_ERROR) from None

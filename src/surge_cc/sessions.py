"""Cooperative shutdown of owned sessions when changing account environments.

No PID is read from a receipt or signalled here. Each supervisor observes a
private generation file and stops only the child it started itself.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import stat
import time
import uuid

from .core import Blocked


_OWNERSHIP = {"schema": 1, "state": "awaiting-confirmed-child-exit"}
_STOP_FAILED = {"schema": 1, "state": "stop-failed"}


def assert_no_stop_failures(root: Path, *, include_pending: bool = True) -> None:
    """Call only under an exclusive workspace lock, after supervisors exit.

    A remaining marker means an owner never confirmed its child had exited.
    No saved PID is trusted. A new account must not start using that route until
    the original owner confirms exit or a person investigates the orphan.
    """
    for marker in root.glob(".stop-failed-*.json"):
        if not include_pending:
            try:
                value, _ = _read_ownership(marker)
                if value == _OWNERSHIP:
                    continue
            except Exception:
                pass
        raise Blocked("此工作区仍有未确认退出的受控程序，已阻止启动或切换。请关闭原程序；仅原监控确认退出后会自动解除，否则需人工核实，不能直接忽略。")


def begin_owned_session(root: Path) -> Path:
    """Persist an ownership latch before spawning, retained after a crash.

    During normal life the shared session lock prevents switching. This small
    marker additionally blocks a switch if the supervisor dies or cannot stop
    its child, including when file locks are released by process termination.
    """
    marker = root / (".stop-failed-" + uuid.uuid4().hex + ".json")
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(_OWNERSHIP, handle)
        handle.flush()
        os.fsync(handle.fileno())
    return marker


def _read_ownership(marker: Path):
    fd = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 256):
            raise Blocked("会话退出标记无法验证，已保留阻止切换的状态。")
        value = json.loads(os.read(fd, 257))
        if value not in (_OWNERSHIP, _STOP_FAILED):
            raise Blocked("会话退出标记无法验证，已保留阻止切换的状态。")
        entry = marker.lstat()
        if (entry.st_dev, entry.st_ino) != (info.st_dev, info.st_ino):
            raise Blocked("会话退出标记发生变化，已保留阻止切换的状态。")
        return value, (info.st_dev, info.st_ino)
    finally:
        os.close(fd)


def mark_stop_failed(marker: Path | None) -> None:
    if marker is None:
        return
    _read_ownership(marker)
    from .workspaces import write_json
    write_json(marker, _STOP_FAILED)


def confirm_owned_exit(marker: Path | None) -> None:
    """Remove only this supervisor's marker after its own child has stopped."""
    if marker is None:
        return
    _, fingerprint = _read_ownership(marker)
    entry = marker.lstat()
    if (entry.st_dev, entry.st_ino) != fingerprint:
        raise Blocked("会话退出标记发生变化，已保留阻止切换的状态。")
    marker.unlink()


def await_owned_exit(child, *, sleep=time.sleep) -> None:
    """Keep the supervisor's session lock until its Popen confirms termination.

    No retry signal is sent. An interrupt may end this wait, but the caller must
    keep its persisted latch, so releasing the file lock cannot permit a switch.
    """
    while child.poll() is None:
        sleep(0.2)


def generation(root: Path) -> str:
    path = root / ".stop-generation.json"
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return ""
    except OSError:
        raise Blocked("工作区停止请求无法安全读取，已停止受控会话。") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 256):
            raise ValueError()
        value = json.loads(os.read(fd, 257))
        token = value.get("generation") if isinstance(value, dict) else None
        if (not isinstance(token, str) or len(token) != 32
                or any(c not in "0123456789abcdef" for c in token)):
            raise ValueError()
        return token
    except (OSError, ValueError, TypeError):
        raise Blocked("工作区停止请求格式异常，已停止受控会话。") from None
    finally:
        os.close(fd)


class SessionChecker:
    def __init__(self, checker, root: Path, initial: str):
        self.checker, self.root, self.initial = checker, root, initial

    @property
    def suspended(self):
        return getattr(self.checker, "suspended", False)

    def check_stop(self):
        if generation(self.root) != self.initial:
            raise Blocked("正在切换账号工作区，已结束此工作区的受控会话。")

    def check(self, **kwargs):
        self.check_stop()
        self.checker.check(**kwargs)
        self.check_stop()


def stop_workspace(config_path: Path, name: str, *, timeout: float = 45) -> None:
    """Caller holds the exclusive account startup gate until switch completes."""
    from . import workspaces, browser_locks
    root = workspaces.create(config_path, name)
    # Validate existing generation before replacing it; do not repair unsafe
    # paths by overwriting them.
    generation(root)
    workspaces.write_json(root / ".stop-generation.json", {"generation": uuid.uuid4().hex})
    fd = os.open(root / ".session.lock", os.O_RDWR | os.O_CREAT |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise Blocked("无法确认当前工作区会话锁，未切换账号。")
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise Blocked("旧工作区会话尚未退出，账号保持原状；请保存任务并关闭旧版 CLI 或专用窗口后重试。") from None
                time.sleep(0.1)
        assert_no_stop_failures(root)
    finally:
        os.close(fd)
    # Chrome may leave singleton links after its parent exits. The established
    # repair validates ownership/liveness and backs up only stale links.
    if any(os.path.lexists(root / "data" / folder / "SingletonLock")
           for folder in ("Browser", "OAuthBrowser")):
        browser_locks.repair(config_path, name)

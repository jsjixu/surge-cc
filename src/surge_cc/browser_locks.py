"""Conservative recovery of stopped, app-owned Chromium singleton links.

This is deliberately not a browser stopper or a profile reset. The two Surge CC
locks exclude cooperating launchers; process/PID/socket checks also reject a
manually launched browser. Only recognized stale symlinks are moved, with a
private manifest, and all browser databases and personal Chrome are untouched.
"""
from __future__ import annotations

from contextlib import ExitStack
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import uuid

from .core import Blocked, now
from .workspaces import name_ok

_LINKS = ("SingletonLock", "SingletonSocket", "SingletonCookie")
_PROFILES = ("Browser", "OAuthBrowser")
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _lstat(fd: int, name: str):
    try:
        return os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _directory(stack: ExitStack, name: str, parent: int | None = None,
               owned: bool = True) -> int:
    fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or (owned and info.st_uid != os.getuid()):
        raise Blocked("浏览器目录的类型或所有者异常，未清理。")
    if owned and info.st_mode & 0o022:
        raise Blocked("浏览器目录允许其他用户写入，未清理。")
    return fd


def _open_base(stack: ExitStack, base: Path) -> int:
    # Traverse with directory descriptors rather than resolving symlinks. The
    # app directory is user-owned; system ancestors such as /private may not be.
    if not base.is_absolute() or ".." in base.parts:
        raise Blocked("配置目录必须是没有上级跳转的绝对路径。")
    fd = _directory(stack, "/", owned=False)
    for index, part in enumerate(base.parts[1:]):
        fd = _directory(stack, part, fd, owned=index == len(base.parts) - 2)
    return fd


def _lock(stack: ExitStack, root_fd: int, name: str) -> tuple[int, tuple]:
    fd = os.open(name, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                 0o600, dir_fd=root_fd)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & 0o022):
        raise Blocked("工作区锁的类型、所有者或链接数量异常，未清理。")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise Blocked("专用浏览器、Claude 或工作区操作仍在运行；请先正常退出后再修复。") from None
    path_info = _lstat(root_fd, name)
    if path_info is None or _identity(path_info) != _identity(info):
        raise Blocked("工作区锁在检查期间发生变化，未清理。")
    return fd, _identity(info)


def _processes() -> list[tuple[int, int, str]]:
    try:
        result = subprocess.run(["/bin/ps", "-ww", "-axo", "pid=,ppid=,uid=,command="],
                                text=True, capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        raise Blocked("无法可靠检查浏览器进程，未清理；请稍后重试。") from None
    if result.returncode or not result.stdout.strip():
        raise Blocked("无法可靠检查浏览器进程，未清理；请稍后重试。")
    values = []
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 3)
        if (len(fields) != 4 or not all(value.isdecimal() for value in fields[:2])
                or not re.fullmatch(r"-?[0-9]+", fields[2])):
            raise Blocked("进程检查返回了无法确认的结果，未清理。")
        values.append((int(fields[0]), int(fields[1]), fields[3]))
    return values


def _assert_stopped(base: Path, profiles: dict[str, Path]) -> None:
    paths = [str(value) for value in profiles.values()]
    # Helpers do not all carry --user-data-dir. Conservatively reject any live
    # helper in the dedicated runtime, including another workspace, rather than
    # risk removing a lock while its parent process is exiting or being replaced.
    paths.append(str(base / "Browser Runtime/Surge CC Browser.app"))
    processes = _processes()
    matching = {pid for pid, _, command in processes if any(path in command for path in paths)}
    changed = True
    while changed:
        children = {pid for pid, parent, _ in processes if parent in matching}
        changed = not children.issubset(matching)
        matching.update(children)
    if matching:
        raise Blocked("专用浏览器或其后台进程仍在运行。请正常退出专用窗口，再点击修复；不会关闭个人 Chrome。")


def _pid_absent(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except (PermissionError, OSError):
        return False
    return False


def _local_hosts() -> set[str]:
    return {socket.gethostname().casefold().rstrip("."),
            os.uname().nodename.casefold().rstrip(".")}


def _read_links(fd: int) -> dict:
    values = {}
    for name in _LINKS:
        before = _lstat(fd, name)
        if before is None:
            continue
        if (not stat.S_ISLNK(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1):
            raise Blocked("浏览器运行时文件不是预期的专用符号链接，未清理。")
        target = os.readlink(name, dir_fd=fd)
        after = _lstat(fd, name)
        if after is None or _identity(before) != _identity(after):
            raise Blocked("浏览器锁在检查期间发生变化，未清理。")
        values[name] = {"target": target, "identity": _identity(before)}
    return values


def _socket_state(path: Path):
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise Blocked("无法确认浏览器套接字状态，未清理。") from None
    if not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1:
        raise Blocked("浏览器套接字类型或所有者异常，未清理。")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.3)
            # Connect only: no Chromium messages or data are sent.
            probe.connect(str(path))
    except OSError as exc:
        if exc.errno not in (errno.ECONNREFUSED, errno.ENOENT):
            raise Blocked("无法确认浏览器套接字已停止服务，未清理。") from None
    else:
        raise Blocked("专用浏览器套接字仍在响应，请先正常退出专用浏览器。")
    try:
        after = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise Blocked("无法复核浏览器套接字，未清理。") from None
    if _identity(before) != _identity(after):
        raise Blocked("浏览器套接字在检查期间发生变化，未清理。")
    return _identity(after)


def _same_moved(info, details: dict) -> bool:
    # rename legitimately updates ctime on macOS. All other identity fields,
    # including inode, owner, type, link count, length and mtime, must match.
    return info is not None and _identity(info)[:-1] == details["identity"][:-1]


def _assert_stale(links: dict):
    if not links:
        return
    if "SingletonLock" not in links:
        raise Blocked("发现不完整的浏览器锁，无法确认所属进程；未清理，请保留现场。")
    target = links["SingletonLock"]["target"]
    match = re.fullmatch(r"([^/\x00]+)-([0-9]+)", target)
    if not match or match[1].casefold().rstrip(".") not in _local_hosts():
        raise Blocked("浏览器锁来自其他主机或格式无法确认，未清理。")
    if len(match[2]) > 10:
        raise Blocked("浏览器锁的进程编号格式异常，未清理。")
    pid = int(match[2])
    if not 2 <= pid <= 2**31 - 1 or not _pid_absent(pid):
        raise Blocked("浏览器锁对应的进程仍存在或无法确认已退出，未清理。")
    if "SingletonCookie" in links and not re.fullmatch(r"[0-9]{1,128}", links["SingletonCookie"]["target"]):
        raise Blocked("浏览器运行时 Cookie 链接格式异常，未清理。")
    if "SingletonSocket" in links:
        path = Path(links["SingletonSocket"]["target"])
        if not path.is_absolute() or ".." in path.parts or path.name != "SingletonSocket":
            raise Blocked("浏览器套接字链接格式异常，未清理。")
        return _socket_state(path)
    return None


def _write_manifest(fd: int, value: dict) -> None:
    temporary = ".manifest-" + uuid.uuid4().hex
    output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                     0o600, dir_fd=fd)
    try:
        with os.fdopen(output, "w") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(temporary, "manifest.json", src_dir_fd=fd, dst_dir_fd=fd)
    finally:
        if _lstat(fd, temporary) is not None:
            os.unlink(temporary, dir_fd=fd)


def repair(config_path: Path, name: str) -> dict:
    """Back up only verifiably stale singleton symlinks in the selected workspace.

    No processes are terminated and no page/login is opened. A missing workspace
    is not silently initialized. Ambiguous cases fail closed, retaining data.
    """
    name_ok(name)
    base = Path(os.path.abspath(config_path.parent))
    root_path = base / "workspaces" / name
    backup_path = None
    moved = []
    try:
        with ExitStack() as stack:
            base_fd = _open_base(stack, base)
            workspaces_fd = _directory(stack, "workspaces", base_fd)
            root_fd = _directory(stack, name, workspaces_fd)
            data_fd = _directory(stack, "data", root_fd)
            locks = {key: _lock(stack, root_fd, key) for key in (".session.lock", ".oauth.lock")}
            profile_fds = {}
            profiles = {key: root_path / "data" / key for key in _PROFILES}
            # Keep original identities, not timestamps, for directories whose
            # entries we deliberately change below.
            directory_ids = {}
            for key in _PROFILES:
                if _lstat(data_fd, key) is None:
                    continue
                profile_fds[key] = _directory(stack, key, data_fd)
                info = os.fstat(profile_fds[key])
                directory_ids[key] = (info.st_dev, info.st_ino)
            if not profile_fds:
                raise Blocked("工作区尚无专用浏览器目录，无需清理。")
            original = {key: _read_links(fd) for key, fd in profile_fds.items()}
            socket_states = {key: _assert_stale(links) for key, links in original.items()}

            def check(expected: dict) -> None:
                # Confirm path names still designate our descriptors, including
                # ancestor directories, before acting on any held descriptor.
                with ExitStack() as verify:
                    current = _open_base(verify, base)
                    for part, held in (("workspaces", workspaces_fd), (name, root_fd), ("data", data_fd)):
                        current = _directory(verify, part, current)
                        current_info, held_info = os.fstat(current), os.fstat(held)
                        if (current_info.st_dev, current_info.st_ino) != (held_info.st_dev, held_info.st_ino):
                            raise Blocked("工作区目录在检查期间发生变化，未继续清理。")
                for key, (fd, identity) in locks.items():
                    info = _lstat(root_fd, key)
                    if info is None or _identity(info) != identity or _identity(os.fstat(fd)) != identity:
                        raise Blocked("工作区锁在检查期间发生变化，未继续清理。")
                for key, fd in profile_fds.items():
                    info = _lstat(data_fd, key)
                    if info is None or (info.st_dev, info.st_ino) != directory_ids[key]:
                        raise Blocked("浏览器目录在检查期间发生变化，未继续清理。")
                    if _read_links(fd) != expected[key]:
                        raise Blocked("浏览器锁在检查期间发生变化，未继续清理。")
                for key in set(_PROFILES) - set(profile_fds):
                    if _lstat(data_fd, key) is not None:
                        raise Blocked("授权浏览器在检查期间创建了目录，未继续清理。")
                _assert_stopped(base, profiles)
                # Always recheck the original PID and socket, including after
                # SingletonLock itself has been moved into the recovery folder.
                for key, links in original.items():
                    if _assert_stale(links) != socket_states[key]:
                        raise Blocked("浏览器套接字在检查期间发生变化，未继续清理。")

            check(original)
            count = sum(len(links) for links in original.values())
            if not count:
                return {"status": "no_stale_locks", "workspace": name, "removed_count": 0,
                        "backup_path": None, "message": "未发现残留锁；可以重新检查线路。"}
            backup_name = "browser-lock-backups"
            try:
                os.mkdir(backup_name, mode=0o700, dir_fd=base_fd)
            except FileExistsError:
                pass
            backups_fd = _directory(stack, backup_name, base_fd)
            if os.fstat(backups_fd).st_mode & 0o077:
                raise Blocked("修复备份目录不是私有目录，未清理。")
            identifier = uuid.uuid4().hex
            os.mkdir(identifier, mode=0o700, dir_fd=backups_fd)
            backup_fd = _directory(stack, identifier, backups_fd)
            backup_path = base / backup_name / identifier
            manifest = {"format": 1, "created_at": now(), "workspace": name,
                        "status": "pending", "entries": [
                            {"profile": key, "name": link, "target": details["target"],
                             "identity": list(details["identity"]), "backup_name": key + "-" + link}
                            for key, links in original.items() for link, details in links.items()],
                        "moved": []}
            _write_manifest(backup_fd, manifest)
            expected = {key: dict(links) for key, links in original.items()}
            try:
                # Socket and cookie first, SingletonLock last, so a stopped
                # browser's startup guard remains effective through the move.
                for key in profile_fds:
                    for link in ("SingletonSocket", "SingletonCookie", "SingletonLock"):
                        if link not in expected[key]:
                            continue
                        check(expected)
                        destination = key + "-" + link
                        details = expected[key][link]
                        if _lstat(backup_fd, destination) is not None:
                            raise Blocked("修复备份文件发生冲突，未继续清理。")
                        os.rename(link, destination, src_dir_fd=profile_fds[key], dst_dir_fd=backup_fd)
                        moved.append((key, link, destination, details))
                        info = _lstat(backup_fd, destination)
                        if (not _same_moved(info, details)
                                or os.readlink(destination, dir_fd=backup_fd) != details["target"]):
                            raise Blocked("移动时浏览器锁发生变化，已停止修复。")
                        del expected[key][link]
                        manifest["moved"].append(destination)
                        _write_manifest(backup_fd, manifest)
                check(expected)
                manifest["status"] = "completed"
                _write_manifest(backup_fd, manifest)
            except (OSError, Blocked):
                # Never overwrite a newly-created runtime link. If safe rollback
                # is impossible, retain the private recovery copy and manifest.
                restored, retained = [], []
                for key, link, destination, details in reversed(moved):
                    try:
                        info = _lstat(backup_fd, destination)
                        if (not _same_moved(info, details)
                                or os.readlink(destination, dir_fd=backup_fd) != details["target"]):
                            retained.append(destination)
                            continue
                        # symlink creation is atomic and fails with EEXIST if
                        # Chrome has created a new link. Never rename over a
                        # destination that was merely absent a moment earlier.
                        # Retain the recovery copy even after restoration.
                        os.symlink(details["target"], link, dir_fd=profile_fds[key])
                        restored.append(destination)
                    except OSError:
                        retained.append(destination)
                manifest.update(status="recovery_required" if retained else "rolled_back",
                                restored=restored, retained=retained)
                try:
                    _write_manifest(backup_fd, manifest)
                except OSError:
                    pass
                raise Blocked("修复过程中状态发生变化，已停止并尝试还原。恢复记录保存在：" + str(backup_path)) from None
            return {"status": "repaired", "workspace": name, "removed_count": count,
                    "backup_path": str(backup_path),
                    "message": "已移走确认过期的浏览器运行锁，登录资料和个人 Chrome 未改动。请重新检查线路。"}
    except Blocked:
        raise
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise Blocked("工作区或锁路径包含符号链接或异常类型，未清理。") from None
        raise Blocked("无法安全访问浏览器运行锁，未清理；请先正常退出专用浏览器后重试。") from None

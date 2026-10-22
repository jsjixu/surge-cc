"""Conservative recovery of stopped, app-owned Chromium singleton links.

``repair`` only moves stale links. ``recover`` can first request a normal stop
of a verified, current-workspace dedicated browser. Neither resets a profile.
Workspace and account locks exclude snapshots, switches and new launches, while
exclusive OAuth and browser locks exclude profile preparation before Chromium
has started. Unrelated CLI sessions may continue;
browser databases and personal Chrome are untouched.
"""
from __future__ import annotations

from contextlib import ExitStack
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid

from .core import Blocked, now
from .workspaces import name_ok

_LINKS = ("SingletonLock", "SingletonSocket", "SingletonCookie")
_PROFILES = ("Browser", "OAuthBrowser")
_RUNTIME_LOCKS = (".session.lock", ".oauth.lock", ".browser.lock")
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


@dataclass(frozen=True)
class _BrowserProcess:
    pid: int
    uid: int
    started: tuple[int, int]
    executable: str
    argv: tuple[str, ...]


class _BSDInfo(ctypes.Structure):
    # macOS SDK sys/proc_info.h: PROC_PIDTBSDINFO / struct proc_bsdinfo.
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid",
        "rgid", "svuid", "svgid", "reserved")] + [
        ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)] + [
        (name, ctypes.c_uint32) for name in ("nfiles", "pgid", "jobc", "tdev", "tpgid")] + [
        ("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]


def _decode_argv(raw: bytes) -> tuple[str, ...]:
    """Decode only argc arguments; never include the following environment."""
    if len(raw) < 5:
        raise ValueError("short process arguments")
    argc = int.from_bytes(raw[:4], sys.byteorder, signed=True)
    if not 1 <= argc <= 4096:
        raise ValueError("invalid argument count")
    position = raw.index(b"\0", 4) + 1  # kernel executable path, then padding
    while position < len(raw) and raw[position] == 0:
        position += 1
    args = []
    for _ in range(argc):
        end = raw.index(b"\0", position)
        args.append(os.fsdecode(raw[position:end]))
        position = end + 1
    return tuple(args)


def _process_snapshot(pid: int) -> _BrowserProcess | None:
    """Read kernel executable, start identity and argv, rather than parse ps text.

    A process can disappear during the read. Any other failure is unknown, not
    permission to signal a PID. OAuth URLs may be in argv, so these snapshots
    remain memory-only and must never be written to logs or recovery manifests.
    """
    if sys.platform != "darwin" or type(pid) is not int or not 2 <= pid <= 2**31 - 1:
        raise Blocked("无法可靠验证专用浏览器进程；请正常退出专用窗口后重试。")
    try:
        lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                     ctypes.c_void_p, ctypes.c_int]
        lib.proc_pidinfo.restype = ctypes.c_int
        lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        lib.proc_pidpath.restype = ctypes.c_int
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        libc.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint,
                                ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                                ctypes.c_void_p, ctypes.c_size_t]
        libc.sysctl.restype = ctypes.c_int
        before, after = _BSDInfo(), _BSDInfo()
        if lib.proc_pidinfo(pid, 3, 0, ctypes.byref(before), ctypes.sizeof(before)) != ctypes.sizeof(before):
            raise OSError("process identity unavailable")
        path = ctypes.create_string_buffer(4096)
        if lib.proc_pidpath(pid, path, len(path)) <= 0:
            raise OSError("process executable unavailable")
        mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN / KERN_PROCARGS2
        size = ctypes.c_size_t()
        if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) or not 5 <= size.value <= 1024 * 1024:
            raise OSError("process arguments unavailable")
        buffer = ctypes.create_string_buffer(size.value)
        if libc.sysctl(mib, 3, buffer, ctypes.byref(size), None, 0):
            raise OSError("process arguments unavailable")
        argv = _decode_argv(bytes(buffer[:size.value]))
        if lib.proc_pidinfo(pid, 3, 0, ctypes.byref(after), ctypes.sizeof(after)) != ctypes.sizeof(after):
            raise OSError("process identity unavailable")
        fields = ("pid", "uid", "ruid", "start_sec", "start_usec")
        if any(getattr(before, key) != getattr(after, key) for key in fields) or before.pid != pid:
            raise OSError("process changed during observation")
        if before.uid != before.ruid:
            raise OSError("unexpected process ownership")
        return _BrowserProcess(pid, before.uid, (before.start_sec, before.start_usec),
                               os.fsdecode(path.value), argv)
    except (OSError, ValueError, AttributeError):
        if _pid_absent(pid):
            return None
        raise Blocked("无法可靠验证专用浏览器进程；未关闭任何无法确认的程序，请正常退出专用窗口。") from None


def _lock_pid(links: dict) -> int | None:
    if not links:
        return None
    value = links.get("SingletonLock", {}).get("target", "")
    match = re.fullmatch(r"([^/\x00]+)-([0-9]{1,10})", value)
    if (not match or match[1].casefold().rstrip(".") not in _local_hosts()
            or not 2 <= int(match[2]) <= 2**31 - 1):
        raise Blocked("专用浏览器锁来源或进程编号无法确认；未关闭程序，请正常退出专用窗口后重试。")
    return int(match[2])


def _owned_browser(process: _BrowserProcess, executable: Path, profile: Path) -> bool:
    return (process.uid == os.getuid() and process.executable == str(executable)
            and process.argv and process.argv[0] == str(executable)
            and [arg for arg in process.argv if arg.startswith("--user-data-dir")] ==
                ["--user-data-dir=" + str(profile)]
            and not any(arg.startswith("--type=") for arg in process.argv))


def _configured_browser(stack: ExitStack, base_fd: int, base: Path, config_path: Path) -> Path:
    fd = os.open(config_path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=base_fd)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > 1024 * 1024):
        raise Blocked("专用浏览器配置无法安全读取，未关闭程序。")
    try:
        config = json.loads(os.read(fd, info.st_size + 1))
    except (ValueError, UnicodeError):
        raise Blocked("专用浏览器配置无法完整读取，未关闭程序。") from None
    from .containment import _browser_identity
    if not isinstance(config, dict):
        raise Blocked("专用浏览器配置无法完整读取，未关闭程序。")
    expected, _, _ = _browser_identity(config, require_files=True)
    directory = _open_base(stack, expected.parent)
    executable = _lstat(directory, expected.name)
    if (executable is None or not stat.S_ISREG(executable.st_mode)
            or executable.st_uid != os.getuid() or executable.st_mode & 0o022
            or not executable.st_mode & 0o111):
        raise Blocked("专用浏览器程序的类型、权限或所有者异常，未关闭程序。")
    return expected


def recover(config_path: Path, name: str, *, timeout: float = 8) -> dict:
    """Normally stop only verified dedicated windows, then back up stale locks.

    SingletonLock supplies a candidate, not authority to kill it. The candidate
    must match kernel executable/UID/start identity and exact profile argv. No
    guard, terminal, CLI, helper, personal Chrome or other workspace is signaled.
    SIGTERM is the only shutdown request; a timeout preserves all runtime links.
    As with any PID-based OS API, the identity is checked immediately before the
    signal; callers must not treat this as a hostile same-user security boundary.
    """
    name_ok(name)
    if not 0 < timeout <= 30:
        raise Blocked("浏览器恢复等待时间无效。")
    config_path = Path(config_path).absolute()
    base = config_path.parent
    root = base / "workspaces" / name
    stopped = []
    try:
        with ExitStack() as stack:
            base_fd = _open_base(stack, base)
            workspaces_fd = _directory(stack, "workspaces", base_fd)
            root_fd = _directory(stack, name, workspaces_fd)
            data_fd = _directory(stack, "data", root_fd)
            _lock(stack, root_fd, ".browser-recovery.lock")
            profiles = {key: root / "data" / key for key in _PROFILES}
            descriptors, links, candidates = {}, {}, {}
            executable = None
            for key in _PROFILES:
                if _lstat(data_fd, key) is None:
                    continue
                descriptors[key] = _directory(stack, key, data_fd)
                links[key] = _read_links(descriptors[key])
                pid = _lock_pid(links[key])
                if pid is None or _pid_absent(pid):
                    continue
                if executable is None:
                    executable = _configured_browser(stack, base_fd, base, config_path)
                process = _process_snapshot(pid)
                if process is None:
                    continue
                if not _owned_browser(process, executable, profiles[key]):
                    raise Blocked("浏览器锁指向的程序不属于当前工作区专用窗口；未关闭它，请正常退出对应窗口后重试。")
                candidates[key] = process

            def recheck(key: str) -> None:
                with ExitStack() as verify:
                    current = _open_base(verify, profiles[key])
                    actual, expected = os.fstat(current), os.fstat(descriptors[key])
                    if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                        raise Blocked("浏览器目录在恢复期间发生变化，已停止；请重新检查。")
                if _read_links(descriptors[key]) != links[key]:
                    raise Blocked("浏览器运行锁在恢复期间发生变化，已停止；请重新检查。")

            # Validate every candidate before any shutdown, so a mismatched
            # OAuth PID does not partially close an otherwise healthy web tab.
            for key, process in candidates.items():
                recheck(key)
                current = _process_snapshot(process.pid)
                if current is None:
                    continue
                if current != process:
                    raise Blocked("浏览器进程身份在恢复期间发生变化，未发送关闭请求；请重新检查。")
                try:
                    os.kill(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    continue
                except OSError:
                    raise Blocked("系统未允许关闭专用窗口；请保存工作并正常退出该窗口后重试。") from None
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    try:
                        current = _process_snapshot(process.pid)
                    except Blocked:
                        # An exited but not yet reaped child can still satisfy
                        # kill(pid, 0) while macOS no longer exposes its argv or
                        # executable. Unknown is not stopped: let its owner reap
                        # it within the same bounded wait, without more signals.
                        time.sleep(0.1)
                        continue
                    if current is None:
                        stopped.append(key)
                        break
                    if current != process:
                        raise Blocked("浏览器进程身份已变化，未继续关闭或清锁；请重新检查。")
                    time.sleep(0.1)
                else:
                    raise Blocked("专用浏览器未在等待期限内退出；请保存工作并正常退出专用窗口，再点击恢复。未强制结束或清锁。")

            # Wait for the browser owner to release its leases. Share the
            # workspace lock with unrelated CLI sessions; exclusive workspace
            # operations still block, as do browser/OAuth profile leases.
            deadline = time.monotonic() + timeout
            while True:
                try:
                    with ExitStack() as held:
                        for lock in _RUNTIME_LOCKS:
                            _lock(held, root_fd, lock, allow_cli=lock == ".session.lock",
                                  workspace_root=root, config_path=config_path)
                    break
                except Blocked as exc:
                    if "仍在运行" not in str(exc):
                        raise
                    if time.monotonic() >= deadline:
                        raise Blocked("当前工作区仍有浏览器、授权或备份操作占用；请先结束该操作再恢复。专用窗口已请求正常关闭，登录资料未清理。") from None
                    time.sleep(0.1)
            if executable is not None:
                _assert_stopped(base, dict(profiles, runtime=executable.parents[2]))
            result = repair(config_path, name)
            result["stopped_profiles"] = stopped
            if stopped:
                result.update(status="recovered", message="已正常关闭当前工作区专用窗口并检查残留锁；登录资料已保留。可以重新检查线路。")
            return result
    except Blocked:
        raise
    except OSError:
        raise Blocked("无法安全访问专用浏览器恢复目录，未继续操作；请正常退出专用窗口后重试。") from None


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


def _lock(stack: ExitStack, root_fd: int, name: str, *, allow_cli: bool = False,
          workspace_root: Path | None = None, config_path: Path | None = None) -> tuple[int, tuple]:
    fd = os.open(name, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                 0o600, dir_fd=root_fd)
    startup_gate = ExitStack()
    # ExitStack unwinds in reverse: close our session fd before releasing the
    # startup gate, so even cleanup has no repair-only SH admission window.
    stack.callback(startup_gate.close)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_mode & 0o022):
        raise Blocked("工作区锁的类型、所有者或链接数量异常，未清理。")
    try:
        if allow_cli:
            if name != ".session.lock" or workspace_root is None or config_path is None:
                raise Blocked("共享工作区锁缺少所属工作区，未清理。")
            from .sessions import assert_no_stop_failures
            # Retain EX when idle, including stop_workspace callers that
            # already own the account gate. Do not downgrade across a gap.
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                from .workspaces import account_lock
                # A repair-only SH holder must never let another launcher
                # mistake it for a healthy session and skip orphan checks.
                # Keep the startup gate even if the last real CLI exits.
                startup_gate.enter_context(account_lock(config_path, exclusive=True))
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                assert_no_stop_failures(workspace_root, include_pending=False)
            else:
                assert_no_stop_failures(workspace_root)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise Blocked("专用浏览器、授权或工作区操作仍在运行；请先正常退出后再修复。") from None
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
            # Retain every lease, including the account gate when sharing the
            # workspace with existing CLI sessions, through moves and rollback.
            locks = {key: _lock(stack, root_fd, key, allow_cli=key == ".session.lock",
                               workspace_root=root_path, config_path=config_path)
                     for key in _RUNTIME_LOCKS}
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

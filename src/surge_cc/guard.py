"""Supervise only a child started here; this is polling, not a network firewall."""
from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

from .core import (
    Blocked, Surge, listener_is_surge, load_config, now, proxy_env,
    route_is_fixed, run_checks, validate_config, validate_topology,
)


class Interrupted(Exception):
    def __init__(self, signum: int):
        self.signum = signum


class RuntimeChecker:
    """Keep baseline material in memory; never persist an effective profile."""

    def __init__(self, config: dict, *, process: str, surge=None, listener=listener_is_surge):
        self.config = validate_config(config)
        self.process = process
        self.surge = surge or Surge()
        self.listener = listener
        status, group, digest = self._snapshot()
        self.path = status.get("profile-path")
        self.group = group
        self.digest = digest

    def _snapshot(self):
        status = self.surge.status()
        if not isinstance(status.get("features"), dict) or status.get("mode") != "rule":
            raise Blocked("运行期间 Surge 状态未知或已离开规则模式。")
        if self.config.get("browser_path") and status["features"].get("enhanced-mode") is not True:
            raise Blocked("专用浏览器的增强模式接管已停止或无法确认。")
        active_path = status.get("profile-path")
        if not isinstance(active_path, str) or not active_path:
            raise Blocked("运行期间无法确认 Surge 的生效配置。")
        if self.config["profile_path"] and active_path != self.config["profile_path"]:
            raise Blocked("运行期间 Surge 配置文件已切换。")
        group = self.surge.group(self.config["group"])
        profile = self.surge.profile()
        validate_topology(profile, group, self.config)
        if group.get("selected") != self.config["policy"]:
            raise Blocked("运行期间固定节点已改变。")
        digest = hashlib.sha256(profile.encode("utf-8")).digest()
        return status, group, digest

    def check(self, *, include_exit: bool = False) -> None:
        status, group, digest = self._snapshot()
        if self.config.get("browser_path"):
            from .containment import validate_scope
            validate_scope(self.config, self.surge)
        if (status.get("profile-path") != self.path or group != self.group or
                digest != self.digest):
            raise Blocked("运行期间 Surge 策略或生效配置发生变化。")
        if not self.listener(self.config):
            raise Blocked("运行期间本地代理入口不再属于 Surge，或无法确认入口。")
        for host in self.config["hosts"]:
            if not route_is_fixed(self.surge.route(host, self.config, self.process), self.config):
                raise Blocked("运行期间 Claude 域名不再固定到指定线路。")
        if include_exit and self.surge.exit_matches(self.config) is not True:
            raise Blocked("运行期间出口变化或出口检测无法确认。")
        # Re-read after asynchronous route/exit checks rather than bless stale state.
        status, group, digest = self._snapshot()
        if (status.get("profile-path") != self.path or group != self.group or
                digest != self.digest):
            raise Blocked("运行期间检查尚未结束，Surge 配置已发生变化。")


def write_state(path: Path | None, *, target: str, state: str, ok: bool, detail: str) -> None:
    """Write a small private receipt without config, command arguments, or PID."""
    if path is None:
        return
    path = Path(path)
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents if parent.exists())):
        raise Blocked("守护状态文件位置无效或包含符号链接。")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and not path.is_file():
        raise Blocked("守护状态文件位置无效。")
    payload = {"schema": 1, "target": target, "state": state, "ok": bool(ok),
               "checked_at": now(), "detail": detail}
    fd, temporary = tempfile.mkstemp(prefix=".surge-cc-guard-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(payload, handle, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def session_lock(path: Path | None):
    """Hold a shared lock so snapshot/restore can require an exclusive lock."""
    if path is None:
        yield
        return
    path = Path(path)
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents if parent.exists())):
        raise Blocked("工作区锁文件位置无效或包含符号链接。")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = None
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise Blocked("工作区锁文件的类型或所有者异常。")
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Blocked("工作区正在备份或恢复，暂时不能启动。") from None
        yield
    finally:
        if fd is not None:
            os.close(fd)


@contextmanager
def child_signals(child_getter=lambda: None, *, killpg=os.killpg, getpgid=os.getpgid):
    """Forward terminal cancel/resize; terminate the owned child on parent shutdown."""
    installed = {}
    if threading.current_thread() is threading.main_thread():
        def handler(signum, frame):
            if signum in (signal.SIGINT, signal.SIGWINCH):
                child = child_getter()
                if child is not None and child.poll() is None:
                    try:
                        if child.pid > 1 and getpgid(child.pid) == child.pid:
                            killpg(child.pid, signum)
                            return
                    except ProcessLookupError:
                        return
                if signum == signal.SIGWINCH:
                    return
            raise Interrupted(signum)
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGWINCH):
            installed[signum] = signal.getsignal(signum)
            signal.signal(signum, handler)
    try:
        yield
    finally:
        for signum, previous in installed.items():
            signal.signal(signum, previous)


def stop_owned_child(child, *, grace: float = 2.0, killpg=os.killpg, getpgid=os.getpgid) -> None:
    """Accept an owned Popen handle, never a saved/user-provided PID or process name."""
    if child is None or child.poll() is not None:
        return
    pid = child.pid
    if not isinstance(pid, int) or pid <= 1 or pid == os.getpid():
        raise Blocked("无法确认受监控进程身份，未向其他进程发送信号。")
    try:
        if getpgid(pid) != pid:
            # Each child is started in its own new session. Do not ever kill a
            # surrounding terminal or unrelated shared group if this changed.
            child.terminate()
            child.wait(timeout=grace)
            return
        killpg(pid, signal.SIGTERM)
        try:
            child.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            # poll/getpgid must still identify our live leader before escalation.
            if child.poll() is None and getpgid(pid) == pid:
                killpg(pid, signal.SIGKILL)
            child.wait(timeout=grace)
    except ProcessLookupError:
        return
    except subprocess.TimeoutExpired:
        raise Blocked("受监控程序未在停止期限内退出，请在应用中手动关闭它。") from None


def supervise(child, checker, *, target: str, status_path: Path | None = None,
              interval: float = 10.0, exit_interval: float = 30.0,
              clock=time.monotonic, sleep=time.sleep) -> int:
    """Poll until the owned child exits. Any unknown/failure stops that child."""
    if not 0 < interval <= 60 or not interval <= exit_interval <= 300:
        raise Blocked("守护检查间隔无效。")
    last_exit = clock()
    next_check = clock() + interval
    while True:
        code = child.poll()
        if code is not None:
            write_state(status_path, target=target, state="exited", ok=code == 0,
                        detail="本工具启动的程序已退出，运行期监控已结束。")
            return code if code >= 0 else 128 - code
        current = clock()
        if current >= next_check:
            full = current - last_exit >= exit_interval
            checker.check(include_exit=full)
            if full:
                last_exit = clock()
            write_state(status_path, target=target, state="running", ok=True,
                        detail="运行期线路检查通过；轮询检测不保证即时阻断网络流量。")
            next_check = clock() + interval
        else:
            sleep(min(0.2, next_check - current))


def run_guarded(command: list[str], *, env: dict | None, cwd: Path,
                config: dict, target: str, receipt_path: Path | None = None,
                status_path: Path | None = None, interval: float = 10.0,
                exit_interval: float = 30.0, preflight=run_checks,
                checker=None, popen=subprocess.Popen, monitor=supervise,
                stop=stop_owned_child, lock_path: Path | None = None,
                on_started=None) -> int:
    """Synchronous owner for CLI or a detached web worker; returns an exit code."""
    child = None
    launched = False
    detail = "线路预检尚未完成。"
    state = "blocked"
    code = 2
    locks = ExitStack()
    try:
        config = validate_config(config)
        if target not in {"code", "web"}:
            raise Blocked("不支持的守护目标。")
        if (not isinstance(command, list) or not command or
                any(not isinstance(item, str) or "\0" in item for item in command) or
                not Path(command[0]).is_absolute()):
            raise Blocked("守护程序必须使用完整的可执行文件路径。")
        cwd = Path(cwd)
        if not cwd.is_absolute() or not cwd.is_dir():
            raise Blocked("项目文件夹不存在。")
        if not 0 < interval <= 60 or not interval <= exit_interval <= 300:
            raise Blocked("守护检查间隔无效。")
        locks.enter_context(session_lock(lock_path))
        report = preflight(config)
        if not isinstance(report, dict) or report.get("ok") is not True:
            raise Blocked("启动前线路检查未通过，已阻止启动。")
        checker = checker or RuntimeChecker(config, process=command[0])
        checker.check(include_exit=True)
        # Verify state paths before starting a program. Failure to report must not
        # leave a detached unmonitored child behind.
        write_state(status_path, target=target, state="starting", ok=True,
                    detail="线路检查通过，正在启动受监控程序。")
        with child_signals(lambda: child):
            child = popen(command, env=env, cwd=str(cwd), start_new_session=True)
            if on_started is not None:
                on_started(child)
            # A launcher that immediately hands off/exits must not count as an
            # owned browser session. Normal CLI fast completion is allowed.
            if target == "web":
                try:
                    child.wait(timeout=0.8)
                except subprocess.TimeoutExpired:
                    pass
                else:
                    raise Blocked("专用浏览器未保持运行；没有建立受监控会话。")
            launched = True
            detail = "已启动并开始运行期线路监控；检测存在轮询间隔。"
            write_state(receipt_path, target=target, state="running", ok=True, detail=detail)
            write_state(status_path, target=target, state="running", ok=True, detail=detail)
            code = monitor(child, checker, target=target, status_path=status_path,
                           interval=interval, exit_interval=exit_interval)
            state = "exited"
            detail = "本工具启动的程序已退出，运行期监控已结束。"
    except Interrupted as exc:
        code = 128 + exc.signum
        state, detail = "stopped", "运行期监控收到停止请求，已停止它启动的程序。"
    except KeyboardInterrupt:
        code = 130
        state, detail = "stopped", "运行期监控收到停止请求，已停止它启动的程序。"
    except Blocked as exc:
        state, detail = "blocked", str(exc)
    except Exception:
        # Do not expose command arguments, subprocess output or profile material.
        state, detail = "blocked", "运行期监控发生未知错误，已按失败处理并停止受监控程序。"
    finally:
        try:
            stop(child)
        except Exception:
            state, detail, code = "stop_failed", "无法确认受监控程序已退出，请手动关闭本工具启动的窗口。", 2
        try:
            write_state(status_path, target=target, state=state, ok=state == "exited" and code == 0,
                        detail=detail)
            if not launched:
                write_state(receipt_path, target=target, state=state, ok=False, detail=detail)
        except Exception:
            code = 2
        locks.close()
    return code


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Surge CC owned-process runtime guard")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--status", type=Path)
    parser.add_argument("--cwd", type=Path, required=True)
    parser.add_argument("--target", choices=("code", "web"), required=True)
    parser.add_argument("--lock", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        config = load_config(args.config)
    except Blocked as exc:
        for path in (args.receipt, args.status):
            try:
                write_state(path, target=args.target, state="blocked", ok=False, detail=str(exc))
            except Blocked:
                pass
        return 2
    return run_guarded(command, env=proxy_env(config["proxy_url"]), cwd=args.cwd,
                       config=config, target=args.target,
                       receipt_path=args.receipt, status_path=args.status, lock_path=args.lock,
                       interval=config["guard_interval"], exit_interval=max(30, config["guard_interval"]))


if __name__ == "__main__":
    sys.exit(main())

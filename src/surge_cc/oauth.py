"""A private, CLI-owned browser opener. Authorization URLs stay in memory."""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import fcntl
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from urllib.parse import parse_qsl, unquote, urlsplit

from . import core, workspaces
from .core import Blocked, BrowserProfileBusy
from .guard import session_lock, stop_owned_child


AUTHORIZE_ENDPOINTS = {
    ("claude.com", "/cai/oauth/authorize"),
    ("platform.claude.com", "/oauth/authorize"),
    ("claude.ai", "/oauth/authorize"),
    ("console.anthropic.com", "/oauth/authorize"),
}
MAX_MESSAGE = 32768


def authorization_candidate(value: str) -> bool:
    """Keep malformed Claude OAuth requests out of the ordinary-page path.

    Classification is deliberately broader than validation. Encoded paths,
    trailing dots/slashes, wrong ports and non-HTTPS variants must still take
    the strict validator, without earning its temporary callback exception.
    """
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        if host not in {host for host, _ in AUTHORIZE_ENDPOINTS}:
            return False
        path = parsed.path
        for _ in range(3):
            path = unquote(path)
        path = path.lower().rstrip("/")
        if path.endswith("/oauth/authorize"):
            return True
        # A damaged endpoint with an authorization query is still an OAuth
        # attempt, rather than a normal page that can bypass its validation.
        keys = {key for key, _ in parse_qsl(parsed.query, max_num_fields=64)}
        return bool(keys & {"response_type", "code_challenge", "redirect_uri"})
    except (ValueError, TypeError, UnicodeError):
        return False  # The ordinary URL validator rejects malformed syntax.


@dataclass(frozen=True)
class Authorization:
    url: str
    callback_host: str
    callback_port: int


def validate_authorization_url(value: str) -> Authorization:
    """Validate without rewriting the OAuth URL, its state, or its PKCE data."""
    try:
        if (not isinstance(value, str) or not 1 <= len(value) <= 16384
                or any(ord(c) <= 32 or ord(c) == 127 for c in value)
                or any(ord(c) < 32 or ord(c) == 127 for c in unquote(value))
                or "#" in value or "\\" in value):
            raise ValueError()
        url = urlsplit(value)
        if (url.scheme != "https" or url.username is not None or url.password is not None
                or url.port not in (None, 443)
                or (url.hostname, url.path) not in AUTHORIZE_ENDPOINTS):
            raise ValueError()
        pairs = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True,
                          max_num_fields=32)
        query = dict(pairs)
        if len(query) != len(pairs):
            raise ValueError()
        if (query.get("response_type") != "code"
                or query.get("code_challenge_method") != "S256"
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,512}", query.get("state", ""))
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", query.get("code_challenge", ""))):
            raise ValueError()
        callback_text = query.get("redirect_uri", "")
        callback = urlsplit(callback_text)
        if (callback.scheme != "http" or callback.hostname not in {"localhost", "127.0.0.1", "::1"}
                or callback.username is not None or callback.password is not None
                or callback.path != "/callback" or callback.query or callback.fragment
                or callback.port is None or not 1024 <= callback.port <= 65535):
            raise ValueError()
        callback_host = "[::1]" if callback.hostname == "::1" else callback.hostname
        if callback_text != f"http://{callback_host}:{callback.port}/callback":
            raise ValueError()
        return Authorization(value, callback.hostname, callback.port)
    except (ValueError, TypeError, UnicodeError):
        raise Blocked("授权链接格式或回调地址不符合专用浏览器要求，未打开。") from None


def callback_owned_by(child, port: int, *, run=subprocess.run) -> bool:
    """Require a live owned CLI process listening on loopback at this exact port."""
    if child is None or child.poll() is not None:
        return False
    pid = child.pid
    if type(pid) is not int or pid <= 1 or pid == os.getpid():
        return False
    try:
        result = run(
            ["/usr/sbin/lsof", "-nP", "-a", "-p", str(pid), "-iTCP:" + str(port),
             "-sTCP:LISTEN", "-Fpn"], capture_output=True, text=True, timeout=5,
            check=False)
        if result.returncode != 0 or child.poll() is not None:
            return False
        owners, addresses = set(), []
        for line in result.stdout.splitlines():
            if line.startswith("p"):
                owners.add(line[1:])
            elif line.startswith("n"):
                addresses.append(line[1:])
        return owners == {str(pid)} and bool(addresses) and all(
            a in {f"127.0.0.1:{port}", f"[::1]:{port}"} for a in addresses)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def oauth_browser_args(config: dict, profile: Path, authorization: Authorization) -> list[str]:
    args = core.chrome_args(config, profile)
    host = ("[::1]" if authorization.callback_host == "::1" else authorization.callback_host)
    bypass = [f"http://{host}:{authorization.callback_port}"]
    if authorization.callback_host == "localhost":
        bypass.append(f"http://127.0.0.1:{authorization.callback_port}")
    for i, arg in enumerate(args):
        if arg.startswith("--proxy-bypass-list="):
            args[i] = "--proxy-bypass-list=<-loopback>;" + ";".join(bypass)
    args[-1] = authorization.url
    return args


def _read_message(connection: socket.socket) -> dict:
    data = bytearray()
    while len(data) <= MAX_MESSAGE:
        chunk = connection.recv(min(4096, MAX_MESSAGE + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if len(data) > MAX_MESSAGE or not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise ValueError("Invalid message")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ValueError("Invalid message")
    return result


def _hook_source(socket_path: str, token: str, *, open_command: bool = False) -> str:
    # This file contains neither a current authorization URL nor a shell command.
    if any(c.isspace() for c in sys.executable):
        raise Blocked("Python 路径无法用作专用授权入口，未启动。")
    return f"""#!{sys.executable}
import json, socket, sys
try:
    args = sys.argv[1:]
    if {open_command!r} and args[:1] == ["--"]:
        args = args[1:]
    if len(args) != 1 or args[0].startswith("-"):
        raise ValueError()
    packet = json.dumps({{"token": {token!r}, "url": args[0]}}, ensure_ascii=True).encode() + b"\\n"
    if len(packet) > {MAX_MESSAGE}:
        raise ValueError()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(300)
        connection.connect({socket_path!r})
        connection.sendall(packet)
        data = bytearray()
        while len(data) <= 1024:
            chunk = connection.recv(1024)
            if not chunk:
                break
            data.extend(chunk)
            if b"\\n" in chunk:
                break
        result = json.loads(data)
        if isinstance(result, dict) and result.get("error") == "browser-busy":
            sys.stderr.write("Surge CC 的专用网页或授权窗口正在使用同一份登录资料。请关闭专用窗口后重试；不会改用空白资料或个人 Chrome。\\n")
            sys.exit(2)
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise ValueError()
except Exception:
    sys.stderr.write("Surge CC 未能打开专用浏览器；只接受单个 HTTP(S) 网页链接，未使用系统浏览器。\\n")
    sys.exit(2)
sys.exit(0)
"""


class OAuthSession:
    """One local CLI owns this broker and every browser process it launches."""

    def __init__(self, config: dict, config_path: Path, *, checker=None, popen=subprocess.Popen,
                 allow_authorization: bool = True, focus_executable: Path | None = None):
        self.config = dict(config)
        self.config_path = Path(config_path).absolute()
        self.checker = checker
        self.popen = popen
        self.allow_authorization = allow_authorization
        self.focus_executable = (Path(focus_executable) if focus_executable is not None
                                 else Path(__file__).resolve().parents[2] / "SurgeCCShortcut")
        self.child = None
        self.browser = None
        self.browser_hook = None
        self.open_hook = None
        self._folder = None
        self._socket = None
        self._thread = None
        self._profile_lock = None
        self._profile = None
        self._locks = None
        self._token = secrets.token_urlsafe(32)
        self._closing = threading.Event()
        self._ready = threading.Event()
        self._state = threading.RLock()

    def __enter__(self):
        if (not self.config.get("browser_path")
                or core.browser_executable(self.config).resolve() == core.CHROME.resolve()):
            raise Blocked("授权接管需要已配置的 Surge CC 独立浏览器。")
        if self.checker is None:
            # Imported lazily: cli itself imports this module for launch.
            from .cli import oauth_checks
            self.checker = oauth_checks
        try:
            # Darwin's per-user TMPDIR may exceed sockaddr_un's 104-byte limit.
            self._folder = Path(tempfile.mkdtemp(prefix="surge-cc-oauth-", dir="/private/tmp"))
            self._folder.chmod(0o700)
            socket_path = str(self._folder / "s")
            self.browser_hook = self._folder / "browser"
            self.browser_hook.write_text(_hook_source(socket_path, self._token), encoding="utf-8")
            self.browser_hook.chmod(0o700)
            # Only controlled child processes receive this PATH entry. Never
            # replace /usr/bin/open or modify the user's shell configuration.
            self.open_hook = self._folder / "open"
            self.open_hook.write_text(_hook_source(socket_path, self._token, open_command=True), encoding="utf-8")
            self.open_hook.chmod(0o700)
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._socket.bind(socket_path)
            os.chmod(socket_path, 0o600)
            self._socket.listen(4)
            self._socket.settimeout(0.25)
            self._thread = threading.Thread(target=self._serve, name="surge-cc-oauth", daemon=True)
            self._thread.start()
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def child_environment(self, base: dict) -> dict:
        if self._folder is None or self.browser_hook is None or self._closing.is_set():
            raise Blocked("专用网页入口尚未就绪，未启动 Claude Code。")
        env = dict(base)
        env["BROWSER"] = str(self.browser_hook)
        previous = env.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        env["PATH"] = str(self._folder) + (os.pathsep + previous if previous else "")
        return env

    def set_child(self, child):
        with self._state:
            if self._closing.is_set() or self.child is not None or child.poll() is not None:
                raise Blocked("授权接管无法绑定当前 Claude Code 进程。")
            self.child = child
            self._ready.set()

    def _live(self) -> bool:
        return (not self._closing.is_set() and self.child is not None
                and self.child.poll() is None)

    def _require_live(self):
        if not self._live():
            raise Blocked("网页会话已结束，未打开链接。")

    def _check(self):
        if not self._live():
            raise Blocked("授权会话已结束，未打开浏览器。")
        report = self.checker(self.config)
        if (not isinstance(report, dict) or
                (report.get("ok") is not True and not core.global_mode_allowed(report)) or not self._live()):
            raise Blocked("授权前线路检查未通过，未使用其他浏览器。")

    def _lock_profile(self):
        if self._profile_lock is not None:
            return
        root = workspaces.location(self.config_path, self.config["workspace"])
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock = root / ".oauth.lock"
        locks = ExitStack()
        try:
            # Keep snapshot/restore excluded even after the CLI guard has ended,
            # until this context has confirmed its own browser has stopped.
            locks.enter_context(session_lock((root / ".session.lock").absolute()))
            fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            locks.callback(os.close, fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise Blocked("授权浏览器锁文件异常。")
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise BrowserProfileBusy("专用授权窗口正在使用登录资料。请关闭专用窗口后重试。") from None
            profile = locks.enter_context(workspaces.browser_session(root, self.config))
            self._profile_lock = fd
            self._profile = profile
            self._locks = locks
        except BaseException:
            locks.close()
            raise

    def _release_profile(self):
        locks, self._locks = self._locks, None
        self._profile_lock = None
        self._profile = None
        if locks is not None:
            locks.close()

    def _stop_browser(self, *, release=True):
        if self.browser is not None:
            stop_owned_child(self.browser)
            if self.browser.poll() is None:
                raise Blocked("未确认专用授权窗口已关闭，请手动检查。")
            self.browser = None
        if release:
            self._release_profile()

    def _open_authorization(self, value: str):
        if self.allow_authorization is not True:
            raise Blocked("当前使用钥匙串长效 Token；网页授权已停用，请先显式切回 OAuth 登录模式。")
        authorization = validate_authorization_url(value)
        started = None
        try:
            self._check()
            if not callback_owned_by(self.child, authorization.callback_port):
                raise Blocked("授权回调端口不属于本次 Claude Code，未打开。")
            with self._state:
                if not self._live():
                    raise Blocked("授权会话已结束。")
                self._stop_browser(release=False)
                self._lock_profile()
                profile = self._profile
                if profile.is_symlink():
                    raise Blocked("专用授权资料目录异常，未启动浏览器。")
                if os.path.lexists(profile / "SingletonLock"):
                    raise BrowserProfileBusy("专用授权资料已被占用或留有锁，请在 Surge CC 中检查并修复浏览器锁。")
                if not self._live() or not callback_owned_by(self.child, authorization.callback_port):
                    raise Blocked("授权回调已经失效。")
                started = self.popen(
                    oauth_browser_args(self.config, profile, authorization),
                    env=core.proxy_env(self.config["proxy_url"]),
                    cwd=str(self.config_path.parent), stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                self.browser = started
            # A handoff to some pre-existing browser is never successful ownership.
            try:
                started.wait(timeout=0.8)
            except subprocess.TimeoutExpired:
                pass
            else:
                raise Blocked("没有建立独立授权浏览器进程。")
            self._check()
            with self._state:
                if not self._live() or self.browser is not started or started.poll() is not None:
                    raise Blocked("专用授权窗口已停止。")
        except BaseException:
            with self._state:
                if started is None or self.browser is started:
                    self._stop_browser()
            raise

    def _open_web(self, value: str):
        from . import shortcuts, web_urls
        web_urls.validate_url(value)
        # The shared page opener reloads the workspace's current config and
        # performs the route check under its account gate. Repeating the OAuth
        # checker here would use this CLI's older config and double the probes.
        self._require_live()
        with self._state:
            if not self._live():
                raise Blocked("网页会话已结束，未打开浏览器。")
            if self.browser is not None:
                if self.browser.poll() is None:
                    raise BrowserProfileBusy("专用授权窗口正在使用登录资料。请关闭专用窗口后重试。")
                self.browser = None
                self._release_profile()
        # Route verification can be slow. Let shutdown mark this broker closed
        # without waiting on its state lock; the delivery callback then rejects
        # the request immediately before the browser receives any URL.
        result = shortcuts.open_url(self.config_path, self.config["workspace"], value,
                                    focus_executable=self.focus_executable,
                                    before_delivery=self._require_live)
        # A CLI is bound to its starting account. Never approve an account
        # switch or default-browser fallback from a background request.
        if (not isinstance(result, dict) or result.get("ok") is not True
                or result.get("opened") is not True or result.get("action") == "needs_switch"):
            raise Blocked("专用网页未能在当前工作区打开，未切换账号或浏览器。")
        # Ordinary pages have their own guarded lifetime. They must not become
        # this OAuth broker's owned child and close when the CLI ends.

    def _open(self, value: str):
        if authorization_candidate(value):
            self._open_authorization(value)
        else:
            self._open_web(value)

    def _serve(self):
        while not self._closing.is_set():
            try:
                connection, _ = self._socket.accept()
            except socket.timeout:
                with self._state:
                    if self.browser is not None and self.browser.poll() is not None:
                        self.browser = None
                        self._release_profile()
                continue
            except OSError:
                break
            with connection:
                ok = False
                error = None
                try:
                    connection.settimeout(5)
                    message = _read_message(connection)
                    if (set(message) != {"token", "url"}
                            or not isinstance(message["token"], str)
                            or not hmac.compare_digest(message["token"], self._token)):
                        raise ValueError("Unauthorized")
                    if not self._ready.wait(timeout=5) or not self._live():
                        raise ValueError("Not ready")
                    self._open(message["url"])
                    ok = True
                except BrowserProfileBusy:
                    # A fixed error code is actionable without disclosing any
                    # URL, account, token, process argument or raw exception.
                    error = "browser-busy"
                except Exception:
                    # Do not return exception text: it may contain the OAuth URL.
                    pass
                try:
                    response = {"ok": ok}
                    if error is not None:
                        response["error"] = error
                    connection.sendall(json.dumps(response).encode() + b"\n")
                except OSError:
                    pass

    def __exit__(self, exc_type, exc, traceback):
        self._closing.set()
        self._ready.set()
        if self._socket is not None:
            self._socket.close()
        try:
            with self._state:
                self._stop_browser()
        finally:
            if self._thread is not None and self._thread is not threading.current_thread():
                self._thread.join(timeout=1)
            if self._folder is not None:
                shutil.rmtree(self._folder, ignore_errors=True)
        return False

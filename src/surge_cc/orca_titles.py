"""A per-launch, least-authority bridge for Orca's local tab title hooks.

The isolated agent gets one short-lived Unix socket, never Orca's general hook
credential or CLI. The host fixes the destination pane and project before launch.
Only lifecycle events and the first 512 characters of a submitted prompt cross
this bridge; transcripts, tool payloads and host responses never do.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

from .core import Blocked
from . import orca_integration

MAX_INPUT = 64 * 1024
MAX_PROMPT = 512
_EVENTS = frozenset(("SessionStart", "UserPromptSubmit", "Stop", "SessionEnd"))
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_SAFE_ASCII = re.compile(r"[!-~]{1,256}\Z")
_ENDPOINT_KEYS = frozenset(("ORCA_AGENT_HOOK_PORT", "ORCA_AGENT_HOOK_TOKEN",
                            "ORCA_AGENT_HOOK_TRANSPORT"))
_ENDPOINT_METADATA = frozenset(("ORCA_AGENT_HOOK_ENV", "ORCA_AGENT_HOOK_VERSION",
                                "ORCA_AGENT_HOOK_OPENCODE_TUI"))
_BIND_ERROR = "未能核验 Orca 标题桥接的本机终端；保留文件隔离，不加载宿主 hooks。"


@dataclass(frozen=True)
class Binding:
    port: int
    token: str = field(repr=False)
    pane_key: str
    tab_id: str
    worktree_id: str
    launch_token: str = ""
    environment: str = "production"
    version: str = "1"


def _ascii(value, *, empty=False):
    return isinstance(value, str) and ((empty and value == "") or _SAFE_ASCII.fullmatch(value) is not None)


def _validate_binding(binding):
    if (not isinstance(binding, Binding) or type(binding.port) is not int
            or not 1024 <= binding.port <= 65535 or not _ascii(binding.token)
            or not _UUID.fullmatch(binding.tab_id)
            or not isinstance(binding.pane_key, str)
            or not binding.pane_key.startswith(binding.tab_id + ":")
            or not _UUID.fullmatch(binding.pane_key[len(binding.tab_id) + 1:])
            or not isinstance(binding.worktree_id, str) or not 1 <= len(binding.worktree_id) <= 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in binding.worktree_id)
            or not _ascii(binding.launch_token, empty=True)
            or binding.environment != "production" or binding.version != "1"):
        raise ValueError("invalid Orca binding")


def _endpoint_values(path: Path) -> dict:
    # Import lazily: isolation imports this module to construct the bridge.
    from .isolation import _safe_file
    content = _safe_file(path, private=True, limit=4096)
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        words = shlex.split(line, comments=True, posix=True)
        if words and words[0] == "export":
            words = words[1:]
        if len(words) != 1 or "=" not in words[0]:
            raise ValueError("invalid endpoint metadata")
        key, value = words[0].split("=", 1)
        if key not in _ENDPOINT_KEYS | _ENDPOINT_METADATA or key in result or not _ascii(value):
            raise ValueError("unexpected endpoint assignment")
        result[key] = value
    if (result.get("ORCA_AGENT_HOOK_ENV", "production") != "production"
            or result.get("ORCA_AGENT_HOOK_VERSION", "1") != "1"):
        raise ValueError("unsupported endpoint metadata")
    return result


def bind(project, inherited=None, runner=subprocess.run) -> Binding | None:
    """Capture a verified local pane; never import the real HOME's settings."""
    env = os.environ if inherited is None else inherited
    if not isinstance(env, dict) and not hasattr(env, "get"):
        raise Blocked(_BIND_ERROR)
    if not any(env.get(key) for key in ("ORCA_PANE_KEY", "ORCA_TAB_ID", "ORCA_WORKTREE_ID")):
        return None
    try:
        if env.get("ORCA_ENVIRONMENT") or env.get("ORCA_PAIRING_CODE"):
            raise ValueError("remote environment")
        values = {key: env.get(key, "") for key in _ENDPOINT_KEYS}
        endpoint = env.get("ORCA_AGENT_HOOK_ENDPOINT")
        if endpoint:
            expected = Path.home() / "Library/Application Support/orca/agent-hooks/endpoint.env"
            if endpoint != str(expected):
                raise ValueError("unexpected endpoint path")
            values.update(_endpoint_values(expected))
        if values.get("ORCA_AGENT_HOOK_TRANSPORT") != "raw-json-v1":
            raise ValueError("unsupported hook transport")
        port = values.get("ORCA_AGENT_HOOK_PORT", "")
        if not isinstance(port, str) or not re.fullmatch(r"[1-9][0-9]{3,4}", port):
            raise ValueError("invalid endpoint port")
        binding = Binding(port=int(port), token=values.get("ORCA_AGENT_HOOK_TOKEN", ""),
                          pane_key=env.get("ORCA_PANE_KEY", ""), tab_id=env.get("ORCA_TAB_ID", ""),
                          worktree_id=env.get("ORCA_WORKTREE_ID", ""),
                          launch_token=env.get("ORCA_AGENT_LAUNCH_TOKEN", ""),
                          environment=env.get("ORCA_AGENT_HOOK_ENV", ""),
                          version=env.get("ORCA_AGENT_HOOK_VERSION", ""))
        _validate_binding(binding)
        root = Path(project.root)
        if not root.is_absolute() or root.resolve(strict=True) != root or not root.is_dir():
            raise ValueError("invalid project root")
        # Explicit path prevents inherited CLI overrides from choosing a script.
        cli = orca_integration._cli_path("/usr/local/bin/orca")
        result = orca_integration._request(cli, ["terminal", "list"], runner)
        records = result.get("terminals")
        if not isinstance(records, list) or result.get("truncated") is True:
            raise ValueError("incomplete terminal inventory")
        matches = [item for item in records if isinstance(item, dict)
                   and item.get("executionHostId") == "local" and item.get("connected") is True
                   and item.get("orphaned") is not True
                   and item.get("worktreePath") == str(root)
                   and item.get("worktreeId") == binding.worktree_id
                   and item.get("tabId") == binding.tab_id
                   and item.get("leafId") == binding.pane_key.split(":", 1)[1]]
        if len(matches) != 1:
            raise ValueError("pane is not the verified project terminal")
        return binding
    except (OSError, ValueError, TypeError, AttributeError, Blocked):
        raise Blocked(_BIND_ERROR) from None


def _sanitize(payload) -> dict:
    if not isinstance(payload, dict) or payload.get("hook_event_name") not in _EVENTS:
        raise ValueError("unsupported hook event")
    session = payload.get("session_id")
    if not isinstance(session, str) or not _UUID.fullmatch(session):
        raise ValueError("missing session binding")
    event = payload["hook_event_name"]
    result = {"hook_event_name": event, "session_id": session.lower()}
    if event == "UserPromptSubmit":
        prompt = payload.get("prompt")
        if not isinstance(prompt, str):
            raise ValueError("missing prompt")
        result["prompt"] = prompt[:MAX_PROMPT]
    elif event == "SessionStart":
        source = payload.get("source", "startup")
        if source not in {"startup", "resume", "clear"}:
            raise ValueError("unsupported session source")
        result["source"] = source
    return result


def _hook_source(socket_path: str, token: str) -> str:
    if any(c.isspace() for c in sys.executable):
        raise Blocked("Python 路径不适合生成 Orca 标题入口。")
    # This is a separate copy of the parser: the sandbox cannot import host
    # modules, and the broker independently enforces the same field restrictions.
    return f'''#!{sys.executable}
import json, re, signal, socket, sys

def expired(*_):
    raise TimeoutError()
try:
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(3)
    raw = sys.stdin.buffer.read({MAX_INPUT + 1})
    if len(raw) > {MAX_INPUT}:
        raise ValueError()
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError()
    event = payload.get("hook_event_name")
    session = payload.get("session_id")
    if event not in {tuple(sorted(_EVENTS))!r} or not isinstance(session, str) or not re.fullmatch({_UUID.pattern!r}, session):
        raise ValueError()
    result = {{"hook_event_name": event, "session_id": session}}
    if event == "UserPromptSubmit":
        if not isinstance(payload.get("prompt"), str):
            raise ValueError()
        result["prompt"] = payload["prompt"][:{MAX_PROMPT}]
    elif event == "SessionStart":
        source = payload.get("source", "startup")
        if source not in ("startup", "resume", "clear"):
            raise ValueError()
        result["source"] = source
    packet = json.dumps({{"token": {token!r}, "payload": result}}, ensure_ascii=True).encode() + b"\\n"
    if len(packet) > {MAX_INPUT}:
        raise ValueError()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(0.5)
        connection.connect({socket_path!r})
        connection.sendall(packet)
except Exception:
    pass
finally:
    signal.alarm(0)
    print("{{}}")
'''


class Session:
    """One child owns one title-only capability and fixed local Orca target."""

    def __init__(self, binding: Binding, project):
        _validate_binding(binding)
        self.binding = binding
        self.project = project
        self.hook = None
        self.settings_hooks = {}
        self.child = None
        self._folder = None
        self._socket = None
        self._thread = None
        self._connection = None
        self._token = secrets.token_urlsafe(32)
        self._closing = threading.Event()
        self._ready = threading.Event()
        self._state = threading.RLock()
        self._session_id = None
        self._last = {}
        self._prompts = 0
        self._events = 0
        self._ended = False
        self.diagnostics = {"accepted": 0, "forwarded": 0, "rejected": 0, "failed": 0}

    def __enter__(self):
        try:
            self._folder = Path(tempfile.mkdtemp(prefix="surge-cc-title-", dir="/private/tmp"))
            self._folder.chmod(0o700)
            self.hook = self._folder / "hook"
            self.hook.write_text(_hook_source(str(self._folder / "s"), self._token), encoding="utf-8")
            self.hook.chmod(0o500)
            command = shlex.quote(str(self.hook))
            self.settings_hooks = {event: [{"hooks": [{"type": "command", "command": command, "timeout": 4}]}]
                                   for event in sorted(_EVENTS)}
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._socket.bind(str(self._folder / "s"))
            os.chmod(self._folder / "s", 0o600)
            self._socket.listen(4)
            self._socket.settimeout(0.2)
            self._thread = threading.Thread(target=self._serve, name="surge-cc-orca-titles", daemon=True)
            self._thread.start()
            return self
        except BaseException:
            self.close()
            raise

    def set_child(self, child):
        with self._state:
            if self._closing.is_set() or self.child is not None or child.poll() is not None:
                raise Blocked("Orca 标题入口无法绑定当前 Claude 进程。")
            self.child = child
            self._ready.set()

    def _live(self):
        return not self._closing.is_set() and self.child is not None and self.child.poll() is None

    def _read(self, connection):
        connection.settimeout(0.5)
        data = bytearray()
        deadline = time.monotonic() + 1.0
        while len(data) <= MAX_INPUT:
            if time.monotonic() >= deadline:
                raise ValueError("slow packet")
            chunk = connection.recv(min(4096, MAX_INPUT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if b"\n" in chunk:
                break
        if len(data) > MAX_INPUT or not data.endswith(b"\n") or data.count(b"\n") != 1:
            raise ValueError("invalid packet")
        packet = json.loads(data)
        if (not isinstance(packet, dict) or not isinstance(packet.get("token"), str)
                or not secrets.compare_digest(packet["token"], self._token)):
            raise ValueError("unauthorized packet")
        return _sanitize(packet.get("payload"))

    def _accept(self, payload):
        with self._state:
            if not self._live() or self._ended or self._events >= 4096:
                return False
            event = payload["hook_event_name"]
            session = payload["session_id"]
            if self._session_id is not None and self._session_id != session:
                return False
            stamp = time.monotonic()
            # Separate event buckets preserve the initial prompt and turn-end
            # signal even when they arrive immediately after SessionStart.
            if stamp - self._last.get(event, -1000.0) < 1.0:
                return False
            if event == "UserPromptSubmit" and self._prompts >= 1000:
                return False
            self._session_id = session
            self._last[event] = stamp
            self._events += 1
            self._prompts += event == "UserPromptSubmit"
            self._ended = event == "SessionEnd"
            self.diagnostics["accepted"] += 1
            return True

    def _post(self, payload):
        binding = self.binding
        meta = "\x1f".join((binding.pane_key, binding.tab_id, binding.launch_token,
                              binding.worktree_id, binding.environment, binding.version))
        headers = {"Content-Type": "application/json",
                   "X-Orca-Agent-Hook-Token": binding.token,
                   "X-Orca-Agent-Hook-Meta-Encoding": "base64",
                   "X-Orca-Agent-Hook-Meta": base64.b64encode(meta.encode()).decode("ascii")}
        payload = dict(payload, cwd=str(self.project.root))
        body = json.dumps(payload, ensure_ascii=True).encode()
        # Literal loopback + http.client: no DNS, proxies, redirect following,
        # inherited environment, or reading a response body into the sandbox.
        connection = http.client.HTTPConnection("127.0.0.1", binding.port, timeout=1.5)
        with self._state:
            if not self._live():
                return
            self._connection = connection
        try:
            connection.request("POST", "/hook/claude", body=body, headers=headers)
            response = connection.getresponse()
            if 200 <= response.status < 300:
                self.diagnostics["forwarded"] += 1
            else:
                self.diagnostics["failed"] += 1
        finally:
            connection.close()
            with self._state:
                if self._connection is connection:
                    self._connection = None

    def _serve(self):
        while not self._closing.is_set():
            try:
                connection, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            payload = None
            try:
                with connection:
                    payload = self._read(connection)
                # Startup hooks can beat Popen's on_started callback by a few ms.
                if not self._ready.wait(2.0) or not self._accept(payload):
                    self.diagnostics["rejected"] += 1
                    continue
                self._post(payload)
            except (OSError, ValueError, TypeError, AttributeError, http.client.HTTPException):
                self.diagnostics["failed"] += 1
            finally:
                # Do not retain even the bounded prompt while awaiting another
                # event; only counters and the UUID remain in the broker.
                payload = None

    def close(self):
        self._closing.set()
        self._ready.set()
        if self._socket is not None:
            self._socket.close()
        if self._connection is not None:
            self._connection.close()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        if self._folder is not None:
            shutil.rmtree(self._folder, ignore_errors=True)
        self._token = ""

    def __exit__(self, *_):
        self.close()

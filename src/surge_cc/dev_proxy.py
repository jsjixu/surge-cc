"""Per-launch development proxy: fixed upstream, owned loopback previews only.

This is not a general host bridge. It never reads files, invokes a shell, resolves
public DNS, or opens a public socket. Internet connections use the existing
Surge listener; localhost listeners must belong to the live child process tree.
"""
from __future__ import annotations

import ipaddress
import os
import re
import select
import socket
import subprocess
import threading
import time
from urllib.parse import urlsplit

from .core import Blocked
from .guard import RuntimeChecker


MAX_HEADER = 32768
CHECK_CACHE_SECONDS = 1.0


class StrictRuntimeChecker(RuntimeChecker):
    """An isolated development session never follows Surge's global policy."""

    def _suspend_if_global(self, status=None):
        return False


def descendants(child, *, run=subprocess.run):
    if child is None or child.poll() is not None or type(child.pid) is not int or child.pid <= 1:
        return set()
    result = run(["/bin/ps", "-axo", "pid=,ppid="], capture_output=True,
                 text=True, timeout=3, check=False)
    if result.returncode or child.poll() is not None:
        return set()
    pairs = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and all(field.isdigit() for field in fields):
            pairs.append(tuple(map(int, fields)))
    allowed = {child.pid}
    for _ in range(64):
        expanded = allowed | {pid for pid, parent in pairs if parent in allowed}
        if expanded == allowed:
            break
        allowed = expanded
    return allowed


def listener_owned_by(child, host, port, *, run=subprocess.run):
    """Check all owners of the exact loopback/wildcard listening port."""
    try:
        allowed = descendants(child, run=run)
        if not allowed or type(port) is not int or not 1024 <= port <= 65535:
            return False
        result = run(["/usr/sbin/lsof", "-nP", "-iTCP:" + str(port),
                      "-sTCP:LISTEN", "-Fpn"], capture_output=True,
                     text=True, timeout=3, check=False)
        if result.returncode or child.poll() is not None:
            return False
        owners, addresses = set(), []
        for line in result.stdout.splitlines():
            if line.startswith("p") and line[1:].isdigit():
                owners.add(int(line[1:]))
            elif line.startswith("n"):
                addresses.append(line[1:])
        valid = {f"127.0.0.1:{port}", f"[::1]:{port}", f"*:{port}"}
        return bool(owners and addresses) and owners <= allowed and all(a in valid for a in addresses)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def destination(authority, default_port=None):
    if (not isinstance(authority, str) or not authority or len(authority) > 1024
            or any(ord(c) <= 32 or ord(c) >= 127 for c in authority)
            or any(c in authority for c in "@/#?\\%")):
        raise ValueError("invalid authority")
    parsed = urlsplit("//" + authority)
    # An explicit zero is invalid, not a request for the default HTTP port.
    host = parsed.hostname
    port = default_port if parsed.port is None else parsed.port
    if not host or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid destination")
    if host == "localhost":
        return "127.0.0.1", port, True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if (not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host)
                or "." not in host or not any(c.isalpha() for c in host)
                or host.lower().endswith((".localhost", ".local", ".internal", ".lan"))
                or any(not part or len(part) > 63 for part in host.split("."))):
            raise ValueError("ambiguous host")
        return host, port, False
    if ip.is_loopback:
        if str(ip) not in {"127.0.0.1", "::1"}:
            raise ValueError("unsupported loopback alias")
        return str(ip), port, True
    if not ip.is_global:
        raise ValueError("non-public address")
    return str(ip), port, False


def _authority(host, port):
    return (f"[{host}]" if ":" in host else host) + ":" + str(port)


def _headers(connection):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            raise ValueError("incomplete headers")
        data.extend(chunk)
        if len(data) > MAX_HEADER:
            raise ValueError("headers too large")
    header, rest = bytes(data).split(b"\r\n\r\n", 1)
    return header, rest


class Session:
    def __init__(self, config, *, checker, owner_check=listener_owned_by):
        if config.get("proxy_url") != "http://127.0.0.1:62919":
            raise Blocked("开发代理需要已验证的专用 Surge 入口。")
        self.checker, self.owner_check = checker, owner_check
        self.child = None
        self._server = None
        self._thread = None
        self._closing = threading.Event()
        self._ready = threading.Event()
        self._lock = threading.RLock()
        self._check_lock = threading.Lock()
        self._sockets = set()
        self._slots = threading.BoundedSemaphore(32)
        self._fault = False
        self._checked_at = None
        self.port = None

    @property
    def proxy_url(self):
        if self.port is None:
            raise Blocked("开发代理尚未启动。")
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self):
        self._server = socket.socket()
        self._server.bind(("127.0.0.1", 0))
        self.port = self._server.getsockname()[1]
        self._server.listen(32)
        self._server.settimeout(.2)
        self._thread = threading.Thread(target=self._serve, daemon=True, name="surge-cc-development")
        self._thread.start()
        return self

    def set_child(self, child):
        if self.child is not None or child.poll() is not None or self._closing.is_set():
            raise Blocked("开发代理无法绑定当前 Claude 会话。")
        self.child = child
        self._ready.set()

    def _live(self):
        return not self._closing.is_set() and self.child is not None and self.child.poll() is None

    def _gate(self):
        """Share a successful check for at most one second in this session.

        Surge inspection itself can take time: this is bounded polling, not an
        instantaneous network firewall. The TTL starts when inspection finishes
        and never caches failure or skips the live-child/fault checks. Every
        public connection still uses the same fixed upstream with no fallback.
        """
        if not self._live() or self._fault:
            raise Blocked("开发会话已停止或线路检查未通过。")
        with self._check_lock:
            # Another connection may have failed the checker while this one
            # waited. A fault is permanent for this launch, even if a later
            # checker invocation would succeed.
            if not self._live() or self._fault:
                raise Blocked("开发会话已停止或线路检查未通过。")
            now = time.monotonic()
            if self._checked_at is not None and 0 <= now - self._checked_at < CHECK_CACHE_SECONDS:
                return
            try:
                self.checker.check(include_exit=False)
                if getattr(self.checker, "suspended", False):
                    raise Blocked("固定出口保护不能挂起。")
                if not self._live() or self._fault:
                    raise Blocked("开发会话在检查期间停止。")
                self._checked_at = time.monotonic()
            except Exception:
                self._fault = True
                self._checked_at = None
                self._disconnect()
                raise Blocked("线路保护检查失败，开发代理已断开。") from None

    def _disconnect(self):
        with self._lock:
            for connection in tuple(self._sockets):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _track(self, connection):
        with self._lock:
            if self._closing.is_set() or self._fault:
                connection.close()
                raise OSError("closed")
            self._sockets.add(connection)
        return connection

    def _release(self, connection):
        with self._lock:
            self._sockets.discard(connection)
            connection.close()

    def _connect(self, host, port, local):
        self._gate()
        if local:
            if port in {self.port, 62919, 6152, 6153} or not self.owner_check(self.child, host, port):
                raise Blocked("该本机服务不属于当前 Claude 会话。")
            connection = self._track(socket.create_connection((host, port), timeout=5))
            if not self.owner_check(self.child, host, port):
                self._release(connection)
                raise Blocked("本机服务归属已变化。")
            return connection, b""
        connection = self._track(socket.create_connection(("127.0.0.1", 62919), timeout=10))
        try:
            authority = _authority(host, port)
            connection.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
            header, rest = _headers(connection)
            status = header.split(b"\r\n", 1)[0].split(b" ")
            if len(status) < 2 or not status[0].startswith(b"HTTP/") or status[1] != b"200":
                raise Blocked("专用上游无法连接；不会改用直连或其他代理。")
            self._gate()
            return connection, rest
        except Exception:
            self._release(connection)
            raise

    def _relay(self, first, second):
        peers = {first: second, second: first}
        last_check = time.monotonic()
        while self._live() and not self._fault:
            if time.monotonic() - last_check >= 2:
                self._gate()
                last_check = time.monotonic()
            ready, _, _ = select.select(list(peers), [], [], .2)
            for connection in ready:
                chunk = connection.recv(65536)
                if not chunk:
                    return
                peers[connection].sendall(chunk)

    def _handle(self, client):
        upstream = None
        try:
            if not self._ready.wait(2) or not self._live():
                raise Blocked("会话尚未就绪。")
            client.settimeout(10)
            raw, body = _headers(client)
            lines = raw.decode("iso-8859-1").split("\r\n")
            method, target, version = lines[0].split(" ")
            if version not in {"HTTP/1.0", "HTTP/1.1"} or not re.fullmatch(r"[A-Z]{1,16}", method):
                raise ValueError("invalid request")
            if method == "CONNECT":
                host, port, local = destination(target)
                upstream, pending = self._connect(host, port, local)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n" + pending)
            else:
                url = urlsplit(target)
                if url.scheme != "http" or url.fragment or not url.netloc:
                    raise ValueError("absolute HTTP URL required")
                host, port, local = destination(url.netloc, 80)
                upstream, pending = self._connect(host, port, local)
                path = url.path or "/"
                if url.query:
                    path += "?" + url.query
                clean, connections, upgrades = [], [], []
                for line in lines[1:]:
                    name, separator, value = line.partition(":")
                    if (not separator or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                            or any(ord(char) < 32 and char != "\t" for char in value)):
                        raise ValueError("invalid header")
                    if name.lower() == "connection":
                        connections.extend(item.strip().lower() for item in value.split(","))
                    elif name.lower() == "upgrade":
                        upgrades.append(value.strip().lower())
                    elif name.lower() not in {"proxy-authorization", "proxy-connection"}:
                        clean.append(line)
                websocket = (local and method == "GET" and version == "HTTP/1.1"
                             and upgrades == ["websocket"] and "upgrade" in connections)
                # Vite/Next and other local previews use this HTTP Upgrade for
                # hot reload. Only the already ownership-checked local server
                # receives it; arbitrary upgrade protocols stay disabled.
                connection = ("Upgrade: websocket\r\nConnection: Upgrade" if websocket
                              else "Connection: close")
                request = f"{method} {path} HTTP/1.1\r\n" + "\r\n".join(clean) + "\r\n" + connection + "\r\n\r\n"
                upstream.sendall(request.encode("iso-8859-1"))
                if pending:
                    client.sendall(pending)
            if body:
                upstream.sendall(body)
            self._relay(client, upstream)
        except (Blocked, OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
        finally:
            with self._lock:
                for connection in (client, upstream):
                    if connection is not None:
                        self._sockets.discard(connection)
                        connection.close()
            self._slots.release()

    def _serve(self):
        while not self._closing.is_set():
            try:
                client, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self._slots.acquire(False):
                client.close()
                continue
            try:
                self._track(client)
                threading.Thread(target=self._handle, args=(client,), daemon=True).start()
            except OSError:
                self._slots.release()

    def close(self):
        self._closing.set()
        self._disconnect()
        if self._server:
            self._server.close()
        if self._thread:
            self._thread.join(timeout=2)
        with self._lock:
            for connection in tuple(self._sockets):
                connection.close()
            self._sockets.clear()

    def __exit__(self, *_):
        self.close()

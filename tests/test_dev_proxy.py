"""Development proxy boundaries; fixtures never touch Surge or model services."""
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import dev_proxy
from surge_cc.core import Blocked


def child(pid=100):
    return SimpleNamespace(pid=pid, poll=Mock(return_value=None))


def completed(stdout="", returncode=0):
    return SimpleNamespace(stdout=stdout, returncode=returncode)


class MemorySocket:
    def __init__(self, incoming=b""):
        self.incoming = io.BytesIO(incoming)
        self.sent = bytearray()
        self.closed = False
        self.shutdowns = []

    def recv(self, size):
        return self.incoming.read(size)

    def sendall(self, value):
        self.sent.extend(value)

    def settimeout(self, value):
        self.timeout = value

    def shutdown(self, how):
        self.shutdowns.append(how)

    def close(self):
        self.closed = True


class DestinationTests(unittest.TestCase):
    def test_public_and_exact_loopback_destinations(self):
        for authority, default, expected in (
            ("github.com:443", None, ("github.com", 443, False)),
            ("registry.npmjs.org", 80, ("registry.npmjs.org", 80, False)),
            ("1.1.1.1:443", None, ("1.1.1.1", 443, False)),
            ("localhost:3000", None, ("127.0.0.1", 3000, True)),
            ("LOCALHOST:3000", None, ("127.0.0.1", 3000, True)),
            ("127.0.0.1:5173", None, ("127.0.0.1", 5173, True)),
            ("[::1]:5173", None, ("::1", 5173, True)),
        ):
            with self.subTest(authority=authority):
                self.assertEqual(dev_proxy.destination(authority, default), expected)

    def test_rejects_zero_private_alias_and_malformed_authorities(self):
        for authority in ("github.com:0", "localhost:0", "[::1]:0", "github.com:65536",
                          "10.0.0.1:443", "192.168.1.1:80", "169.254.169.254:80",
                          "127.0.0.2:3000", "127.1:80", "2130706433:80", "localhost.local:80",
                          "foo.internal:80", "foo.lan:80", "localhost.:80", "user@host.com:80",
                          "host.com/path", "host.com?x", "host.com#x", "host.com%0a:80",
                          "host.com\r\nX: y", "[::ffff:127.0.0.1]:80", "", None):
            with self.subTest(authority=authority), self.assertRaises(ValueError):
                dev_proxy.destination(authority, 80)

    def test_connect_requires_explicit_port(self):
        with self.assertRaises(ValueError):
            dev_proxy.destination("github.com")


class OwnershipTests(unittest.TestCase):
    def test_transitive_child_tree_and_exact_listener(self):
        run = Mock(side_effect=[completed("1 0\n100 1\n102 101\n101 100\n999 1\n"),
                                completed("p102\nn127.0.0.1:5173\n")])
        self.assertTrue(dev_proxy.listener_owned_by(child(), "127.0.0.1", 5173, run=run))
        self.assertEqual(run.call_args_list[1].args[0],
                         ["/usr/sbin/lsof", "-nP", "-iTCP:5173", "-sTCP:LISTEN", "-Fpn"])

    def test_unrelated_or_mixed_owner_and_non_loopback_listener_are_denied(self):
        for owners in ("p999\nn127.0.0.1:5173\n", "p101\nn127.0.0.1:5173\np999\nn[::1]:5173\n",
                       "p101\nn192.168.1.2:5173\n", "p101\n", "n127.0.0.1:5173\n", ""):
            run = Mock(side_effect=[completed("100 1\n101 100\n999 1\n"), completed(owners)])
            with self.subTest(owners=owners):
                self.assertFalse(dev_proxy.listener_owned_by(child(), "127.0.0.1", 5173, run=run))

    def test_listener_probe_errors_and_dead_child_fail_closed(self):
        for failure in (OSError("denied"), subprocess.TimeoutExpired("ps", 3)):
            self.assertFalse(dev_proxy.listener_owned_by(child(), "127.0.0.1", 5173,
                                                        run=Mock(side_effect=failure)))
        dead = child()
        dead.poll.return_value = 0
        run = Mock()
        self.assertFalse(dev_proxy.listener_owned_by(dead, "127.0.0.1", 5173, run=run))
        run.assert_not_called()


class ProxyFixture(unittest.TestCase):
    def setUp(self):
        self.checker = SimpleNamespace(check=Mock(), suspended=False)
        self.owner = Mock(return_value=True)
        self.session = dev_proxy.Session({"proxy_url": "http://127.0.0.1:62919"},
                                         checker=self.checker, owner_check=self.owner)
        self.session.port = 49123
        self.session.set_child(child())
        self.addCleanup(self.session.close)


class ConnectionTests(ProxyFixture):
    def test_only_fixed_surge_upstream_is_used_for_public_destination(self):
        upstream = MemorySocket(b"HTTP/1.1 200 Connection Established\r\n\r\nrest")
        with patch.object(dev_proxy.socket, "create_connection", return_value=upstream) as connect:
            sock, rest = self.session._connect("github.com", 443, False)
        connect.assert_called_once_with(("127.0.0.1", 62919), timeout=10)
        self.assertEqual(rest, b"rest")
        self.assertIs(sock, upstream)
        self.assertEqual(bytes(upstream.sent), b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
        self.owner.assert_not_called()

    def test_upstream_failure_never_retries_direct_or_another_proxy(self):
        with patch.object(dev_proxy.socket, "create_connection", side_effect=OSError("offline")) as connect:
            with self.assertRaises(OSError):
                self.session._connect("github.com", 443, False)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(connect.call_args.args[0], ("127.0.0.1", 62919))
        for reply in (b"HTTP/1.1 502 Bad Gateway\r\n\r\n", b"HTTP/1.1 302 Redirect\r\n\r\n"):
            upstream = MemorySocket(reply)
            with patch.object(dev_proxy.socket, "create_connection", return_value=upstream) as connect:
                with self.assertRaises(Blocked):
                    self.session._connect("github.com", 443, False)
                self.assertEqual(connect.call_count, 1)
                self.assertTrue(upstream.closed)

    def test_local_owner_is_checked_before_and_after_connect(self):
        upstream = MemorySocket()
        with patch.object(dev_proxy.socket, "create_connection", return_value=upstream) as connect:
            self.session._connect("127.0.0.1", 5173, True)
        self.assertEqual(self.owner.call_count, 2)
        connect.assert_called_once_with(("127.0.0.1", 5173), timeout=5)
        self.owner.side_effect = [True, False]
        with patch.object(dev_proxy.socket, "create_connection", return_value=upstream):
            with self.assertRaises(Blocked):
                self.session._connect("127.0.0.1", 5173, True)
        self.assertTrue(upstream.closed)

    def test_reserved_ports_and_unowned_local_services_never_connect(self):
        self.owner.return_value = False
        for port in (49123, 62919, 6152, 6153, 5173):
            with self.subTest(port=port), patch.object(dev_proxy.socket, "create_connection") as connect:
                with self.assertRaises(Blocked):
                    self.session._connect("127.0.0.1", port, True)
                connect.assert_not_called()

    def test_checker_failure_locks_session_and_disconnects_existing_sockets(self):
        active = MemorySocket()
        self.session._sockets.add(active)
        self.checker.check.side_effect = Blocked("fixed exit offline")
        with self.assertRaises(Blocked):
            self.session._gate()
        self.assertTrue(self.session._fault)
        self.assertEqual(active.shutdowns, [socket.SHUT_RDWR])
        self.checker.check.side_effect = None
        with patch.object(dev_proxy.socket, "create_connection") as connect:
            with self.assertRaises(Blocked):
                self.session._connect("github.com", 443, False)
            connect.assert_not_called()
        self.assertEqual(self.checker.check.call_count, 1)

    def test_suspension_also_locks_session(self):
        self.checker.suspended = True
        with self.assertRaises(Blocked):
            self.session._gate()
        self.assertTrue(self.session._fault)

    def test_waiting_gate_cannot_reopen_after_another_connection_faulted(self):
        session = self.session

        class FaultBeforeAcquire:
            def __enter__(self):
                # Model a peer that faults while this caller waits for lock.
                session._fault = True

            def __exit__(self, *_):
                pass

        self.session._check_lock = FaultBeforeAcquire()
        with self.assertRaises(Blocked):
            self.session._gate()
        self.checker.check.assert_not_called()
        newly_connected = MemorySocket()
        with self.assertRaises(OSError):
            self.session._track(newly_connected)
        self.assertTrue(newly_connected.closed)
        self.assertNotIn(newly_connected, self.session._sockets)

    def test_success_cache_expires_one_second_after_check_completion(self):
        with patch.object(dev_proxy.time, "monotonic", return_value=100.0) as clock:
            # A slow real check may take 1.8s. Cache starts at completion, not
            # before the check, so concurrent npm requests can reuse it.
            self.checker.check.side_effect = lambda **kw: setattr(clock, "return_value", 101.8)
            self.session._gate()
            self.assertEqual(self.session._checked_at, 101.8)
            self.assertEqual(self.checker.check.call_count, 1)
            self.checker.check.side_effect = None
            clock.return_value = 102.799
            self.session._gate()
            self.assertEqual(self.checker.check.call_count, 1)
            clock.return_value = 102.801
            self.session._gate()
            self.assertEqual(self.checker.check.call_count, 2)
            self.assertEqual(self.session._checked_at, 102.801)

    def test_concurrent_requests_share_exactly_one_initial_full_check(self):
        ready = threading.Barrier(9)
        entered, release = threading.Event(), threading.Event()
        errors = []

        def check(**kw):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test timeout")

        def request():
            try:
                ready.wait(timeout=5)
                self.session._gate()
            except Exception as exc:
                errors.append(repr(exc))

        self.checker.check.side_effect = check
        with patch.object(dev_proxy.time, "monotonic", return_value=100.0):
            workers = [threading.Thread(target=request) for _ in range(8)]
            for worker in workers:
                worker.start()
            ready.wait(timeout=5)
            self.assertTrue(entered.wait(5))
            release.set()
            for worker in workers:
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
        self.assertFalse(errors, errors)
        self.assertEqual(self.checker.check.call_count, 1)

    def test_failed_recheck_invalidates_cache_and_can_never_recover(self):
        with patch.object(dev_proxy.time, "monotonic", return_value=100.0) as clock:
            self.session._gate()
            clock.return_value = 101.01
            self.checker.check.side_effect = Blocked("route failed")
            with self.assertRaises(Blocked):
                self.session._gate()
            self.assertIsNone(self.session._checked_at)
            self.assertTrue(self.session._fault)
            self.checker.check.side_effect = None
            clock.return_value = 500.0
            with self.assertRaises(Blocked):
                self.session._gate()
            self.assertEqual(self.checker.check.call_count, 2)

    def test_cached_success_never_bypasses_dead_child_or_fault(self):
        with patch.object(dev_proxy.time, "monotonic", return_value=100.0):
            self.session._gate()
            self.session.child.poll.return_value = 0
            with self.assertRaises(Blocked):
                self.session._gate()
            self.session.child.poll.return_value = None
            self.session._fault = True
            with self.assertRaises(Blocked):
                self.session._gate()
            self.assertEqual(self.checker.check.call_count, 1)


class RequestTests(ProxyFixture):
    def request(self, raw):
        client, upstream = MemorySocket(raw), MemorySocket()
        self.session._slots.acquire()
        with patch.object(self.session, "_connect", return_value=(upstream, b"")) as connect, \
                patch.object(self.session, "_relay"):
            self.session._handle(client)
        return bytes(upstream.sent), bytes(client.sent), connect

    def test_local_http_is_origin_form_and_strips_proxy_credentials(self):
        wire, response, connect = self.request(
            b"GET http://localhost:5173/app?q=1 HTTP/1.1\r\nHost: localhost:5173\r\n"
            b"Proxy-Authorization: secret\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n")
        connect.assert_called_once_with("127.0.0.1", 5173, True)
        self.assertTrue(wire.startswith(b"GET /app?q=1 HTTP/1.1\r\n"))
        self.assertNotIn(b"secret", wire)
        self.assertNotIn(b"Proxy-", wire)
        self.assertIn(b"Connection: close\r\n", wire)
        self.assertEqual(response, b"")

    def test_local_websocket_upgrade_and_hmr_headers_are_preserved(self):
        wire, _, connect = self.request(
            b"GET http://localhost:5173/__hmr HTTP/1.1\r\nHost: localhost:5173\r\n"
            b"Upgrade: WebSocket\r\nConnection: keep-alive, Upgrade\r\n"
            b"Sec-WebSocket-Key: synthetic\r\nSec-WebSocket-Protocol: vite-hmr\r\n\r\n")
        connect.assert_called_once_with("127.0.0.1", 5173, True)
        self.assertIn(b"Upgrade: websocket\r\nConnection: Upgrade\r\n", wire)
        self.assertIn(b"Sec-WebSocket-Protocol: vite-hmr", wire)
        self.assertNotIn(b"Connection: close", wire)

    def test_incomplete_nonlocal_or_nonwebsocket_upgrades_are_not_forwarded(self):
        for target, method, upgrade, connection in (
            ("http://localhost:5173/", "GET", "h2c", "Upgrade"),
            ("http://localhost:5173/", "GET", "websocket", "keep-alive"),
            ("http://localhost:5173/", "POST", "websocket", "Upgrade"),
            ("http://example.com/", "GET", "websocket", "Upgrade"),
        ):
            raw = f"{method} {target} HTTP/1.1\r\nHost: localhost\r\nUpgrade: {upgrade}\r\nConnection: {connection}\r\n\r\n".encode()
            wire, _, _ = self.request(raw)
            with self.subTest(target=target, method=method, upgrade=upgrade):
                self.assertNotIn(b"Upgrade:", wire)
                self.assertIn(b"Connection: close", wire)

    def test_invalid_authority_is_rejected_before_connect(self):
        wire, response, connect = self.request(b"GET http://localhost:0/ HTTP/1.1\r\nHost: localhost:0\r\n\r\n")
        connect.assert_not_called()
        self.assertEqual(wire, b"")
        self.assertTrue(response.startswith(b"HTTP/1.1 502"))


class LoopbackTests(unittest.TestCase):
    def test_real_local_websocket_handshake_and_duplex_bytes(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        port = listener.getsockname()[1]
        self.addCleanup(listener.close)
        observed, errors = [], []

        def server():
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(5)
                    header, rest = dev_proxy._headers(conn)
                    observed.append(header)
                    conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                    message = rest or conn.recv(4)
                    conn.sendall(message.upper())
            except Exception as exc:
                errors.append(repr(exc))

        worker = threading.Thread(target=server, daemon=True)
        worker.start()
        checker = SimpleNamespace(check=Mock(), suspended=False)
        owner = Mock(side_effect=lambda c, h, p: h == "127.0.0.1" and p == port)
        with dev_proxy.Session({"proxy_url": "http://127.0.0.1:62919"}, checker=checker, owner_check=owner) as proxy:
            proxy.set_child(child(os.getpid()))
            with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as client:
                client.sendall((f"GET http://localhost:{port}/hmr HTTP/1.1\r\nHost: localhost:{port}\r\n"
                                "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n").encode())
                header, rest = dev_proxy._headers(client)
                self.assertTrue(header.startswith(b"HTTP/1.1 101"))
                client.sendall(b"ping")
                self.assertEqual(rest + client.recv(4), b"PING")
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors, errors)
        self.assertEqual(len(observed), 1)
        self.assertIn(b"Connection: Upgrade", observed[0])
        self.assertEqual(owner.call_count, 2)


if __name__ == "__main__":
    unittest.main()

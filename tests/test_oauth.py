import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import oauth, workspaces
from surge_cc.core import Blocked


def url(port=49152, host="localhost", endpoint="https://claude.com/cai/oauth/authorize", **changes):
    query = dict(response_type="code", state="state_" + "x" * 32,
                 code_challenge="x" * 43, code_challenge_method="S256",
                 redirect_uri=f"http://{host}:{port}/callback")
    query.update(changes)
    return endpoint + "?" + urlencode(query)


def config():
    return {"group": "Claude", "policy": "Home", "expected_ip": "203.0.113.10",
            "proxy_url": "http://127.0.0.1:62919", "workspace": "A",
            "browser_path": "/independent/Surge CC Browser.app/Contents/MacOS/Google Chrome"}


class URLTests(unittest.TestCase):
    def test_official_endpoints_preserve_exact_url(self):
        for host, path in oauth.AUTHORIZE_ENDPOINTS:
            value = url(endpoint="https://" + host + path) + "&login_hint=user%2Btag%40example.com"
            self.assertEqual(oauth.validate_authorization_url(value).url, value)

    def test_rejects_bad_endpoint_and_url_syntax(self):
        values = [url().replace("https:", "http:", 1), url().replace("claude.com", "claude.com.evil"),
                  url().replace("claude.com", "user@claude.com"), url() + "#",
                  url() + "&x=%0a", url() + "\n", url().replace("/cai/oauth/", "/oauth/"),
                  url().replace("claude.com", "claude.com:444"), url() + "&state=another"]
        for value in values:
            with self.subTest(value=value), self.assertRaises(Blocked):
                oauth.validate_authorization_url(value)

    def test_requires_pkce_state_code_and_callback(self):
        for changes in ({"state": ""}, {"state": "short"}, {"code_challenge": "a"},
                        {"code_challenge_method": "plain"}, {"response_type": "token"},
                        {"redirect_uri": "https://platform.claude.com/oauth/code/callback"},
                        {"redirect_uri": "http://127.0.0.1:22/callback"},
                        {"redirect_uri": "http://127.0.0.1:70000/callback"},
                        {"redirect_uri": "http://127.0.0.1:49152/callback?extra=1"},
                        {"redirect_uri": "http://127.0.0.1:49152/callback#"},
                        {"redirect_uri": "http://localhost:049152/callback"},
                        {"redirect_uri": "http://127.0.0.1.evil:49152/callback"},
                        {"redirect_uri": "http://user@localhost:49152/callback"}):
            with self.subTest(changes=changes), self.assertRaises(Blocked):
                oauth.validate_authorization_url(url(**changes))

    def test_callback_only_exact_loopback_and_high_port(self):
        for host in ("localhost", "127.0.0.1", "[::1]"):
            item = oauth.validate_authorization_url(url(host=host))
            self.assertEqual(item.callback_port, 49152)
        for host in ("0.0.0.0", "127.0.0.2", "localhost.evil", "192.168.1.1"):
            with self.assertRaises(Blocked):
                oauth.validate_authorization_url(url(host=host))

    def test_args_are_single_unchanged_url_and_narrow_callback(self):
        value = url() + "&login_hint=a%26b%40example.com"
        args = oauth.oauth_browser_args(config(), Path("/private/profile with spaces"),
                                       oauth.validate_authorization_url(value))
        self.assertEqual(args[0], config()["browser_path"])
        self.assertEqual(args[-1], value)
        self.assertIn("--user-data-dir=/private/profile with spaces", args)
        self.assertIn("--proxy-server=http://127.0.0.1:62919", args)
        self.assertIn("--proxy-bypass-list=<-loopback>;http://localhost:49152;http://127.0.0.1:49152", args)
        self.assertNotIn("open", args)


class OwnershipTests(unittest.TestCase):
    def test_real_loopback_listener_pid_is_required(self):
        child = subprocess.Popen(
            [sys.executable, "-u", "-c",
             "import socket,sys; s=socket.socket(); s.bind(('127.0.0.1',0)); "
             "s.listen(1); print(s.getsockname()[1],flush=True); sys.stdin.read()"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, start_new_session=True)
        try:
            port = int(child.stdout.readline())
            self.assertTrue(oauth.callback_owned_by(child, port))
            self.assertFalse(oauth.callback_owned_by(child, port + 1))
        finally:
            child.communicate("", timeout=3)
        self.assertFalse(oauth.callback_owned_by(child, port))

    def test_listener_requires_owned_pid_loopback_and_live_process(self):
        child = Mock(pid=12345)
        child.poll.return_value = None
        for output, expected in (("p12345\nn127.0.0.1:49152\n", True),
                                 ("p12345\nn[::1]:49152\n", True),
                                 ("p12345\nn*:49152\n", False),
                                 ("p99999\nn127.0.0.1:49152\n", False),
                                 ("p12345\n", False)):
            run = Mock(return_value=Mock(returncode=0, stdout=output))
            self.assertEqual(oauth.callback_owned_by(child, 49152, run=run), expected)
            self.assertIn("-a", run.call_args.args[0])
        child.poll.return_value = 0
        run = Mock()
        self.assertFalse(oauth.callback_owned_by(child, 49152, run=run))
        run.assert_not_called()


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config_path = self.root / "config.json"
        self.profile = self.root / "workspaces/A/data/OAuthBrowser"
        self.profile.mkdir(parents=True)
        self.checker = Mock(return_value={"ok": True})
        self.child = Mock(pid=12345)
        self.child.poll.return_value = None
        self.browsers = []

        def spawn(*args, **kwargs):
            browser = Mock(pid=23456 + len(self.browsers))
            browser.poll.return_value = None
            browser.wait.side_effect = subprocess.TimeoutExpired("browser", 0.8)
            self.browsers.append(browser)
            return browser
        self.spawn = Mock(side_effect=spawn)

        def stop(child):
            child.poll.return_value = 0
        self.stop = self.enterContext(patch.object(oauth, "stop_owned_child", side_effect=stop))
        self.owner = self.enterContext(patch.object(oauth, "callback_owned_by", return_value=True))
        self.prepare = self.enterContext(patch.object(
            workspaces, "prepare_oauth_browser", create=True, return_value=self.profile))

    def session(self):
        return oauth.OAuthSession(config(), self.config_path, checker=self.checker, popen=self.spawn)

    def test_hook_private_short_and_no_authorization_data(self):
        with self.session() as session:
            hook = session.browser_hook
            self.assertEqual(hook.stat().st_mode & 0o777, 0o700)
            self.assertEqual(hook.parent.stat().st_mode & 0o777, 0o700)
            self.assertLess(len(str(hook.parent / "s").encode()), 104)
            self.assertNotIn("response_type", hook.read_text())
            self.assertNotIn("subprocess", hook.read_text())
        self.assertFalse(hook.exists())

    def test_success_owned_browser_and_context_cleanup(self):
        with self.session() as session:
            session.set_child(self.child)
            session._open_authorization(url())
            self.assertEqual(self.checker.call_count, 2)
            self.assertIs(session.browser, self.browsers[0])
            self.assertTrue(self.spawn.call_args.kwargs["start_new_session"])
            self.assertEqual(self.spawn.call_args.kwargs["env"]["HTTPS_PROXY"], config()["proxy_url"])
        self.stop.assert_called_once_with(self.browsers[0])
        self.child.terminate.assert_not_called()

    def test_initial_failed_check_never_spawns(self):
        self.checker.return_value = {"ok": False}
        with self.session() as session:
            session.set_child(self.child)
            with self.assertRaises(Blocked):
                session._open_authorization(url())
        self.spawn.assert_not_called()

    def test_wrong_callback_owner_never_spawns(self):
        self.owner.return_value = False
        with self.session() as session:
            session.set_child(self.child)
            with self.assertRaises(Blocked):
                session._open_authorization(url())
        self.spawn.assert_not_called()

    def test_after_open_failed_check_closes_only_owned_browser(self):
        self.checker.side_effect = [{"ok": True}, {"ok": False}]
        with self.session() as session:
            session.set_child(self.child)
            with self.assertRaises(Blocked):
                session._open_authorization(url())
            self.assertIsNone(session.browser)
        self.stop.assert_called_once_with(self.browsers[0])

    def test_different_callback_stops_old_browser_before_launch(self):
        with self.session() as session:
            session.set_child(self.child)
            session._open_authorization(url(49152))
            first = session.browser
            session._open_authorization(url(49153))
            self.assertIsNot(first, session.browser)
            self.assertEqual(first.poll(), 0)
            self.assertIn("http://localhost:49153", self.spawn.call_args.args[0][3])
        self.assertEqual(self.stop.call_count, 2)

    def test_existing_unknown_browser_lock_is_not_touched(self):
        lock = self.profile / "SingletonLock"
        lock.symlink_to("/unknown/existing/browser")
        with self.session() as session:
            session.set_child(self.child)
            with self.assertRaises(Blocked):
                session._open_authorization(url())
        self.assertTrue(lock.is_symlink())
        self.spawn.assert_not_called()
        self.stop.assert_not_called()

    def test_workspace_oauth_lock_excludes_second_cli(self):
        with self.session() as first, self.session() as second:
            first.set_child(self.child)
            second.set_child(self.child)
            first._open_authorization(url())
            with self.assertRaises(BlockingIOError):
                second._open_authorization(url(49153))
            self.assertIsNotNone(first.browser)
            self.assertIsNone(second.browser)
        self.assertEqual(self.spawn.call_count, 1)

    def test_oauth_browser_holds_real_workspace_lock_until_stopped(self):
        with self.session() as session:
            session.set_child(self.child)
            session._open_authorization(url())
            # No Chrome SingletonLock exists in this simulated browser, and no
            # CLI guard holds a workspace lock: the OAuth context must hold it.
            with self.assertRaises(Blocked):
                with workspaces.exclusive(self.config_path, "A"):
                    self.fail("Active OAuth browser allowed exclusive workspace access")
            with session._state:
                session._stop_browser()
            with workspaces.exclusive(self.config_path, "A") as loc:
                self.assertEqual(loc["root"], self.profile.parent.parent)

    def test_shutdown_during_slow_check_cannot_late_spawn(self):
        entered, finish = threading.Event(), threading.Event()
        def slow(_):
            entered.set()
            finish.wait(3)
            return {"ok": True}
        self.checker.side_effect = slow
        session = self.session().__enter__()
        session.set_child(self.child)
        failures = []
        def request():
            try:
                session._open_authorization(url())
            except Blocked:
                failures.append(True)
        thread = threading.Thread(target=request)
        thread.start()
        self.assertTrue(entered.wait(1))
        session.__exit__(None, None, None)
        finish.set()
        thread.join(2)
        self.assertEqual(failures, [True])
        self.spawn.assert_not_called()

    def test_ipc_wrong_token_fails_without_check_or_spawn(self):
        with self.session() as session:
            session.set_child(self.child)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect(str(session._folder / "s"))
                sock.sendall(json.dumps({"token": "wrong", "url": url()}).encode() + b"\n")
                self.assertEqual(json.loads(sock.recv(1024)), {"ok": False})
        self.checker.assert_not_called()
        self.spawn.assert_not_called()

    def test_ipc_malformed_messages_are_rejected_without_checks(self):
        with self.session() as session:
            session.set_child(self.child)
            for packet in (b"[]\n", b"{broken}\n", b"{}\n", b"x" * (oauth.MAX_MESSAGE + 1) + b"\n",
                           json.dumps({"token": session._token, "url": url(),
                                       "browser_path": "/other/browser"}).encode() + b"\n"):
                with self.subTest(size=len(packet)):
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                        sock.settimeout(2)
                        sock.connect(str(session._folder / "s"))
                        sock.sendall(packet)
                        self.assertEqual(json.loads(sock.recv(1024)), {"ok": False})
        self.checker.assert_not_called()
        self.spawn.assert_not_called()

    def test_browser_immediate_handoff_is_not_owned_session(self):
        browser = Mock(pid=23456)
        browser.poll.return_value = 0
        browser.wait.return_value = 0
        self.spawn.side_effect = None
        self.spawn.return_value = browser
        with self.session() as session:
            session.set_child(self.child)
            with self.assertRaises(Blocked):
                session._open_authorization(url())
            self.assertIsNone(session.browser)

    def test_failed_stop_prevents_another_browser_spawn(self):
        self.stop.side_effect = Blocked("stop not confirmed")
        session = self.session().__enter__()
        try:
            session.set_child(self.child)
            session._open_authorization(url())
            with self.assertRaises(Blocked):
                session._open_authorization(url(49153))
            self.assertEqual(self.spawn.call_count, 1)
        finally:
            self.browsers[0].poll.return_value = 0
            self.stop.side_effect = None
            session.__exit__(None, None, None)

    def test_child_exit_during_precheck_cannot_open_browser(self):
        def checking(_):
            self.child.poll.return_value = 0
            return {"ok": True}
        self.checker.side_effect = checking
        with self.session() as session:
            session.set_child(self.child)
            with self.assertRaises(Blocked):
                session._open_authorization(url())
        self.spawn.assert_not_called()

    def test_real_generated_hook_uses_private_ipc(self):
        with self.session() as session:
            session.set_child(self.child)
            result = subprocess.run([str(session.browser_hook), url()], capture_output=True,
                                    text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(self.spawn.call_count, 1)

    def test_real_generated_hook_failure_never_contains_url(self):
        self.checker.return_value = {"ok": False}
        with self.session() as session:
            session.set_child(self.child)
            result = subprocess.run([str(session.browser_hook), url()], capture_output=True,
                                    text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("state", result.stderr)
            self.assertNotIn(url(), result.stderr)
            self.spawn.assert_not_called()

    def test_bind_rejects_exited_child_and_repeat_binding(self):
        with self.session() as session:
            session.set_child(self.child)
            with self.assertRaises(Blocked):
                session.set_child(self.child)
        self.child.poll.return_value = 0
        with self.session() as session:
            with self.assertRaises(Blocked):
                session.set_child(self.child)


if __name__ == "__main__":
    unittest.main()

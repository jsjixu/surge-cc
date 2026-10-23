"""Orca title bridge boundaries: exact local pane and narrow one-way events."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import orca_titles as titles
from surge_cc.core import Blocked

TAB = "4a1d4287-27bc-47be-a45f-4d6c9b753151"
LEAF = "dd4e7f2a-a852-44c8-8d52-e8994e8e019c"
SID = "6ab5c76f-44fa-4d8b-8631-3f1b681e8be5"
OTHER_SID = "217c241c-cf3b-4d55-888a-a8d24cb09d01"
HOST_TOKEN = "unit-test-host-hook-secret"


def reply(result):
    return subprocess.CompletedProcess([], 0, json.dumps({"ok": True, "result": result}), "")


def payload(event="UserPromptSubmit", **extra):
    value = {"hook_event_name": event, "session_id": SID}
    if event == "UserPromptSubmit":
        value["prompt"] = "Check title integration"
    return dict(value, **extra)


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.project = SimpleNamespace(root=self.root / "project")
        self.project.root.mkdir()
        self.home = self.root / "host-home"
        self.home.mkdir()
        self.env = {
            "ORCA_AGENT_HOOK_PORT": "54321", "ORCA_AGENT_HOOK_TOKEN": HOST_TOKEN,
            "ORCA_AGENT_HOOK_TRANSPORT": "raw-json-v1",
            "ORCA_AGENT_HOOK_ENV": "production", "ORCA_AGENT_HOOK_VERSION": "1",
            "ORCA_PANE_KEY": TAB + ":" + LEAF, "ORCA_TAB_ID": TAB,
            "ORCA_WORKTREE_ID": "repository-id::" + str(self.project.root),
        }
        self.record = {"executionHostId": "local", "connected": True,
                       "worktreePath": str(self.project.root),
                       "worktreeId": self.env["ORCA_WORKTREE_ID"], "tabId": TAB, "leafId": LEAF}
        self.runner = Mock(return_value=reply({"terminals": [self.record]}))
        cli_patch = patch.object(titles.orca_integration, "_cli_path", return_value=self.root / "verified-orca")
        self.cli = cli_patch.start()
        self.addCleanup(cli_patch.stop)
        home_patch = patch.object(titles.Path, "home", return_value=self.home)
        home_patch.start()
        self.addCleanup(home_patch.stop)

    def bind(self):
        return titles.bind(self.project, inherited=self.env, runner=self.runner)

    def endpoint(self, text=None):
        path = self.home / "Library/Application Support/orca/agent-hooks/endpoint.env"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text or "\n".join([
            "ORCA_AGENT_HOOK_PORT=54322", "ORCA_AGENT_HOOK_TOKEN=refreshed-fake-token",
            "ORCA_AGENT_HOOK_TRANSPORT=raw-json-v1", "ORCA_AGENT_HOOK_ENV=production",
            "ORCA_AGENT_HOOK_VERSION=1", "ORCA_AGENT_HOOK_OPENCODE_TUI=1", "",
        ]))
        path.chmod(0o600)
        self.env["ORCA_AGENT_HOOK_ENDPOINT"] = str(path)
        return path

    def test_non_orca_launch_has_no_host_reads_or_cli_calls(self):
        with patch.object(titles, "_endpoint_values") as read:
            self.assertIsNone(titles.bind(self.project, inherited={}, runner=self.runner))
        self.cli.assert_not_called()
        self.runner.assert_not_called()
        read.assert_not_called()

    def test_binds_only_verified_local_pane_and_project(self):
        binding = self.bind()
        self.assertEqual(binding.pane_key, TAB + ":" + LEAF)
        self.assertEqual(binding.launch_token, "")  # ordinary shell terminals have none
        self.assertNotIn(HOST_TOKEN, repr(binding))
        self.cli.assert_called_once_with("/usr/local/bin/orca")
        self.assertEqual(self.runner.call_args.args[0][-3:], ["terminal", "list", "--json"])

    def test_inherited_cli_override_is_not_used(self):
        self.env["ORCA_CLI_COMMAND"] = "/unsafe/user/script"
        self.env["ORCA_DEV_REPO_ROOT"] = "/untrusted"
        self.bind()
        self.cli.assert_called_once_with("/usr/local/bin/orca")

    def test_remote_or_pairing_context_rejected_before_cli(self):
        for key in ("ORCA_ENVIRONMENT", "ORCA_PAIRING_CODE"):
            with self.subTest(key=key):
                self.env[key] = "untrusted-remote"
                with self.assertRaises(Blocked):
                    self.bind()
                self.env.pop(key)
        self.runner.assert_not_called()

    def test_malformed_binding_and_protocol_fail_closed(self):
        cases = {"ORCA_TAB_ID": "invalid", "ORCA_PANE_KEY": TAB + ":bad",
                 "ORCA_WORKTREE_ID": "wrong\npane", "ORCA_AGENT_HOOK_PORT": "65536",
                 "ORCA_AGENT_HOOK_TOKEN": "bad\nheader", "ORCA_AGENT_HOOK_ENV": "development",
                 "ORCA_AGENT_HOOK_VERSION": "2", "ORCA_AGENT_HOOK_TRANSPORT": "form-v0"}
        for key, value in cases.items():
            with self.subTest(key=key):
                original = self.env[key]
                self.env[key] = value
                with self.assertRaises(Blocked):
                    self.bind()
                self.env[key] = original
        self.runner.assert_not_called()

    def test_different_disconnected_remote_or_orphaned_terminal_rejected(self):
        cases = {"executionHostId": "remote-host", "connected": False, "orphaned": True,
                 "worktreePath": "/another-project", "worktreeId": "another-worktree",
                 "tabId": OTHER_SID, "leafId": OTHER_SID}
        for key, value in cases.items():
            with self.subTest(key=key):
                self.runner.return_value = reply({"terminals": [dict(self.record, **{key: value})]})
                with self.assertRaises(Blocked):
                    self.bind()

    def test_incomplete_or_ambiguous_inventory_rejected(self):
        for result in ({}, {"terminals": []}, {"terminals": [self.record], "truncated": True},
                       {"terminals": [self.record, self.record]}):
            with self.subTest(result_keys=list(result)):
                self.runner.return_value = reply(result)
                with self.assertRaises(Blocked):
                    self.bind()

    def test_symlink_or_relative_project_root_cannot_match(self):
        actual = self.project.root
        alias = self.root / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        for candidate in (alias, Path("relative-project")):
            with self.subTest(candidate_type="absolute" if candidate.is_absolute() else "relative"):
                self.project.root = candidate
                with self.assertRaises(Blocked):
                    self.bind()
        self.project.root = actual
        self.runner.assert_not_called()

    def test_cli_failure_never_leaks_raw_terminal_or_secret(self):
        self.runner.return_value = subprocess.CompletedProcess([], 1, HOST_TOKEN, "private prompt")
        with self.assertRaises(Blocked) as caught:
            self.bind()
        self.assertNotIn(HOST_TOKEN, str(caught.exception))
        self.assertNotIn("private prompt", str(caught.exception))

    def test_endpoint_refresh_reads_only_exact_private_metadata(self):
        self.endpoint()
        binding = self.bind()
        self.assertEqual(binding.port, 54322)
        self.assertEqual(binding.token, "refreshed-fake-token")

    def test_endpoint_path_override_never_read(self):
        self.env["ORCA_AGENT_HOOK_ENDPOINT"] = str(self.home / ".claude/settings.json")
        with patch.object(titles, "_endpoint_values") as read:
            with self.assertRaises(Blocked):
                self.bind()
        read.assert_not_called()

    def test_endpoint_symlink_hardlink_and_public_permissions_rejected(self):
        path = self.endpoint()
        path.chmod(0o644)
        with self.assertRaises(Blocked):
            self.bind()
        path.chmod(0o600)
        copy = path.with_name("copy")
        os.link(path, copy)
        with self.assertRaises(Blocked):
            self.bind()
        copy.unlink()
        path.rename(copy)
        path.symlink_to(copy)
        with self.assertRaises(Blocked):
            self.bind()

    def test_endpoint_is_data_not_a_shell_script(self):
        marker = self.root / "must-not-exist"
        self.endpoint("ORCA_AGENT_HOOK_PORT=54322\nORCA_AGENT_HOOK_TOKEN='$(touch " + str(marker) + ")'\n"
                      "ORCA_AGENT_HOOK_TRANSPORT=raw-json-v1\n")
        with self.assertRaises(Blocked):
            self.bind()
        self.assertFalse(marker.exists())
        for text in ("source /tmp/evil\n", "PATH=/tmp/evil\n", "ORCA_AGENT_HOOK_PORT=54322\nORCA_AGENT_HOOK_PORT=54323\n"):
            self.endpoint(text)
            with self.assertRaises(Blocked):
                self.bind()

    def test_shell_syntax_in_quoted_endpoint_value_is_literal_data(self):
        self.endpoint("ORCA_AGENT_HOOK_PORT=54322\nORCA_AGENT_HOOK_TOKEN='$(id)'\n"
                      "ORCA_AGENT_HOOK_TRANSPORT=raw-json-v1\n")
        self.assertEqual(self.bind().token, "$(id)")


class SanitizerTests(unittest.TestCase):
    def test_prompt_is_bounded_and_all_non_title_fields_are_discarded(self):
        result = titles._sanitize(payload(prompt="中" * 600, transcript_path="/private/transcript",
                                          tool_input={"command": "secret"}, tool_response="secret",
                                          cwd="/another-project", token=HOST_TOKEN))
        self.assertEqual(result, {"hook_event_name": "UserPromptSubmit", "session_id": SID, "prompt": "中" * 512})

    def test_lifecycle_has_no_prompt_or_transcript(self):
        for event in ("SessionStart", "Stop", "SessionEnd"):
            with self.subTest(event=event):
                value = titles._sanitize(payload(event, prompt="private text", transcript_path="/private/file"))
                self.assertNotIn("prompt", value)
                self.assertNotIn("transcript_path", value)
        self.assertEqual(titles._sanitize(payload("SessionStart", source="resume"))["source"], "resume")

    def test_unsupported_events_sessions_and_sources_rejected(self):
        for item in ([], {}, payload("PreToolUse"), payload(session_id="bad"), payload(prompt=42),
                     payload("SessionStart", source="compact")):
            with self.subTest(item_type=type(item).__name__):
                with self.assertRaises(ValueError):
                    titles._sanitize(item)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.tmp.cleanup)
        self.project = SimpleNamespace(root=Path(self.tmp.name))
        self.requests = queue.Queue()
        self.response_status = 204
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                owner.requests.put({"path": self.path, "headers": dict(self.headers), "body": json.loads(body)})
                self.send_response(owner.response_status)
                self.send_header("Location", "http://never-follow.invalid/private")
                self.end_headers()
            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        self.server_thread.start()
        self.addCleanup(self.stop_server)
        self.binding = titles.Binding(port=self.server.server_port, token=HOST_TOKEN, pane_key=TAB + ":" + LEAF,
                                      tab_id=TAB, worktree_id="repo::" + str(self.project.root))
        self.session = titles.Session(self.binding, self.project).__enter__()
        self.addCleanup(self.session.close)
        self.child = SimpleNamespace(poll=Mock(return_value=None))
        self.session.set_child(self.child)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=2)

    def send(self, item, *, token=None):
        packet = {"token": self.session._token if token is None else token, "payload": item}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            client.connect(str(self.session.hook.parent / "s"))
            client.sendall(json.dumps(packet).encode() + b"\n")

    def wait_count(self, key, count=1):
        deadline = time.monotonic() + 3
        while self.session.diagnostics[key] < count and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertGreaterEqual(self.session.diagnostics[key], count)

    def run_hook(self, item):
        return subprocess.run([str(self.session.hook)], input=json.dumps(item), text=True,
                              capture_output=True, timeout=5)

    def test_private_capability_excludes_host_token_and_global_hooks(self):
        self.assertEqual(stat.S_IMODE(self.session.hook.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.session.hook.stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE((self.session.hook.parent / "s").stat().st_mode), 0o600)
        helper = self.session.hook.read_text()
        self.assertNotIn(HOST_TOKEN, helper)
        self.assertNotIn("endpoint.env", helper)
        self.assertNotIn("X-Orca", helper)
        self.assertNotIn(str(self.binding.port), helper)
        self.assertNotIn(HOST_TOKEN, json.dumps(self.session.settings_hooks))
        self.assertEqual(set(self.session.settings_hooks), {"SessionStart", "UserPromptSubmit", "Stop", "SessionEnd"})

    def test_generated_helper_forwards_only_title_data_with_fixed_target(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://not-used.invalid:9", "ALL_PROXY": "socks5://not-used.invalid:9"}):
            result = self.run_hook(payload(prompt="x" * 600, cwd="/wrong", transcript_path="/private/log",
                                           tool_input={"secret": "data"}, token="wrong-host-token"))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "{}")
        self.assertEqual(result.stderr, "")
        request = self.requests.get(timeout=3)
        self.assertEqual(request["path"], "/hook/claude")
        self.assertEqual(request["body"], dict(payload(prompt="x" * 512), cwd=str(self.project.root)))
        self.assertEqual(request["headers"]["X-Orca-Agent-Hook-Token"], HOST_TOKEN)
        meta = base64.b64decode(request["headers"]["X-Orca-Agent-Hook-Meta"]).decode().split("\x1f")
        self.assertEqual(meta, [self.binding.pane_key, TAB, "", self.binding.worktree_id, "production", "1"])

    def test_broker_independently_discards_extra_fields(self):
        self.send(payload(prompt="z" * 600, cwd="/other", transcript_path="/private/log", tool_input="secret"))
        request = self.requests.get(timeout=3)
        self.assertEqual(request["body"], dict(payload(prompt="z" * 512), cwd=str(self.project.root)))

    def test_wrong_private_token_rejected_and_host_token_is_not_a_capability(self):
        self.send(payload(), token=HOST_TOKEN)
        self.wait_count("failed")
        self.assertTrue(self.requests.empty())
        self.send(payload())
        self.assertEqual(self.requests.get(timeout=3)["body"]["session_id"], SID)

    def test_first_session_owns_bridge_and_other_session_cannot_forward(self):
        self.send(payload("SessionStart"))
        self.requests.get(timeout=3)
        self.send(payload(session_id=OTHER_SID))
        self.wait_count("rejected")
        self.assertTrue(self.requests.empty())
        self.send(payload())
        self.assertEqual(self.requests.get(timeout=3)["body"]["session_id"], SID)

    def test_exited_child_and_ended_session_cannot_forward(self):
        self.child.poll.return_value = 0
        self.send(payload())
        self.wait_count("rejected")
        self.assertTrue(self.requests.empty())

        self.child.poll.return_value = None
        self.send(payload("SessionEnd"))
        self.requests.get(timeout=3)
        self.send(payload())
        self.wait_count("rejected", 2)
        self.assertTrue(self.requests.empty())

    def test_live_child_binding_cannot_be_replaced(self):
        with self.assertRaises(Blocked):
            self.session.set_child(SimpleNamespace(poll=lambda: None))
        self.assertIs(self.session.child, self.child)

    def test_duplicate_event_is_rate_limited(self):
        self.send(payload())
        self.requests.get(timeout=3)
        self.send(payload(prompt="another prompt"))
        self.wait_count("rejected")
        self.assertTrue(self.requests.empty())

    def test_startup_waits_for_live_child_binding(self):
        self.session.close()
        self.session = titles.Session(self.binding, self.project).__enter__()
        self.addCleanup(self.session.close)
        self.send(payload("SessionStart"))
        self.session.set_child(self.child)
        self.assertEqual(self.requests.get(timeout=3)["body"]["hook_event_name"], "SessionStart")

    def test_bounded_client_input_fails_without_blocking_claude(self):
        result = self.run_hook(payload(prompt="x" * titles.MAX_INPUT))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "{}")
        self.assertTrue(self.requests.empty())

    def test_non_title_event_never_reaches_host(self):
        self.send(payload("PreToolUse", tool_input={"command": "private"}))
        self.wait_count("failed")
        self.assertTrue(self.requests.empty())

    def test_redirect_or_failure_does_not_propagate_to_child(self):
        self.response_status = 302
        result = self.run_hook(payload())
        self.requests.get(timeout=3)
        self.wait_count("failed")
        self.assertEqual(result.stdout.strip(), "{}")
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.session.diagnostics["forwarded"], 0)

    def test_close_removes_socket_helper_and_invalidates_capability(self):
        folder = self.session.hook.parent
        self.session.close()
        self.assertFalse(folder.exists())
        self.assertEqual(self.session._token, "")
        self.assertFalse(self.session._thread.is_alive())
        with self.assertRaises(Blocked):
            self.session.set_child(self.child)


if __name__ == "__main__":
    unittest.main()

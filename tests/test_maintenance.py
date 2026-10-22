"""Offline native-maintenance transactions: no user accounts, network or apps."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import core, maintenance as m, terminal, workspaces


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="surge-maintenance-", dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(Path, "home", return_value=self.root))
        self.native = self.root / ".local/share/claude/versions/2.1.296"
        self.native.parent.mkdir(parents=True, mode=0o700)
        self.native.write_bytes(b"\xcf\xfa\xed\xfe" + b"original-native")
        self.native.chmod(0o700)
        self.command = self.root / ".local/bin/claude"
        self.command.parent.mkdir(parents=True, mode=0o700)
        self.command.symlink_to(self.native)
        self.config_path = self.root / "settings/config.json"
        self.config = core.validate_config({"schema": 1, "group": "Claude", "policy": "Fixed",
            "expected_ip": "203.0.113.10", "proxy_url": "http://127.0.0.1:62919",
            "cli_process_paths": [str(self.native.parent) + "/"]})
        core.save_config(self.config_path, self.config)
        self.backend = self.root / "backend.py"
        self.backend.write_text("print('guarded')\n")
        self.backend.chmod(0o600)
        self.state = self.root / "terminal"
        with patch.object(terminal.subprocess, "run", return_value=Mock(returncode=0, stdout="2.1.296 (Claude Code)")):
            terminal.install(self.config_path, self.backend, Path(sys.executable).resolve(),
                             command_path=self.command, state_dir=self.state)
        self.verify = self.stack.enter_context(patch.object(m, "_verify_native", side_effect=self.verified))
        self.original_manifest = (self.state / "manifest.json").read_bytes()
        self.original_shim = self.command.read_bytes()
        self.original_link = os.readlink(self.state / "original-link")
        self.account_values = {}
        for name in ("A", "B"):
            paths = workspaces.paths(self.config_path, name)
            for key in ("claude", "browser"):
                marker = paths[key] / "account-marker"
                marker.write_text("preserve-" + name + "-" + key)
                self.account_values[marker] = marker.read_bytes()
        self.config_bytes = self.config_path.read_bytes()

    def verified(self, path, **kwargs):
        return {"path": str(path), "version": path.name + " (Claude Code)", **m._hash_file(path)}

    def plan(self, operation="repair-terminal"):
        return m.plan(self.config_path, operation, state_dir=self.state)

    def apply(self, value):
        return m.apply(self.config_path, value["plan_id"], state_dir=self.state)

    def unchanged(self):
        self.assertEqual(self.command.read_bytes(), self.original_shim)
        self.assertFalse(self.command.is_symlink())
        self.assertEqual((self.state / "manifest.json").read_bytes(), self.original_manifest)
        self.assertEqual(os.readlink(self.state / "original-link"), self.original_link)
        self.accounts_unchanged()

    def accounts_unchanged(self):
        self.assertEqual(self.config_path.read_bytes(), self.config_bytes)
        for path, contents in self.account_values.items():
            self.assertEqual(path.read_bytes(), contents)

    def test_status_is_readonly_no_native_execution_or_network(self):
        with patch.object(m, "_fetch", side_effect=AssertionError("network")):
            value = m.status(self.config_path, state_dir=self.state)
        self.assertTrue(value["ok"])
        self.assertEqual(value["entries"][2]["action"], "update-claude")
        self.verify.assert_not_called()
        self.unchanged()

    def test_changed_native_is_repaired_after_verified_publisher(self):
        self.native.write_bytes(self.native.read_bytes() + b"signed-new-content")
        self.assertFalse(terminal.status(state_dir=self.state)["ok"])
        value = self.plan()
        self.assertEqual(value["operation"], "repair-terminal")
        self.assertTrue(self.apply(value)["ok"])
        self.assertTrue(terminal.status(state_dir=self.state)["ok"])
        self.assertEqual(terminal.original_claude(self.command, state_dir=self.state), self.native)
        self.assertEqual(self.verify.call_count, 2)
        self.assertFalse(self.command.is_symlink())
        self.accounts_unchanged()

    def test_missing_wrapper_restored_without_native_fallback(self):
        self.command.unlink()
        value = self.plan()
        self.assertTrue(self.apply(value)["ok"])
        self.assertFalse(self.command.is_symlink())
        self.assertIn(terminal.MARKER.encode(), self.command.read_bytes())
        self.assertTrue(terminal.status(state_dir=self.state)["ok"])
        self.accounts_unchanged()

    def test_known_official_symlink_is_reprotected(self):
        self.command.unlink()
        self.command.symlink_to(self.native)
        self.assertTrue(self.apply(self.plan())["ok"])
        self.assertFalse(self.command.is_symlink())
        self.assertTrue(terminal.status(state_dir=self.state)["ok"])

    def test_unknown_regular_command_is_never_overwritten(self):
        self.command.write_text("#!/bin/sh\nnot our launcher\n")
        with self.assertRaises(core.Blocked):
            self.plan()
        self.assertEqual(self.command.read_text(), "#!/bin/sh\nnot our launcher\n")
        self.verify.assert_not_called()

    def test_unknown_symlink_is_never_overwritten(self):
        other = self.root / "other"
        other.write_text("unknown")
        self.command.unlink()
        self.command.symlink_to(other)
        with self.assertRaises(core.Blocked):
            self.plan()
        self.assertEqual(self.command.resolve(), other)
        self.verify.assert_not_called()

    def test_signature_failure_refuses_repair(self):
        self.verify.side_effect = core.Blocked("publisher rejected")
        with self.assertRaisesRegex(core.Blocked, "publisher rejected"):
            self.plan()
        self.unchanged()

    def test_candidate_mutated_after_preview_refuses(self):
        value = self.plan()
        self.native.write_bytes(self.native.read_bytes() + b"mutated")
        with self.assertRaisesRegex(core.Blocked, "已变化"):
            self.apply(value)
        self.unchanged()

    def test_new_config_after_preview_refuses(self):
        value = self.plan()
        self.config_path.write_bytes(self.config_bytes + b"\n")
        with self.assertRaisesRegex(core.Blocked, "已变化"):
            self.apply(value)
        self.assertEqual(self.command.read_bytes(), self.original_shim)

    def test_wrong_config_cannot_manage_other_registration(self):
        other = self.config_path.parent / "other.json"
        other.write_bytes(self.config_bytes)
        other.chmod(0o600)
        with self.assertRaises(core.Blocked):
            m.plan(other, state_dir=self.state)
        self.unchanged()

    def test_expired_and_replayed_plan_refuse(self):
        value = self.plan()
        with patch.object(m.time, "time", return_value=time.time() + 3601):
            with self.assertRaisesRegex(core.Blocked, "过期"):
                self.apply(value)
        self.assertTrue(self.apply(value)["ok"])
        with self.assertRaises(core.Blocked):
            self.apply(value)

    def test_active_workspace_refuses_without_stopping_session(self):
        value = self.plan()
        path = workspaces.location(self.config_path, "B")
        with workspaces._lock(path, exclusive=False):
            with self.assertRaisesRegex(core.Blocked, "仍有受控"):
                self.apply(value)
        self.unchanged()
        self.assertFalse((self.state / "maintenance-active.json").exists())

    def test_orphan_session_refuses(self):
        value = self.plan()
        path = workspaces.location(self.config_path, "B") / ".stop-failed-fixture.json"
        path.write_text('{}')
        with self.assertRaisesRegex(core.Blocked, "仍有受控"):
            self.apply(value)
        self.unchanged()

    def test_account_barrier_blocks_concurrent_launch_prepare(self):
        value = self.plan()
        real_commit = m._commit
        def checked(*args):
            with self.assertRaises(core.Blocked):
                with workspaces.account_lock(self.config_path):
                    self.fail("launched during maintenance")
            return real_commit(*args)
        with patch.object(m, "_commit", side_effect=checked):
            self.assertTrue(self.apply(value)["ok"])

    def test_every_commit_exchange_is_blocked(self):
        value = self.plan()
        exchange = terminal._exchange
        observations = []
        def checked(*args):
            with self.assertRaisesRegex(core.Blocked, "维护尚未完成"):
                terminal.original_claude(self.command, state_dir=self.state)
            observations.append(True)
            return exchange(*args)
        with patch.object(terminal, "_exchange", side_effect=checked):
            self.assertTrue(self.apply(value)["ok"])
        self.assertEqual(len(observations), 3)
        self.assertTrue(terminal.status(state_dir=self.state)["ok"])

    def test_second_exchange_failure_rolls_back_exact_originals(self):
        value = self.plan()
        exchange = terminal._exchange
        def fail(first, second):
            if second == self.state / "original-link":
                raise OSError("injected exchange failure")
            return exchange(first, second)
        with patch.object(terminal, "_exchange", side_effect=fail):
            with self.assertRaises(core.Blocked):
                self.apply(value)
        self.unchanged()
        self.assertTrue(terminal.status(state_dir=self.state)["ok"])
        self.assertFalse((self.state / "maintenance-active.json").exists())

    def test_post_commit_failure_rolls_back_exact_originals(self):
        value = self.plan()
        with patch.object(terminal, "_verify_active", side_effect=core.Blocked("injected validation")):
            with self.assertRaises(core.Blocked):
                self.apply(value)
        self.unchanged()
        self.assertTrue(terminal.status(state_dir=self.state)["ok"])

    def test_concurrent_command_edit_never_overwritten_by_rollback(self):
        value = self.plan()
        exchange = terminal._exchange
        def edit(first, second):
            result = exchange(first, second)
            if second == self.state / "original-link":
                self.command.write_text("concurrent-user-edit")
                raise core.Blocked("injected conflict")
            return result
        with patch.object(terminal, "_exchange", side_effect=edit):
            with self.assertRaises(core.Blocked):
                self.apply(value)
        self.assertEqual(self.command.read_text(), "concurrent-user-edit")
        self.assertTrue((self.state / "maintenance-active.json").exists())
        self.assertFalse(terminal.status(state_dir=self.state)["ok"])

    def test_interrupted_barrier_can_be_repaired(self):
        marker = self.state / "maintenance-active.json"
        marker.write_text('{"schema":1}')
        marker.chmod(0o600)
        self.assertFalse(terminal.status(state_dir=self.state)["ok"])
        self.assertTrue(self.apply(self.plan())["ok"])
        self.assertFalse(marker.exists())
        self.assertTrue(terminal.status(state_dir=self.state)["ok"])

    def test_update_adds_version_without_deleting_original_and_changes_registration(self):
        payload = b"\xcf\xfa\xed\xfe" + b"new-official-version"
        release = {"version": "2.1.308", "platform": "darwin-arm64", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}
        def fetch(url, config, destination, limit):
            self.assertIn("/2.1.308/darwin-arm64/claude", url)
            destination.write_bytes(payload)
        with patch.object(m, "_release", return_value=release):
            value = self.plan("update-claude")
        old_bytes = self.native.read_bytes()
        with patch.object(m, "_fetch", side_effect=fetch), patch.object(m.subprocess, "run", return_value=Mock(returncode=0)):
            result = self.apply(value)
        self.assertEqual(result["version"], "2.1.308 (Claude Code)")
        self.assertEqual(self.native.read_bytes(), old_bytes)
        self.assertEqual(terminal.original_claude(self.command, state_dir=self.state), self.native.parent / "2.1.308")
        self.assertFalse(self.command.is_symlink())
        self.accounts_unchanged()

    def test_missing_native_can_be_restored_to_same_official_version(self):
        payload = b"\xcf\xfa\xed\xfe" + b"replacement-native"
        release = {"version": "2.1.296", "platform": "darwin-arm64", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}
        self.native.unlink()
        with patch.object(m, "_release", return_value=release):
            value = self.plan("update-claude")
        with patch.object(m, "_fetch", side_effect=lambda u, c, p, n: p.write_bytes(payload)), patch.object(m.subprocess, "run", return_value=Mock(returncode=0)):
            self.assertTrue(self.apply(value)["ok"])
        self.assertTrue(terminal.status(state_dir=self.state)["ok"])
        self.assertEqual(self.native.read_bytes(), payload)
        self.accounts_unchanged()

    def test_last_result_write_failure_does_not_misreport_committed_update(self):
        value = self.plan()
        real_write = terminal._write_private
        def write(path, body, **kwargs):
            if path.name == "last-result.json":
                raise OSError("disk-full-history")
            return real_write(path, body, **kwargs)
        with patch.object(terminal, "_write_private", side_effect=write):
            result = self.apply(value)
        self.assertTrue(result["ok"])
        self.assertFalse(result["history_saved"])
        self.assertTrue(terminal.status(state_dir=self.state)["ok"])

    def test_download_mismatch_leaves_entry_untouched(self):
        release = {"version": "2.1.308", "platform": "darwin-arm64", "sha256": "0" * 64, "size": 8}
        with patch.object(m, "_release", return_value=release):
            value = self.plan("update-claude")
        with patch.object(m, "_fetch", side_effect=lambda u, c, p, n: p.write_bytes(b"wrongbit")):
            with self.assertRaisesRegex(core.Blocked, "SHA256"):
                self.apply(value)
        self.unchanged()
        self.assertFalse((self.native.parent / "2.1.308").exists())

    def test_existing_target_not_matching_release_not_overwritten(self):
        new = self.native.parent / "2.1.308"
        new.write_bytes(b"not-official")
        new.chmod(0o700)
        release = {"version": "2.1.308", "platform": "darwin-arm64", "sha256": "0" * 64, "size": 8}
        with patch.object(m, "_release", return_value=release), self.assertRaisesRegex(core.Blocked, "已有同名版本"):
            self.plan("update-claude")
        self.assertEqual(new.read_bytes(), b"not-official")
        self.unchanged()

    def test_downgrade_refused(self):
        with patch.object(m, "_release", return_value={"version": "2.1.200"}), self.assertRaisesRegex(core.Blocked, "降级"):
            self.plan("update-claude")

    def test_changed_native_without_existing_scope_refused(self):
        new = dict(self.config, cli_process_paths=[])
        core.save_config(self.config_path, new)
        with self.assertRaisesRegex(core.Blocked, "旁路保护范围"):
            self.plan()


class PublisherAndDownloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="surge-native-", dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = patch.object(Path, "home", return_value=self.root)
        self.home.start()
        self.addCleanup(self.home.stop)
        self.path = self.root / ".local/share/claude/versions/2.1.300"
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(b"\xcf\xfa\xed\xfe" + b"test fixture")
        self.path.chmod(0o700)

    def test_signature_precedes_version_and_cleans_environment(self):
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return Mock(returncode=0, stdout="2.1.300 (Claude Code)")
        with patch.object(m.subprocess, "run", side_effect=run), patch.dict(os.environ, {"ANTHROPIC_API_KEY": "never-forward-this"}):
            result = m._verify_native(self.path)
        self.assertEqual(result["version"], "2.1.300 (Claude Code)")
        self.assertEqual(calls[0][0][0], "/usr/bin/codesign")
        self.assertIn("-R=" + m.PUBLISHER_REQUIREMENT, calls[0][0])
        env = calls[1][1]["env"]
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertNotEqual(env["HOME"], str(self.root))
        self.assertEqual(env["DISABLE_UPDATES"], "1")

    def test_failed_signature_never_executes_native(self):
        with patch.object(m.subprocess, "run", return_value=Mock(returncode=1)) as run:
            with self.assertRaisesRegex(core.Blocked, "发布者签名"):
                m._verify_native(self.path)
        self.assertEqual(run.call_count, 1)

    def test_script_magic_rejected_before_execution(self):
        self.path.write_bytes(b"#!/bin/sh\necho fake")
        with patch.object(m.subprocess, "run") as run:
            with self.assertRaisesRegex(core.Blocked, "不是 macOS 原生"):
                m._verify_native(self.path)
        run.assert_not_called()

    def test_hash_change_during_signature_rejected_before_native_exec(self):
        def run(*args, **kwargs):
            self.path.write_bytes(self.path.read_bytes() + b"changed")
            return Mock(returncode=0)
        with patch.object(m.subprocess, "run", side_effect=run) as runner:
            with self.assertRaisesRegex(core.Blocked, "发生变化"):
                m._verify_native(self.path)
        self.assertEqual(runner.call_count, 1)

    def test_fetch_uses_fixed_origin_explicit_proxy_without_redirects_or_curlrc(self):
        output = self.root / "download"
        def run(argv, **kwargs):
            output.write_bytes(b"ok")
            return Mock(returncode=0)
        with patch.object(m.subprocess, "run", side_effect=run) as runner:
            m._fetch(m.RELEASES + "/latest", {"proxy_url": "http://127.0.0.1:62919"}, output, 128)
        args = runner.call_args.args[0]
        self.assertEqual(args[1], "--disable")
        self.assertEqual(args[args.index("--noproxy") + 1], "")
        self.assertIn("http://127.0.0.1:62919", args)
        self.assertNotIn("--location", args)
        with self.assertRaises(core.Blocked):
            m._fetch("https://example.com/evil", {"proxy_url": "http://127.0.0.1:62919"}, output, 128)

    def test_release_manifest_strict_schema(self):
        config = {"proxy_url": "http://127.0.0.1:62919"}
        def fetch(url, config, output, limit):
            output.write_text("2.1.308" if url.endswith("/latest") else json.dumps({
                "version": "2.1.308", "platforms": {"darwin-arm64": {"binary": "claude", "checksum": "a" * 64, "size": 200}}}))
        with patch.object(m.platform, "machine", return_value="arm64"), patch.object(m, "_fetch", side_effect=fetch):
            self.assertEqual(m._release(config)["version"], "2.1.308")
        with patch.object(m, "_fetch", side_effect=lambda u,c,p,n: p.write_text("../../bad")):
            with self.assertRaises(core.Blocked):
                m._release(config)


if __name__ == "__main__":
    unittest.main()

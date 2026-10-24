import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import terminal_links as m


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.rc = self.root / ".zshrc"
        self.router = self.root / "router.json"
        self.router.write_text("{}")
        self.support = self.root / "support"
        self.support.mkdir(mode=0o700)
        self.data = {"config": str(self.support / "config.json"), "app": str(self.root / "Main.app"),
                     "python": sys.executable, "sources": []}
        self.backend = Path(self.data["app"]) / "Contents/Resources/scripts/surge-cc"
        self.backend.parent.mkdir(parents=True)
        self.backend.write_text("# test backend\n")
        self.folder = self.support / "terminal-links"
        self.patches = [patch.object(m.link_router, "load", return_value=self.data),
                        patch.object(m.Path, "home", return_value=self.root)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def install(self, content=b"# user\nexport TEST=original"):
        self.rc.write_bytes(content)
        self.rc.chmod(0o644)
        return m.install(self.router)


class InstallationTests(Fixture):
    def test_install_is_idempotent_and_preserves_original_bytes_and_mode(self):
        original = b"# unicode \xe4\xb8\xad\xe6\x96\x87\r\nexport TEST='a b'"
        self.install(original)
        first = self.rc.read_bytes()
        self.assertTrue(first.startswith(original))
        self.assertEqual((self.folder / "zshrc.original").read_bytes(), original)
        self.assertEqual(stat.S_IMODE((self.folder / "zshrc.original").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.rc.stat().st_mode), 0o644)
        self.assertFalse(m.install(self.router)["changed"])
        self.assertEqual(self.rc.read_bytes(), first)
        self.assertTrue(m.status(self.router)["ok"])

    def test_remove_keeps_new_user_edits_and_exact_original_prefix(self):
        original = b"export TEST=original"
        self.install(original)
        self.rc.write_bytes(self.rc.read_bytes() + b"# new edit\n")
        self.assertTrue(m.remove(self.router)["ok"])
        self.assertEqual(self.rc.read_bytes(), original + b"\n# new edit\n")
        self.assertEqual((self.folder / "zshrc.original").read_bytes(), original)
        self.assertFalse(m.status(self.router)["installed"])

    def test_install_and_remove_missing_rc(self):
        self.assertTrue(m.install(self.router)["ok"])
        self.assertTrue(m.remove(self.router)["ok"])
        self.assertEqual(self.rc.read_bytes(), b"")

    def test_modified_marker_is_not_overwritten_or_removed(self):
        self.install()
        self.rc.write_bytes(self.rc.read_bytes().replace(b"source ", b"source altered "))
        saved = self.rc.read_bytes()
        for action in (m.install, m.remove):
            with self.assertRaises(m.core.Blocked):
                action(self.router)
        self.assertEqual(self.rc.read_bytes(), saved)

    def test_symlink_or_shared_writable_rc_is_rejected(self):
        victim = self.root / "victim"
        victim.write_bytes(b"keep")
        self.rc.symlink_to(victim)
        with self.assertRaises(m.core.Blocked):
            m.install(self.router)
        self.assertEqual(victim.read_bytes(), b"keep")
        self.rc.unlink()
        self.rc.write_text("keep")
        self.rc.chmod(0o666)
        with self.assertRaises(m.core.Blocked):
            m.install(self.router)

    def test_existing_partial_marker_is_rejected(self):
        self.rc.write_bytes(m.BEGIN)
        with self.assertRaises(m.core.Blocked):
            m.install(self.router)

    def test_changed_backup_or_script_fails_status(self):
        self.install()
        (self.folder / "open.zsh").write_text("changed")
        self.assertFalse(m.status(self.router)["ok"])
        (self.folder / "zshrc.original").write_text("changed")
        with self.assertRaises(m.core.Blocked):
            m.remove(self.router)

    def test_concurrent_rc_update_is_not_overwritten(self):
        self.rc.write_text("initial")
        snapshot = m._read(self.rc)
        self.rc.write_text("new user data")
        with self.assertRaises(m.core.Blocked):
            m._replace(self.rc, snapshot, b"replacement", 0o600)
        self.assertEqual(self.rc.read_text(), "new user data")

    def test_exchange_validation_exception_keeps_displaced_data(self):
        self.rc.write_bytes(b"original")
        snapshot = m._read(self.rc)
        exchange = m.terminal._exchange
        def changed(first, second):
            exchange(first, second)
            if first.read_bytes() == b"original":
                first.write_bytes(b"concurrent user edit")
                first.chmod(0o666)  # Forces displaced-file validation to raise.
        with patch.object(m.terminal, "_exchange", side_effect=changed), self.assertRaises(m.core.Blocked):
            m._replace(self.rc, snapshot, b"managed replacement", 0o600)
        all_content = [self.rc.read_bytes()] + [p.read_bytes() for p in self.root.glob(".surge-cc-web-*")]
        self.assertIn(b"concurrent user edit", all_content)

    def test_regular_read_handles_short_reads_without_truncation(self):
        self.rc.write_bytes(b"longer original content")
        read = m.os.read
        with patch.object(m.os, "read", side_effect=lambda fd, count: read(fd, min(count, 3))):
            self.assertEqual(m._read(self.rc)[0], b"longer original content")


class DispatchTests(Fixture):
    def setUp(self):
        super().setUp()
        self.install()
        self.source = {"chain": [{"pid": 1_001, "parent": 1, "started": [100, 1], "executable": "/bin/zsh"}]}
        for item in (patch.object(m, "_source", return_value=self.source),
                     patch.object(m, "_session_owned", return_value=False),
                     patch.object(m.link_router, "_source_matches", return_value=True),
                     patch.object(m.core, "load_config", return_value={"workspace": "A"})):
            item.start()
            self.addCleanup(item.stop)

    def test_protected_url_goes_a_via_stdin_no_url_output(self):
        url = "https://example.com/private?token=SECRET"
        with patch.object(m.shortcuts, "open_url", return_value={"action": "focus"}) as opening:
            result = m.dispatch(self.router, (url + "\0").encode())
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(opening.call_args.args[:3], (Path(self.data["config"]), "A", url))
        self.assertNotIn("SECRET", json.dumps(result))

    def test_protected_failure_or_workspace_b_never_falls_back(self):
        with patch.object(m.shortcuts, "open_url", side_effect=m.core.Blocked("route unavailable")), \
                patch.object(m, "_system") as system:
            self.assertEqual(m.dispatch(self.router, b"https://example.com\0")["exit_code"], 78)
            system.assert_not_called()
        with patch.object(m.core, "load_config", return_value={"workspace": "B"}), \
                patch.object(m.shortcuts, "open_url") as opening, patch.object(m, "_system") as system:
            self.assertEqual(m.dispatch(self.router, b"https://example.com\0")["exit_code"], 78)
            opening.assert_not_called()
            system.assert_not_called()

    def test_nonweb_and_explicit_app_keep_exact_arguments(self):
        for args in (["/tmp/a b"], ["-a", "Safari", "https://example.com"]):
            with self.subTest(args=args), patch.object(m, "_system", return_value={"exit_code": 0}) as system:
                m.dispatch(self.router, b"\0".join(x.encode() for x in args) + b"\0")
                system.assert_called_once_with(args)

    def test_unsupported_web_options_and_multiple_urls_block(self):
        for args in (["-g", "https://example.com"], ["https://one.example", "https://two.example"]):
            with self.subTest(args=args), patch.object(m, "_system") as system:
                self.assertEqual(m.dispatch(self.router, b"\0".join(x.encode() for x in args) + b"\0")["exit_code"], 78)
                system.assert_not_called()

    def test_non_orca_complete_chain_uses_original_open(self):
        with patch.object(m.link_router, "_source_matches", return_value=False), \
                patch.object(m, "_system", return_value={"exit_code": 0}) as system:
            m.dispatch(self.router, b"--\0https://example.com\0")
            system.assert_called_once_with(["--", "https://example.com"])
            self.assertEqual(m.eligible(self.router)["exit_code"], 3)

    def test_unknown_or_truncated_ancestry_blocks_without_personal_fallback(self):
        for source in ({"chain": []}, {"chain": [dict(self.source["chain"][0], parent=4321)]}):
            with self.subTest(source=source), patch.object(m, "_source", return_value=source), \
                    patch.object(m.link_router, "_source_matches", return_value=False), patch.object(m, "_system") as system:
                self.assertEqual(m.dispatch(self.router, b"https://example.com\0")["exit_code"], 78)
                self.assertEqual(m.eligible(self.router)["exit_code"], 78)
                system.assert_not_called()

    def test_controlled_claude_session_is_not_rerouted_to_a(self):
        with patch.object(m, "_session_owned", return_value=True), patch.object(m.shortcuts, "open_url") as opening:
            self.assertEqual(m.eligible(self.router)["exit_code"], 3)
            self.assertEqual(m.dispatch(self.router, b"https://example.com\0")["exit_code"], 78)
            opening.assert_not_called()

    def test_bad_framing_and_bad_urls_block_with_url_free_result(self):
        for payload in (b"https://example.com", b"https://example.com\x00" * 129,
                        b"x" * (m.MAX_REQUEST_BYTES + 1), b"https://example.com/%0aSECRET\0", b"\xff\0"):
            with self.subTest(length=len(payload)), patch.object(m, "_system") as system:
                result = m.dispatch(self.router, payload)
                self.assertEqual(result["exit_code"], 78)
                self.assertNotIn("SECRET", json.dumps(result))
                system.assert_not_called()

    def test_removed_registration_blocks_old_shell_hook(self):
        m.remove(self.router)
        with patch.object(m, "_system") as system:
            self.assertEqual(m.dispatch(self.router, b"https://example.com\0")["exit_code"], 78)
            system.assert_not_called()


@unittest.skipUnless(Path("/bin/zsh").exists(), "requires zsh")
class ZshHookTests(Fixture):
    def setUp(self):
        super().setUp()
        self.backend.write_text("""import sys
from pathlib import Path
if 'shell-eligible' in sys.argv:
    raise SystemExit(0)
if 'shell-open' in sys.argv:
    raw = sys.stdin.buffer.read()
    Path(__file__).with_name('payload').write_bytes(raw)
    print('opened')
    raise SystemExit(0)
raise SystemExit(78)
""")
        self.install()

    def shell(self, commands, env=None):
        runenv = dict(os.environ, ZDOTDIR=str(self.root / "unused-zdot"))
        for key in ("BROWSER", "SURGE_CC_TERMINAL_ENTRY"):
            runenv.pop(key, None)
        runenv.update(env or {})
        return subprocess.run(["/bin/zsh", "-f", "-i", "-c", commands], env=runenv,
                              capture_output=True, text=True, timeout=10)

    def test_absolute_and_plain_open_use_same_sync_hook_and_nul_input(self):
        script = self.folder / "open.zsh"
        for command in ("open", "/usr/bin/open"):
            result = self.shell(f"source '{script}'; {command} -- 'https://example.com/path?token=SECRET'")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.backend.with_name("payload").read_bytes(), b"--\0https://example.com/path?token=SECRET\0")
            self.assertNotIn("SECRET", result.stdout + result.stderr)

    def test_existing_alias_and_function_are_preserved(self):
        script = self.folder / "open.zsh"
        result = self.shell(f"function open() {{ print kept; }}; source '{script}'; open; (( $+functions[/usr/bin/open] == 0 ))")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("kept", result.stdout)
        result = self.shell(f"alias open='print kept'; source '{script}'; alias open; (( $+functions[/usr/bin/open] == 0 ))")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("kept", result.stdout)

    def test_controlled_claude_startup_keeps_private_path_opener(self):
        result = self.shell(f"source '{self.folder / 'open.zsh'}'; (( $+functions[open] == 0 && $+functions[/usr/bin/open] == 0 ))",
                            {"BROWSER": "/private/tmp/surge-cc-oauth-fixture/browser"})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_deleted_backend_blocks_active_hook(self):
        result = self.shell(f"source '{self.folder / 'open.zsh'}'; /bin/rm '{self.backend}'; /usr/bin/open https://example.com")
        self.assertEqual(result.returncode, 78, result.stderr)
        self.assertIn("blocked", result.stderr)
        self.assertFalse(self.backend.with_name("payload").exists())

    def test_unrelated_terminal_does_not_define_functions(self):
        self.backend.write_text("raise SystemExit(3)\n")
        result = self.shell(f"source '{self.folder / 'open.zsh'}'; (( $+functions[open] == 0 && $+functions[/usr/bin/open] == 0 ))")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unsupported_web_arguments_are_blocked_in_shell(self):
        for arguments in ("-g https://example.com", "https://one.example https://two.example"):
            result = self.shell(f"source '{self.folder / 'open.zsh'}'; open {arguments}")
            self.assertEqual(result.returncode, 78, result.stderr)
            self.assertFalse(self.backend.with_name("payload").exists())

    def test_broker_entered_after_startup_takes_priority_over_generic_a(self):
        with tempfile.TemporaryDirectory(prefix="surge-cc-oauth-", dir="/private/tmp") as directory:
            broker = Path(directory)
            (broker / "browser").write_text("fixture")
            (broker / "open").write_text("#!/bin/sh\nprintf '%s\\n' broker-session-B\n")
            (broker / "open").chmod(0o700)
            result = self.shell(f"source '{self.folder / 'open.zsh'}'; export BROWSER='{broker}/browser'; export PATH='{broker}':$PATH; open https://example.com")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("broker-session-B", result.stdout)
            self.assertFalse(self.backend.with_name("payload").exists())


if __name__ == "__main__":
    unittest.main()

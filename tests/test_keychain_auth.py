"""Synthetic keychain tests; never invoke the real macOS keychain."""
import contextlib
import io
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import traceback
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import core, keychain_auth as auth


class KeychainAuthTests(unittest.TestCase):
    def setUp(self):
        self.identity = pwd.getpwuid(os.getuid())
        self.config = {"enabled": True, "service": auth.SERVICE,
                       "account": self.identity.pw_name}
        self.token = "sk-ant-oat01-" + "synthetic-secret_" * 4
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.config_path = self.base / "config.json"
        self.terminal = self.base / "terminal"
        self.marker = self.terminal / auth.MARKER

    def write_marker(self, data=None):
        self.terminal.mkdir(mode=0o700, exist_ok=True)
        self.marker.write_text(json.dumps(self.config if data is None else data))
        self.marker.chmod(0o600)

    def test_valid_token_is_returned_only_in_memory(self):
        for ending in (b"", b"\n", b"\r\n"):
            with self.subTest(ending=ending), patch.object(auth.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, self.token.encode() + ending, b"")
                output, errors = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    self.assertEqual(auth.read_token(self.config), self.token)
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(errors.getvalue(), "")
                self.assertFalse(self.terminal.exists())

    def test_subprocess_uses_fixed_binary_and_no_shell_or_inherited_environment(self):
        malicious = {"PATH": "/evil", "HOME": "/evil", "USER": "someone-else",
                     "CLAUDE_CODE_OAUTH_TOKEN": self.token, "ANTHROPIC_API_KEY": self.token,
                     "DYLD_INSERT_LIBRARIES": "/evil", "PYTHONPATH": "/evil",
                     "SECURITYSESSIONID": "invalid", "BASH_ENV": "/evil"}
        with patch.dict(os.environ, malicious), patch.object(auth.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, self.token.encode(), b"")
            self.assertEqual(auth.read_token(self.config), self.token)
        positional, named = run.call_args
        self.assertEqual(positional[0], ["/usr/bin/security", "find-generic-password", "-s",
                                        auth.SERVICE, "-a", self.identity.pw_name, "-w"])
        self.assertIs(named["shell"], False)
        self.assertIs(named["capture_output"], True)
        self.assertIs(named["check"], False)
        self.assertIs(named["close_fds"], True)
        self.assertEqual(named["timeout"], auth.TIMEOUT)
        self.assertEqual(named["stdin"], subprocess.DEVNULL)
        self.assertEqual(named["cwd"], "/")
        self.assertEqual(named["env"], {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                                       "HOME": self.identity.pw_dir, "USER": self.identity.pw_name,
                                       "LOGNAME": self.identity.pw_name, "LANG": "C", "LC_ALL": "C"})
        self.assertNotIn(self.token, repr((positional, named)))

    def test_disabled_never_reads_keychain(self):
        with patch.object(auth.subprocess, "run") as run:
            for config in (None, {"enabled": False}, {**self.config, "enabled": False}):
                with self.subTest(config=config):
                    self.assertIsNone(auth.read_token(config))
            run.assert_not_called()

    def test_malformed_config_never_reads_keychain(self):
        cases = ({}, [], True, {"enabled": "true"}, {"enabled": 1},
                 {**self.config, "enabled": 1}, {**self.config, "enabled": None},
                 {**self.config, "service": "old-account"},
                 {**self.config, "account": "someone-else"},
                 {**self.config, "token": self.token},
                 {**self.config, "account": self.token},
                 {**self.config, "enabled": False, "service": "old-account"})
        with patch.object(auth.subprocess, "run") as run:
            for config in cases:
                with self.subTest(index=cases.index(config)), self.assertRaises(core.Blocked) as caught:
                    auth.read_token(config)
                self.assertNotIn(self.token, str(caught.exception))
            run.assert_not_called()

    def test_failed_keychain_read_never_uses_captured_secret_or_fallback(self):
        with patch.object(auth.subprocess, "run") as run:
            for code in (1, 36, 44, -9):
                run.return_value = subprocess.CompletedProcess([], code, self.token.encode(), self.token.encode())
                with self.subTest(code=code), self.assertRaises(core.Blocked) as caught:
                    auth.read_token(self.config)
                self.assertNotIn(self.token, str(caught.exception))
                self.assertIsNone(caught.exception.__context__)
            self.assertEqual(run.call_count, 4)

    def test_exceptions_cannot_leak_secret_in_traceback_or_context(self):
        failures = [subprocess.TimeoutExpired(["security"], 15, output=self.token.encode(), stderr=self.token.encode()),
                    subprocess.CalledProcessError(1, ["security"], output=self.token, stderr=self.token),
                    OSError(self.token), RuntimeError(self.token)]
        for failure in failures:
            with self.subTest(kind=type(failure)), patch.object(auth.subprocess, "run", side_effect=failure):
                try:
                    auth.read_token(self.config)
                except core.Blocked as error:
                    self.assertNotIn(self.token, traceback.format_exc())
                    self.assertIsNone(error.__cause__)
                    self.assertIsNone(error.__context__)
                else:
                    self.fail("keychain error did not block")

    def test_invalid_token_formats_block_without_fallback(self):
        cases = (b"", b"sk-ant-oat01-short", b"sk-ant-api03-" + b"x" * 80,
                 self.token.encode() + b"\n\n", b" " + self.token.encode(),
                 self.token.encode() + b" ", self.token.encode() + b"\x00",
                 self.token.encode() + b"\x7f", self.token.encode() + b"\xff",
                 b"sk-ant-oat01-" + b"x" * auth.MAX_TOKEN, self.token, None)
        for index, value in enumerate(cases):
            with self.subTest(index=index), patch.object(auth.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, value, b"")
                with self.assertRaises(core.Blocked):
                    auth.read_token(self.config)
                self.assertEqual(run.call_count, 1)

    def test_load_missing_marker_or_terminal_is_disabled_and_creates_nothing(self):
        self.assertIsNone(auth._load_legacy(self.config_path))
        self.assertFalse(self.terminal.exists())
        self.terminal.mkdir(mode=0o700)
        self.assertIsNone(auth._load_legacy(self.config_path))
        self.assertEqual(list(self.terminal.iterdir()), [])

    def test_load_valid_marker_returns_only_explicit_config_without_reading_keychain(self):
        self.write_marker()
        with patch.object(auth.subprocess, "run") as run:
            self.assertEqual(auth._load_legacy(self.config_path), self.config)
            run.assert_not_called()

    def test_load_explicit_disable_is_supported(self):
        self.write_marker({"enabled": False})
        self.assertIsNone(auth._load_legacy(self.config_path))

    def test_load_rejects_symlinks_and_hard_links(self):
        self.write_marker()
        original = self.base / "original"
        self.marker.rename(original)
        self.marker.symlink_to(original)
        with self.assertRaises(core.Blocked):
            auth._load_legacy(self.config_path)
        self.marker.unlink()
        os.link(original, self.marker)
        with self.assertRaises(core.Blocked):
            auth._load_legacy(self.config_path)
        self.marker.unlink()
        original.rename(self.marker)
        self.terminal.rename(self.base / "other-terminal")
        self.terminal.symlink_to(self.base / "other-terminal")
        with self.assertRaises(core.Blocked):
            auth._load_legacy(self.config_path)

    def test_load_rejects_dangling_terminal_symlink(self):
        self.terminal.symlink_to(self.base / "missing")
        with self.assertRaises(core.Blocked):
            auth._load_legacy(self.config_path)

    def test_load_rejects_aliased_ancestor(self):
        self.write_marker()
        alias = self.base / "alias"
        alias.symlink_to(self.base)
        with self.assertRaises(core.Blocked):
            auth._load_legacy(alias / "config.json")

    def test_load_rejects_nonprivate_or_unexpected_modes(self):
        self.write_marker()
        for mode in (0o644, 0o640, 0o400, 0o700):
            self.marker.chmod(mode)
            with self.subTest(file_mode=oct(mode)), self.assertRaises(core.Blocked):
                auth._load_legacy(self.config_path)
        self.marker.chmod(0o600)
        for mode in (0o755, 0o750, 0o500):
            self.terminal.chmod(mode)
            with self.subTest(dir_mode=oct(mode)), self.assertRaises(core.Blocked):
                auth._load_legacy(self.config_path)
        self.terminal.chmod(0o700)

    def test_load_rejects_corrupt_oversized_duplicate_and_secret_fields(self):
        self.write_marker()
        cases = (b"broken", b"{}", b"null", b"[]", b" " * 4097,
                 b'{"enabled":false,"enabled":true}',
                 json.dumps({**self.config, "token": self.token}).encode())
        for index, value in enumerate(cases):
            self.marker.write_bytes(value)
            with self.subTest(index=index), self.assertRaises(core.Blocked) as caught:
                auth._load_legacy(self.config_path)
            self.assertNotIn(self.token, str(caught.exception))
            self.assertIsNone(caught.exception.__context__)

    def test_load_rejects_special_marker_and_wrong_owner(self):
        self.terminal.mkdir(mode=0o700)
        self.marker.mkdir(mode=0o700)
        with self.assertRaises(core.Blocked):
            auth._load_legacy(self.config_path)
        self.marker.rmdir()
        os.mkfifo(self.marker, 0o600)
        with self.assertRaises(core.Blocked):
            auth._load_legacy(self.config_path)
        self.marker.unlink()
        self.write_marker()
        with patch.object(auth.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaises(core.Blocked):
                auth._load_legacy(self.config_path)


if __name__ == "__main__":
    unittest.main()

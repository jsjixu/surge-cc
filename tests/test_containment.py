"""Isolated scope validation uses temporary browser files and fake rule responses."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_core import config, group, profile, route
from surge_cc import containment as scope
from surge_cc.core import Blocked, CHROME


class FakeSurge:
    def __init__(self, settings, text):
        self.settings = settings
        self.text = text
        self.state = {"mode": "rule", "profile-path": settings["profile_path"],
                      "features": {"enhanced-mode": True}}
        self.group_value = group()
        self.calls = []
        self.bad_protocol = None
        self.bad_process = None
        self.bad_entry = False
        self.bad_entry_process = None
        self.final_text = None
        self.profile_reads = 0
        self.reject_final = "REJECT"

    def status(self):
        return deepcopy(self.state)

    def profile(self):
        self.profile_reads += 1
        return self.final_text if self.final_text is not None and self.profile_reads > 1 else self.text

    def group(self, name):
        return deepcopy(self.group_value)

    def call(self, *args):
        self.calls.append(args)
        fields = dict(item.split("=", 1) for item in args[3:])
        self.assert_command(args)
        if fields.get("listen-port") == "62919":
            return ({"final": "DIRECT"} if self.bad_entry or
                    fields.get("process-path") == self.bad_entry_process else route())
        if (fields.get("protocol") == self.bad_protocol or
                fields.get("process-path") == self.bad_process):
            return {"rule-policy": "DIRECT", "final": "DIRECT", "final-type": "DIRECT", "steps": []}
        return {"rule-policy": "REJECT", "final": self.reject_final, "final-type": self.reject_final, "steps": []}

    @staticmethod
    def assert_command(args):
        if args[:2] != ("rule", "explain"):
            raise AssertionError("Only read-only explain calls are allowed")


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.bundle = self.root / "Surge CC Browser.app"
        self.binary = self.bundle / "Contents/MacOS/Google Chrome"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_text("fixture; never executed")
        self.binary.chmod(0o700)
        self.helper = self.bundle / ("Contents/Frameworks/Google Chrome Framework.framework/"
                                     "Versions/1.0/Helpers/Google Chrome Helper.app/"
                                     "Contents/MacOS/Google Chrome Helper")
        self.helper.parent.mkdir(parents=True)
        self.helper.write_text("helper fixture; never executed")
        self.helper.chmod(0o700)
        self.settings = dict(config(), proxy_url="http://127.0.0.1:62919",
                             browser_path=str(self.binary))
        self.original = (
            "[General]\nloglevel = notify\nhttp-listen = 127.0.0.1:6152\n"
            "socks5-listen = 127.0.0.1:6153\n" + profile() +
            "[Rule]\nDOMAIN-SUFFIX,unrelated.example,DIRECT\nFINAL,DIRECT\n")
        self.patched = scope.patch_profile(self.original, self.settings)
        self.surge = FakeSurge(self.settings, self.patched)

    def enable_cli_scope(self, *, exact=False):
        home = patch.object(scope.Path, "home", return_value=self.root)
        home.start()
        self.addCleanup(home.stop)
        self.versions = self.root / ".local/share/claude/versions"
        self.versions.mkdir(parents=True)
        self.cli_binary = self.versions / "2.1.296"
        self.cli_binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"native fixture; never executed")
        self.cli_binary.chmod(0o700)
        self.settings["cli_process_paths"] = [str(self.cli_binary) if exact else str(self.versions) + "/"]
        self.patched = scope.patch_profile(self.original, self.settings)
        self.surge = FakeSurge(self.settings, self.patched)

    def test_native_cli_prefix_adds_only_scoped_reject_after_browser(self):
        self.enable_cli_scope()
        rules = scope.profile_sections(self.patched)["rule"]
        self.assertEqual(scope._rule_fields(rules[0]), ["IN-PORT", "62919", "Claude"])
        self.assertEqual(scope._rule_fields(rules[1]), ["PROCESS-NAME", str(self.bundle) + "/", "REJECT"])
        self.assertEqual(scope._rule_fields(rules[2]), ["PROCESS-NAME", str(self.versions) + "/", "REJECT"])
        self.assertEqual(rules[3:], ["DOMAIN-SUFFIX,unrelated.example,DIRECT", "FINAL,DIRECT"])
        self.assertIn("http-listen = 127.0.0.1:6152, 127.0.0.1:62919", self.patched)
        self.assertIn("socks5-listen = 127.0.0.1:6153", self.patched)
        self.assertEqual(scope.patch_profile(self.patched, self.settings), self.patched)
        scope.validate_scope(self.settings, self.surge)
        self.assertEqual(len(self.surge.calls), 24)
        fields = [dict(item.split("=", 1) for item in call[3:]) for call in self.surge.calls]
        cli_fields = [item for item in fields if item["process-path"] == str(self.cli_binary)]
        self.assertEqual(len(cli_fields), 8)
        self.assertEqual({item["listen-port"] for item in cli_fields}, {"0", "62919"})
        self.assertEqual({item["protocol"] for item in cli_fields}, {"TCP", "UDP", "STUN", "QUIC", "HTTP", "HTTPS"})

    def test_native_cli_exact_file_scope_is_supported(self):
        self.enable_cli_scope(exact=True)
        scope.validate_scope(self.settings, self.surge)
        self.assertEqual(len(self.surge.calls), 24)
        self.assertTrue(scope.cli_scope_covers(self.settings, self.cli_binary))

    def test_new_native_version_is_checked_without_changing_prefix_rule(self):
        self.enable_cli_scope()
        updated = self.versions / "2.1.297"
        updated.write_bytes(self.cli_binary.read_bytes())
        updated.chmod(0o700)
        self.assertTrue(scope.cli_scope_covers(self.settings, updated))
        scope.validate_scope(self.settings, self.surge)
        self.assertEqual(len(self.surge.calls), 32)
        self.assertEqual(scope.patch_profile(self.original, self.settings), self.patched)

    def test_cli_reject_and_explicit_proxy_are_both_verified(self):
        self.enable_cli_scope()
        self.surge.bad_process = str(self.cli_binary)
        with self.assertRaisesRegex(Blocked, "CLI 程序"):
            scope.validate_scope(self.settings, self.surge)
        self.surge.bad_process = None
        self.surge.bad_entry_process = str(self.cli_binary)
        with self.assertRaisesRegex(Blocked, "专用 HTTP 入口"):
            scope.validate_scope(self.settings, self.surge)

    def test_cli_missing_or_reordered_reject_rule_blocks(self):
        self.enable_cli_scope()
        line = f'PROCESS-NAME,"{self.versions}/",REJECT\n'
        self.surge.text = self.patched.replace(line, "")
        with self.assertRaises(Blocked):
            scope.validate_scope(self.settings, self.surge)
        self.surge.text = self.patched.replace(line, "").replace("FINAL,DIRECT", line + "FINAL,DIRECT")
        with self.assertRaises(Blocked):
            scope.validate_scope(self.settings, self.surge)
        self.assertEqual(self.surge.calls, [])

    def test_cli_paths_reject_overbroad_interpreter_and_malformed_scopes(self):
        self.enable_cli_scope()
        bad = [None, "claude", ["/"], [str(self.root) + "/"], ["/usr/bin/"],
               ["/usr/bin/python3"], ["/usr/local/bin/node"], ["/bin/zsh"],
               [str(self.bundle) + "/"], ["relative/claude"], ["/tmp/../bin/claude"],
               ["/tmp//bin/claude"], ["/tmp/claude\n"], ['/tmp/a"/claude'],
               [str(self.versions) + "/"] * 2, [str(self.versions) + "/"] * 17]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(Blocked):
                scope.patch_profile(self.original, dict(self.settings, cli_process_paths=value))

    def test_cli_shared_interpreter_script_or_symlink_is_not_a_native_identity(self):
        self.enable_cli_scope(exact=True)
        self.cli_binary.write_text("#!/usr/bin/env node\n")
        with self.assertRaises(Blocked):
            scope.validate_scope(self.settings, self.surge)
        self.cli_binary.unlink()
        outside = self.root / "claude"
        outside.write_bytes(b"\xcf\xfa\xed\xfe")
        outside.chmod(0o700)
        self.cli_binary.symlink_to(outside)
        with self.assertRaises(Blocked):
            scope.validate_scope(self.settings, self.surge)
        self.assertEqual(self.surge.calls, [])

    def test_native_prefix_requires_usable_canonical_installed_binary(self):
        self.enable_cli_scope()
        self.cli_binary.unlink()
        with self.assertRaises(Blocked):
            scope.validate_scope(self.settings, self.surge)
        self.cli_binary.write_text("#!/bin/sh\n")
        self.cli_binary.chmod(0o700)
        with self.assertRaises(Blocked):
            scope.validate_scope(self.settings, self.surge)
        self.assertEqual(self.surge.calls, [])

    def test_cli_scope_coverage_resolves_entry_symlink_and_refuses_other_install(self):
        self.enable_cli_scope()
        alias = self.root / ".local/bin/claude"
        alias.parent.mkdir(parents=True)
        alias.symlink_to(self.cli_binary)
        self.assertTrue(scope.cli_scope_covers(self.settings, alias))
        outside = self.root / "claude"
        outside.write_bytes(self.cli_binary.read_bytes())
        outside.chmod(0o700)
        self.assertFalse(scope.cli_scope_covers(self.settings, outside))
        self.assertFalse(scope.cli_scope_covers(self.settings, self.root / "missing"))
        self.assertFalse(scope.cli_scope_covers(dict(self.settings, cli_process_paths=[]), self.cli_binary))

    def test_unrecognized_extra_owned_reject_rule_is_not_removed(self):
        self.enable_cli_scope()
        for path in ("/usr/bin/node", "/Users/", str(self.root) + "/"):
            source = self.patched.replace(scope.END, f'PROCESS-NAME,"{path}",REJECT\n' + scope.END)
            with self.subTest(path=path), self.assertRaises(Blocked):
                scope.patch_profile(source, self.settings)

    def test_disabling_cli_scope_only_removes_owned_cli_rules(self):
        self.enable_cli_scope()
        disabled = scope.patch_profile(self.patched, dict(self.settings, cli_process_paths=[]))
        self.assertNotIn(str(self.versions), disabled)
        self.assertIn(str(self.bundle), disabled)
        self.assertIn("DOMAIN-SUFFIX,unrelated.example,DIRECT\nFINAL,DIRECT\n", disabled)
        self.assertEqual(disabled, scope.patch_profile(self.original, dict(self.settings, cli_process_paths=[])))

    def test_valid_scope_checks_main_helper_and_raw_ipv4_ipv6_without_network(self):
        scope.validate_scope(self.settings, self.surge)
        self.assertEqual(len(self.surge.calls), 16)
        fields = [dict(item.split("=", 1) for item in call[3:]) for call in self.surge.calls]
        self.assertEqual({item["process-path"] for item in fields}, {str(self.binary), str(self.helper)})
        self.assertEqual({item["protocol"] for item in fields}, {"TCP", "UDP", "STUN", "QUIC", "HTTP", "HTTPS"})
        self.assertEqual({item["listen-port"] for item in fields}, {"0", "62919"})
        self.assertTrue(any(":" in call[2] for call in self.surge.calls))

    def test_surge_high_frequency_reject_drop_is_still_terminal_rejection(self):
        self.surge.reject_final = "REJECT-DROP"
        scope.validate_scope(self.settings, self.surge)
        self.assertEqual(len(self.surge.calls), 16)

    def test_unknown_or_mismatched_reject_response_does_not_pass(self):
        valid = {"rule-policy": "REJECT", "final": "REJECT-DROP", "final-type": "REJECT-DROP", "steps": []}
        for changed in (
            {"rule-policy": "DIRECT"}, {"final": "DIRECT"}, {"final-type": "REJECT"},
            {"final": "unknown", "final-type": "unknown"}, {"steps": [{"name": "other-proxy"}]},
        ):
            with self.subTest(changed=changed):
                self.assertFalse(scope._rejects(dict(valid, **changed)))

    def test_personal_chrome_and_non_app_binary_are_rejected(self):
        for value in (str(CHROME), "/usr/local/bin/chrome", "relative/Google Chrome"):
            with self.subTest(value=value), self.assertRaises(Blocked):
                scope.validate_scope(dict(self.settings, browser_path=value), self.surge)
        self.assertEqual(self.surge.calls, [])

    def test_missing_helper_and_symlinked_binary_block_before_surge_queries(self):
        self.helper.unlink()
        with self.assertRaises(Blocked):
            scope.validate_scope(self.settings, self.surge)
        self.helper.write_text("fixture")
        self.helper.chmod(0o700)
        target = self.root / "outside-binary"
        self.binary.rename(target)
        self.binary.symlink_to(target)
        with self.assertRaises(Blocked):
            scope.validate_scope(self.settings, self.surge)
        self.assertEqual(self.surge.calls, [])

    def test_helper_symlink_outside_bundle_is_rejected(self):
        self.helper.unlink()
        target = self.root / "outside-helper"
        target.write_text("fixture")
        target.chmod(0o700)
        self.helper.symlink_to(target)
        with self.assertRaises(Blocked):
            scope.validate_scope(self.settings, self.surge)

    def test_rule_mode_and_actual_boolean_enhanced_required(self):
        for mode, enhanced in (("direct", True), ("proxy", True), ("rule", False), ("rule", "true")):
            with self.subTest(mode=mode, enhanced=enhanced), self.assertRaises(Blocked):
                self.surge.state.update(mode=mode, features={"enhanced-mode": enhanced})
                scope.validate_scope(self.settings, self.surge)

    def test_default_ports_and_non_loopback_endpoint_block(self):
        for url in ("http://127.0.0.1:6152", "http://127.0.0.1:6153", "http://127.0.0.1:0",
                    "http://192.0.2.2:62919", "http://user:pass@127.0.0.1:62919"):
            with self.subTest(url=url), self.assertRaises(Blocked):
                scope.validate_scope(dict(self.settings, proxy_url=url), self.surge)

    def test_missing_public_or_authenticated_dedicated_listener_block(self):
        for replacement in ("", ", 0.0.0.0:62919", ", fixture@127.0.0.1:62919"):
            with self.subTest(replacement=replacement), self.assertRaises(Blocked):
                self.surge.text = self.patched.replace(", 127.0.0.1:62919", replacement)
                scope.validate_scope(self.settings, self.surge)

    def test_rule_order_policy_and_process_scope_are_exact(self):
        for text in (
            self.patched.replace(scope.BEGIN + "\n", scope.BEGIN + "\nDOMAIN,example.com,DIRECT\n"),
            self.patched.replace('IN-PORT,62919,"Claude"', 'IN-PORT,62919,DIRECT'),
            self.patched.replace(str(self.bundle) + "/", str(self.bundle.parent) + "/"),
            self.patched.replace('",REJECT', '",DIRECT'),
        ):
            with self.subTest(text=text), self.assertRaises(Blocked):
                self.surge.text = text
                scope.validate_scope(self.settings, self.surge)

    def test_raw_or_helper_bypass_is_not_misreported_as_safe(self):
        for protocol in ("TCP", "UDP", "STUN", "QUIC"):
            with self.subTest(protocol=protocol), self.assertRaises(Blocked):
                self.surge.bad_protocol = protocol
                scope.validate_scope(self.settings, self.surge)
        self.surge.bad_protocol = None
        self.surge.bad_process = str(self.helper)
        with self.assertRaises(Blocked):
            scope.validate_scope(self.settings, self.surge)

    def test_entry_bypass_and_group_fallback_are_blocked(self):
        self.surge.bad_entry = True
        with self.assertRaises(Blocked):
            scope.validate_scope(self.settings, self.surge)
        self.surge.bad_entry = False
        self.surge.group_value["options"].append({"name": "DIRECT", "enabled": True, "isGroup": False})
        with self.assertRaises(Blocked):
            scope.validate_scope(self.settings, self.surge)

    def test_effective_profile_drift_blocks_result(self):
        self.surge.final_text = self.patched + "# changed during checks\n"
        with self.assertRaises(Blocked):
            scope.validate_scope(self.settings, self.surge)

    def test_patch_is_idempotent_and_preserves_unrelated_text(self):
        self.assertEqual(scope.patch_profile(self.patched, self.settings), self.patched)
        self.assertIn("password=fixture", self.patched)
        self.assertIn("DOMAIN-SUFFIX,unrelated.example,DIRECT\nFINAL,DIRECT\n", self.patched)
        self.assertIn("socks5-listen = 127.0.0.1:6153", self.patched)
        self.assertEqual(self.patched.count(scope.BEGIN), 1)
        self.assertEqual(self.patched.count("127.0.0.1:62919"), 1)

    def test_missing_listeners_keep_observed_default_http_and_socks_entries(self):
        source = self.original.replace("http-listen = 127.0.0.1:6152\n", "").replace(
            "socks5-listen = 127.0.0.1:6153\n", "")
        patched = scope.patch_profile(source, self.settings)
        self.assertIn("http-listen = 127.0.0.1:6152, 127.0.0.1:62919", patched)
        self.assertIn("socks5-listen = 127.0.0.1:6153", patched)

    def test_legacy_listener_values_are_converted_without_losing_existing_ports(self):
        source = self.original.replace("http-listen = 127.0.0.1:6152",
                                       "interface = 0.0.0.0\nport = 7162").replace(
            "socks5-listen = 127.0.0.1:6153", "socks-interface = 127.0.0.1\nsocks-port = 7163")
        patched = scope.patch_profile(source, self.settings)
        self.assertIn("http-listen = 0.0.0.0:7162, 127.0.0.1:62919", patched)
        self.assertIn("socks5-listen = 127.0.0.1:7163", patched)
        self.assertNotIn("\ninterface =", patched)
        self.assertNotIn("\nport =", patched)
        self.assertNotIn("\nsocks-interface =", patched)

    def test_unknown_legacy_interface_or_port_is_not_guessed(self):
        source = self.original.replace("http-listen = 127.0.0.1:6152", "interface = en0\nport = 6152")
        with self.assertRaises(Blocked):
            scope.patch_profile(source, self.settings)
        source = self.original.replace("http-listen = 127.0.0.1:6152", "interface = 127.0.0.1\nport = auto")
        with self.assertRaises(Blocked):
            scope.patch_profile(source, self.settings)

    def test_existing_listener_auth_comments_and_crlf_are_preserved(self):
        source = self.original.replace("http-listen = 127.0.0.1:6152",
                                       "http-listen = private-fixture@127.0.0.1:6152  # local users")
        patched = scope.patch_profile(source.replace("\n", "\r\n"), self.settings)
        self.assertIn("private-fixture@127.0.0.1:6152, 127.0.0.1:62919  # local users\r\n", patched)
        self.assertNotIn("\n", patched.replace("\r\n", ""))

    def test_only_owned_rule_blocks_are_removed_and_unmarked_rules_preserved(self):
        source = self.original.replace("[Rule]\n", '[Rule]\nIN-PORT,62919,"Claude"\n')
        patched = scope.patch_profile(source, self.settings)
        self.assertEqual(patched.count('IN-PORT,62919,"Claude"'), 2)
        self.assertEqual(scope.patch_profile(patched, self.settings), patched)

    def test_partial_or_modified_owned_markers_are_not_deleted(self):
        for source in (self.patched.replace(scope.END, "# missing end"),
                       self.patched.replace(scope.BEGIN, "# missing begin"),
                       self.patched.replace(scope.END, "DOMAIN,unknown.example,DIRECT\n" + scope.END)):
            with self.subTest(source=source), self.assertRaises(Blocked):
                scope.patch_profile(source, self.settings)

    def test_duplicate_sections_or_listener_keys_are_rejected(self):
        for addition in ("[General]\nloglevel=info\n", "[Rule]\nFINAL,DIRECT\n"):
            with self.subTest(addition=addition), self.assertRaises(Blocked):
                scope.patch_profile(self.original + addition, self.settings)
        source = self.original.replace("loglevel = notify", "http-listen = 127.0.0.1:7000")
        with self.assertRaises(Blocked):
            scope.patch_profile(source, self.settings)

    def test_modern_legacy_listener_ambiguity_is_not_silently_resolved(self):
        for extra in ("interface = 127.0.0.1\nport = 7162\n", "socks-port = 7163\n"):
            with self.subTest(extra=extra), self.assertRaises(Blocked):
                source = self.original.replace("[General]\n", "[General]\n" + extra)
                scope.patch_profile(source, self.settings)

    def test_socks_listener_collision_is_blocked_without_changing_the_port(self):
        for listener in ("socks5-listen = 127.0.0.1:62919",
                         "socks-interface = 127.0.0.1\nsocks-port = 62919"):
            with self.subTest(listener=listener), self.assertRaises(Blocked):
                source = self.original.replace("socks5-listen = 127.0.0.1:6153", listener)
                scope.patch_profile(source, self.settings)

    def test_missing_general_section_creates_both_preserved_defaults(self):
        source = self.original[self.original.index("[Proxy]"):]
        patched = scope.patch_profile(source, self.settings)
        self.assertTrue(patched.startswith("[General]\n"))
        self.assertIn("127.0.0.1:6152, 127.0.0.1:62919", patched)
        self.assertIn("socks5-listen = 127.0.0.1:6153", patched)


if __name__ == "__main__":
    unittest.main()

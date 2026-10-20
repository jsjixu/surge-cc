"""Offline regression checks for route validation and fail-closed startup gates."""
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import core


def config():
    return core.validate_config({
        "schema": 1, "group": "Claude", "policy": "Home",
        "expected_ip": "203.0.113.10", "proxy_url": "http://127.0.0.1:6152",
        "profile_path": "/test/profile.conf",
    })


def group():
    return {"name": "Claude", "type": "手动选择策略组", "selected": "Home",
            "options": [{"name": "Home", "enabled": True, "isGroup": False}]}


def profile(group_fields="select, Home", node_fields="ss, example.invalid, 443, password=fixture"):
    return f"[Proxy]\nHome = {node_fields}\n[Proxy Group]\nClaude = {group_fields}\n"


def route():
    return {"rule-policy": "Claude", "final": "Home", "final-type": "Shadowsocks",
            "steps": [{"group": "Claude", "selected": "Home", "reason": "user selection"}]}


class FakeSurge:
    def __init__(self):
        self.status_calls = 0
        self.group_calls = 0
        self.route_calls = []
        self.exit_calls = 0
        self.status_value = {"mode": "rule", "features": {}, "profile-path": "/test/profile.conf"}
        self.group_value = group()
        self.profile_value = profile()
        self.route_value = route()
        self.exit_value = True
        self.final_mode = None
        self.final_profile = None
        self.change_host_after_probe = None

    def status(self):
        self.status_calls += 1
        data = deepcopy(self.status_value)
        if self.status_calls > 1 and self.final_mode:
            data["mode"] = self.final_mode
        if self.status_calls > 1 and self.final_profile:
            data["profile-path"] = self.final_profile
        return data

    def group(self, name):
        self.group_calls += 1
        return deepcopy(self.group_value)

    def profile(self):
        return self.profile_value

    def route(self, host, settings, process):
        self.route_calls.append((host, process))
        data = deepcopy(self.route_value)
        if self.exit_calls and host == self.change_host_after_probe:
            data["final"] = "DIRECT"
            data["final-type"] = "Direct"
        return data

    def exit_matches(self, settings):
        self.exit_calls += 1
        if isinstance(self.exit_value, Exception):
            raise self.exit_value
        return self.exit_value


class TopologyTests(unittest.TestCase):
    def test_single_enabled_leaf_select_is_accepted(self):
        core.validate_topology(profile(), group(), config())

    def test_empty_or_multiple_members_blocked(self):
        for options in ([], group()["options"] * 2):
            with self.subTest(options=options), self.assertRaises(core.Blocked):
                candidate = group()
                candidate["options"] = options
                core.validate_topology(profile(), candidate, config())

    def test_disabled_nested_wrong_member_blocked(self):
        for change in ({"enabled": False}, {"isGroup": True}, {"name": "DIRECT"}, {"name": "Other"}):
            with self.subTest(change=change), self.assertRaises(core.Blocked):
                candidate = group()
                candidate["options"][0].update(change)
                core.validate_topology(profile(), candidate, config())

    def test_automatic_groups_and_extra_direct_members_blocked(self):
        for fields in ("fallback, Home", "url-test, Home", "smart, Home", "load-balance, Home",
                       "select, Home, DIRECT", "select, Nested"):
            with self.subTest(fields=fields), self.assertRaises(core.Blocked):
                core.validate_topology(profile(fields), group(), config())

    def test_dynamic_imports_blocked(self):
        for field in ("policy-path=https://example.invalid/list", "include-other-group=Other",
                      "include-all-proxies=true", "include-all-proxy-groups=1"):
            with self.subTest(field=field), self.assertRaises(core.Blocked):
                core.validate_topology(profile("select, Home, " + field), group(), config())

    def test_explicitly_disabled_dynamic_imports_accepted(self):
        core.validate_topology(profile("select, Home, include-all-proxies=0"), group(), config())

    def test_duplicate_definitions_blocked(self):
        for extra in ("[Proxy Group]\nClaude = select, Home\n", "[Proxy]\nHome = direct\n"):
            with self.subTest(extra=extra), self.assertRaises(core.Blocked):
                core.validate_topology(profile() + extra, group(), config())

    def test_node_underlying_proxy_is_blocked_including_spacing(self):
        for field in ("underlying-proxy=Relay", "underlying-proxy = Relay", "UNDERLYING-PROXY=Relay"):
            with self.subTest(field=field), self.assertRaises(core.Blocked):
                core.validate_topology(profile(node_fields="ss, example.invalid, 443, " + field), group(), config())

    def test_group_underlying_proxy_is_blocked(self):
        with self.assertRaises(core.Blocked):
            core.validate_topology(profile("select, Home, underlying-proxy=Relay"), group(), config())

    def test_direct_node_definition_blocked(self):
        with self.assertRaises(core.Blocked):
            core.validate_topology(profile(node_fields="direct"), group(), config())

    def test_malformed_group_and_option_shapes_are_blocked(self):
        for candidate in (None, [], {"options": None}, {"options": [None]},
                          {"options": ["Home"]}, {"options": [[]]}):
            with self.subTest(candidate=candidate), self.assertRaises(core.Blocked):
                core.validate_topology(profile(), candidate, config())
        with self.assertRaises(core.Blocked):
            core.validate_topology(None, group(), config())

    def test_empty_group_or_node_definition_is_blocked(self):
        for text in (profile(group_fields=""), profile(group_fields=", Home"),
                     profile(node_fields=""), profile(node_fields=", example.invalid")):
            with self.subTest(text=text), self.assertRaises(core.Blocked):
                core.validate_topology(text, group(), config())


class RouteTests(unittest.TestCase):
    def test_exact_route_passes(self):
        self.assertTrue(core.route_is_fixed(route(), config()))

    def test_wrong_leaf_group_nested_and_substitute_blocked(self):
        mutations = [
            {"final": "Other"}, {"rule-policy": "Other"}, {"final-type": "DIRECT"},
            {"final-type": "SUBSTITUTE"}, {"steps": []}, {"steps": route()["steps"] * 2},
            {"steps": [{"group": "Claude", "selected": "Home", "reason": "automatic selection"}]},
            {"steps": [{"group": "Claude", "selected": "Other", "reason": "user selection"}]},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = route()
                value.update(mutation)
                self.assertFalse(core.route_is_fixed(value, config()))

    def test_malformed_route_step_and_final_type_are_false(self):
        for value in (None, [], "route", 0):
            with self.subTest(value=value):
                self.assertFalse(core.route_is_fixed(value, config()))
        for mutation in ({"steps": None}, {"steps": [None]}, {"steps": ["Home"]},
                         {"steps": [[]]}, {"final-type": None}, {"final-type": 1},
                         {"final-type": []}, {"final-type": "   "}):
            with self.subTest(mutation=mutation):
                value = route()
                value.update(mutation)
                self.assertFalse(core.route_is_fixed(value, config()))


class SurgeTransportTests(unittest.TestCase):
    def test_nonzero_stdout_json_still_blocks_without_leaking_output(self):
        runner = Mock(return_value=subprocess.CompletedProcess([], 19, '{"ok":true}', "SECRET_TEST_ERROR"))
        with self.assertRaises(core.Blocked) as exc:
            core.Surge(run=runner).status()
        self.assertNotIn("SECRET_TEST_ERROR", str(exc.exception))

    def test_malformed_unknown_and_error_responses_block(self):
        for payload in ("not json", "[]", "null", '{"error":"SECRET_TEST_ERROR"}'):
            with self.subTest(payload=payload), self.assertRaises(core.Blocked):
                runner = Mock(return_value=subprocess.CompletedProcess([], 0, payload, ""))
                core.Surge(run=runner).status()

    def test_controller_timeout_or_missing_binary_blocks(self):
        for failure in (OSError("private detail"), subprocess.TimeoutExpired("surge", 2)):
            with self.subTest(failure=type(failure)), self.assertRaises(core.Blocked):
                core.Surge(run=Mock(side_effect=failure)).status()

    def test_group_set_uses_argv_without_shell_or_credentials(self):
        surge = core.Surge()
        surge.group = Mock(return_value=group())
        surge.profile = Mock(return_value=profile())
        surge.call = Mock(return_value={})
        surge.pin(config())
        surge.call.assert_called_once_with("policy-group", "set", "Claude", "Home")

    def test_pin_refuses_invalid_topology_before_mutation(self):
        surge = core.Surge()
        value = group()
        value["options"] = []
        surge.group = Mock(return_value=value)
        surge.profile = Mock(return_value=profile())
        surge.call = Mock()
        with self.assertRaises(core.Blocked):
            surge.pin(config())
        surge.call.assert_not_called()

    def test_exit_probe_handles_match_mismatch_error_and_deletes_temp_script(self):
        for status, match, expected in ((200, True, True), (200, False, False), (503, True, False)):
            with self.subTest(status=status, match=match):
                seen = []
                def runner(argv, **kwargs):
                    probe = Path(argv[3])
                    seen.append(probe)
                    source = probe.read_text()
                    self.assertEqual(probe.stat().st_mode & 0o777, 0o600)
                    self.assertIn("'auto-redirect':false", source)
                    marker = re.search(r'SURGE_CC_[a-f0-9]+:', source).group()
                    payload = {"result": None, "output": "time " + marker + json.dumps({"status": status, "match": match}) + "\n"}
                    return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")
                self.assertIs(core.Surge(run=runner).exit_matches(config()), expected)
                self.assertTrue(seen)
                self.assertFalse(seen[0].exists())

    def test_missing_exit_probe_marker_is_failure(self):
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, '{"output":"Script Completed"}', ""))
        with self.assertRaises(core.Blocked):
            core.Surge(run=runner).exit_matches(config())

    def test_nonobject_exit_marker_payload_is_failure(self):
        for payload in ("[]", "null", "true", '"text"'):
            with self.subTest(payload=payload):
                def runner(argv, **kwargs):
                    source = Path(argv[3]).read_text()
                    marker = re.search(r'SURGE_CC_[a-f0-9]+:', source).group()
                    result = {"output": marker + payload + "\n"}
                    return subprocess.CompletedProcess(argv, 0, json.dumps(result), "")
                with self.assertRaises(core.Blocked):
                    core.Surge(run=runner).exit_matches(config())


class GateTests(unittest.TestCase):
    def gate(self, surge, probe=None):
        return core.run_checks(config(), surge=surge, probe=probe or Mock(return_value=(True, "mock connected")),
                               claude_path=Path("/test/claude"))

    def test_full_pass_checks_all_hosts_and_processes(self):
        surge = FakeSurge()
        report = self.gate(surge)
        self.assertTrue(report["ok"])
        self.assertEqual(set(core.CHECK_IDS), {r["id"] for r in report["checks"]})
        for host in config()["hosts"]:
            self.assertIn((host, "/test/claude"), surge.route_calls)
            self.assertIn((host, str(core.CHROME)), surge.route_calls)

    def test_missing_checks_cannot_be_passed_by_partial_report(self):
        self.assertFalse(core.result([core.row("surge", "Surge", True, "")])["ok"])
        all_rows = [core.row(k, k, True, "") for k in core.CHECK_IDS]
        self.assertFalse(core.result(all_rows + [all_rows[0]])["ok"])

    def test_wrong_initial_mode_prevents_network_probes(self):
        surge = FakeSurge()
        surge.status_value["mode"] = "direct"
        probe = Mock()
        self.assertFalse(self.gate(surge, probe)["ok"])
        probe.assert_not_called()
        self.assertEqual(surge.exit_calls, 0)

    def test_wrong_profile_fails(self):
        surge = FakeSurge()
        surge.status_value["profile-path"] = "/test/other.conf"
        self.assertFalse(self.gate(surge)["ok"])

    def test_wrong_route_prevents_probes(self):
        surge = FakeSurge()
        surge.route_value["final"] = "DIRECT"
        probe = Mock()
        self.assertFalse(self.gate(surge, probe)["ok"])
        probe.assert_not_called()

    def test_ip_change_or_failed_probe_blocks(self):
        for value in (False, core.Blocked("probe failed")):
            with self.subTest(value=str(value)):
                surge = FakeSurge()
                surge.exit_value = value
                self.assertFalse(self.gate(surge)["ok"])
        surge = FakeSurge()
        self.assertFalse(self.gate(surge, Mock(return_value=(False, "unavailable")))["ok"])
        self.assertEqual(surge.exit_calls, 0)

    def test_mode_or_profile_changed_during_check_blocks(self):
        for key, value in (("final_mode", "direct"), ("final_profile", "/test/other.conf")):
            with self.subTest(key=key):
                surge = FakeSurge()
                setattr(surge, key, value)
                self.assertFalse(self.gate(surge)["ok"])

    def test_non_api_domain_route_change_during_check_blocks(self):
        surge = FakeSurge()
        surge.change_host_after_probe = "claude.ai"
        self.assertFalse(self.gate(surge)["ok"])


class EnvironmentAndBrowserTests(unittest.TestCase):
    def test_proxy_environment_removes_case_variants_and_bypasses(self):
        base = {"HTTPS_PROXY": "http://other.invalid", "NO_PROXY": "*", "No_Proxy": "example.invalid",
                "npm_config_proxy": "http://other.invalid", "npm_config_noproxy": "*", "KEEP": "yes"}
        actual = core.proxy_env(config()["proxy_url"], base)
        self.assertEqual(base["NO_PROXY"], "*")
        self.assertEqual(actual["KEEP"], "yes")
        self.assertEqual(actual["NO_PROXY"], "")
        self.assertEqual(actual["no_proxy"], "")
        self.assertNotIn("No_Proxy", actual)
        self.assertNotIn("npm_config_noproxy", actual)
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            self.assertEqual(actual[key], config()["proxy_url"])

    @patch.object(core, "listener_is_surge", return_value=True)
    def test_local_proxy_test_never_uses_direct_fallback(self, listener):
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, "401", ""))
        self.assertTrue(core.local_proxy_check(config(), run=runner)[0])
        argv = runner.call_args.args[0]
        self.assertIn("--disable", argv)
        self.assertEqual(argv[argv.index("--proxy") + 1], config()["proxy_url"])
        self.assertEqual(argv[argv.index("--noproxy") + 1], "")
        self.assertEqual(runner.call_count, 1)
        runner.return_value = subprocess.CompletedProcess([], 7, "000", "private detail")
        self.assertFalse(core.local_proxy_check(config(), run=runner)[0])

    def test_provider_environment_rejects_alternate_endpoints(self):
        for env in ({"ANTHROPIC_BASE_URL": "https://other.invalid"}, {"CLAUDE_CODE_USE_BEDROCK": "1"},
                    {"CLAUDE_CODE_USE_VERTEX": "true"}, {"CLAUDE_CODE_USE_FOUNDRY": "1"}):
            with self.subTest(env=env):
                self.assertFalse(core.provider_environment_ok(env))
        self.assertTrue(core.provider_environment_ok({"ANTHROPIC_BASE_URL": "https://api.anthropic.com/"}))

    def test_chrome_gets_separate_profile_fixed_proxy_and_no_direct_fallback(self):
        folder = Path("/test/Surge CC/Browser")
        args = core.chrome_args(config(), folder)
        self.assertIn("--user-data-dir=" + str(folder), args)
        self.assertIn("--proxy-server=http://127.0.0.1:6152", args)
        self.assertIn("--proxy-bypass-list=<-loopback>", args)
        self.assertIn("--disable-quic", args)
        self.assertFalse(any("direct://" in a.lower() for a in args))
        self.assertFalse(any("--profile-directory=Default" == a for a in args))

    def test_config_cannot_remove_baseline_domains(self):
        value = config()
        value["hosts"] = []
        self.assertEqual(core.validate_config(value)["hosts"], list(core.DEFAULT_HOSTS))

    def test_nonloopback_authenticated_or_nonhttp_proxy_rejected(self):
        for url in ("http://203.0.113.10:6152", "http://user:secret@127.0.0.1:6152", "socks5://127.0.0.1:6153"):
            with self.subTest(url=url), self.assertRaises(core.Blocked):
                value = config()
                value["proxy_url"] = url
                core.validate_config(value)


if __name__ == "__main__":
    unittest.main()

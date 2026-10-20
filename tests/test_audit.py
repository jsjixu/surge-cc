"""Read-only audit tests. All OS commands, DNS, GeoIP and Chrome are mocked."""
from copy import deepcopy
import json
import ipaddress
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import audit, browser_probe, core


def settings():
    return {"expected_ip": "203.0.113.10", "proxy_url": "http://127.0.0.1:6152",
            "expected_timezone": "", "expected_locale": "", "expected_country": "",
            "expected_asn": "", "browser_language": "", "privacy_strict": True}


INTERFACES = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
    inet6 ::1 prefixlen 128
    inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    inet6 fe80::ab%en0 prefixlen 64 scopeid 0x4
    status: active
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    inet6 2001:db8::55 prefixlen 64
    status: inactive
"""
ROUTES = """Routing tables
Internet6:
Destination                             Gateway                         Flags         Netif Expire
::1                                     ::1                             UHL             lo0
"""


class FakeSurge:
    def __init__(self):
        self.status_value = {"features": {"enhanced-mode": True, "system-proxy": True}}
        self.dns = {"domain": "claude.ai", "v4Addresses": ["203.0.113.20"], "v6Addresses": [],
                    "server": "https://dns.example.invalid/private-secret?q=private-secret",
                    "interface": "utun9", "path": "do-not-output-private-secret", "logs": ["private-secret"]}
        self.geo = {"address": "203.0.113.10", "country": "US", "asn": 64512,
                    "organization": "Example Network", "geoip-db-date": 1700000000, "asn-db-date": 1700000000}

    def status(self):
        return deepcopy(self.status_value)

    def call(self, *args, **kwargs):
        result = self.dns if args[:2] == ("dns", "lookup") else self.geo
        if isinstance(result, Exception):
            raise result
        return deepcopy(result)


def runner(argv, **kwargs):
    outputs = {
        ("/usr/sbin/scutil", "--dns"): "resolver #1\n nameserver[0] : 198.18.0.2\n",
        ("/usr/bin/dscacheutil", "-q", "host", "-a", "name", "claude.ai"): "name: claude.ai\nip_address: 198.18.0.10\n",
        ("/sbin/ifconfig", "-a"): INTERFACES,
        ("/usr/sbin/netstat", "-rn", "-f", "inet6"): ROUTES,
        ("/usr/bin/readlink", "/etc/localtime"): "/var/db/timezone/zoneinfo/America/Los_Angeles\n",
        ("/usr/bin/defaults", "read", "-g", "AppleLocale"): "en_US\n",
        ("/usr/bin/defaults", "read", "-g", "AppleLanguages"): '(\n "en-US",\n "zh-Hans"\n)\n',
    }
    key = tuple(argv)
    if key not in outputs:
        raise AssertionError("Unexpected command: " + repr(argv))
    return subprocess.CompletedProcess(argv, 0, outputs[key], "")


class DNSTests(unittest.TestCase):
    def test_dns_checks_target_claude_for_both_resolvers(self):
        surge = FakeSurge()
        surge.call = Mock(wraps=surge.call)
        run = Mock(side_effect=runner)
        audit.dns_checks(settings(), surge, surge.status(), run)
        surge.call.assert_called_once_with("dns", "lookup", "claude.ai", timeout=12)
        self.assertIn(("/usr/bin/dscacheutil", "-q", "host", "-a", "name", "claude.ai"),
                      [tuple(call.args[0]) for call in run.call_args_list])

    def test_dns_takeover_is_scoped_and_egress_stays_unknown_nonrequired(self):
        rows = audit.dns_checks(settings(), FakeSurge(), FakeSurge().status(), runner)
        self.assertEqual(rows[0]["status"], "pass")
        self.assertTrue(rows[0]["required"])
        self.assertIn("有限证据", rows[0]["evidence_scope"])
        self.assertIn("FakeIP 不是递归 DNS 出口证明", rows[0]["evidence_scope"])
        self.assertEqual(rows[1]["status"], "unknown")
        self.assertFalse(rows[1]["required"])
        self.assertIn("本次尚未执行外部观测", rows[1]["detail"])
        self.assertIn("通常不必等于住宅代理出口", " ".join(rows[1]["evidence"]))
        self.assertNotIn("private-secret", json.dumps(rows))
        self.assertIn("https://dns.example.invalid/…", " ".join(rows[0]["evidence"]))
        self.assertIn("utun9", " ".join(rows[0]["evidence"]))
        self.assertLess(len(rows[0]["detail"]), 60)

    def test_failed_lookup_or_os_resolution_is_unknown(self):
        surge = FakeSurge()
        surge.dns = core.Blocked("private failure")
        self.assertEqual(audit.dns_checks(settings(), surge, surge.status(), runner)[0]["status"], "unknown")
        failed = Mock(side_effect=subprocess.TimeoutExpired("read", 5))
        self.assertEqual(audit.dns_checks(settings(), FakeSurge(), surge.status(), failed)[0]["status"], "unknown")

    def test_surge_lookup_alone_does_not_prove_system_takeover(self):
        def direct_dns(argv, **kwargs):
            value = runner(argv, **kwargs)
            value.stdout = value.stdout.replace("198.18.0.2", "203.0.113.53").replace("198.18.0.10", "203.0.113.20")
            return value
        row = audit.dns_checks(settings(), FakeSurge(), FakeSurge().status(), direct_dns)[0]
        self.assertEqual(row["status"], "warn")

    def test_fake_ip_and_private_doh_url_handling(self):
        self.assertTrue(audit.is_fake_ip("198.18.0.1"))
        self.assertTrue(audit.is_fake_ip("198.19.0.1"))
        self.assertTrue(audit.is_fake_ip("fd00:6152::1"))
        self.assertFalse(audit.is_fake_ip("203.0.113.10"))
        self.assertFalse(audit.is_fake_ip(None))
        self.assertEqual(audit.safe_dns_server("https://user:secret@dns.example.invalid:443/private?key=secret"),
                         "https://dns.example.invalid:443/…")


class IPv6Tests(unittest.TestCase):
    def test_malformed_interface_or_default_route_is_unknown(self):
        for target, content in (
                ("/sbin/ifconfig", INTERFACES.replace("fe80::ab%en0", "invalid-ipv6")),
                ("/sbin/ifconfig", INTERFACES.replace("fe80::ab%en0", "1.1.1.1")),
                ("/usr/sbin/netstat", ROUTES + "default fe80::1%utun9\n"),
                ("/usr/sbin/netstat", ROUTES + "default invalid-gateway UGcIg utun9\n"),
                ("/usr/sbin/netstat", ROUTES + "default 1.1.1.1 UGcIg utun9\n"),
                ("/usr/sbin/netstat", ROUTES.replace("Internet6:", "Internet:")),
                ("/usr/sbin/netstat", "Destination only; malformed inventory")):
            def malformed(argv, **kwargs):
                if argv[0] == target:
                    return subprocess.CompletedProcess(argv, 0, content, "")
                return runner(argv, **kwargs)
            self.assertEqual(audit.ipv6_check(settings(), malformed)["status"], "unknown")

    def test_inactive_interface_is_excluded(self):
        interfaces = audit.ipv6_interfaces(INTERFACES)
        self.assertEqual([v["name"] for v in interfaces], ["lo0", "en0"])
        row = audit.ipv6_check(settings(), runner)
        self.assertEqual(row["status"], "info")
        self.assertFalse(row["required"])
        self.assertNotIn("en1", " ".join(row["evidence"]))

    def test_linklocal_with_utun_defaults_is_information_not_leak_warning(self):
        def with_route(argv, **kwargs):
            value = runner(argv, **kwargs)
            if "netstat" in argv[0]:
                value.stdout += "default fe80::1%utun9 UGcIg utun9\n" \
                                "default link#24 UGcIg utun10\n"
            if "ifconfig" in argv[0]:
                value.stdout += "utun9: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n" \
                                "    inet6 fe80::abcd%utun9 prefixlen 64\n"
            return value
        row = audit.ipv6_check(settings(), with_route)
        self.assertEqual(row["status"], "info")
        self.assertFalse(row["required"])
        self.assertIn("不能据此证明没有旁路", row["detail"])
        evidence = " ".join(row["evidence"])
        self.assertIn("en0（物理接口）：链路本地 ×1", evidence)
        self.assertIn("utun9（utun 隧道）：链路本地 ×1", evidence)
        self.assertIn("默认路由：utun10（utun 隧道）", evidence)
        self.assertIn("不同的 VPN", row["evidence_scope"])

    def test_physical_global_or_default_and_unknown_interface_remain_warning(self):
        for target, suffix in (
                ("/sbin/ifconfig", "en2: flags=8863<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500\n"
                 "    inet6 2606:4700::1111 prefixlen 64\n    status: active\n"),
                ("/usr/sbin/netstat", "default fe80::1%en0 UGcIg en0\n"),
                ("/usr/sbin/netstat", "default fe80::1%bridge0 UGcIg bridge0\n")):
            with self.subTest(target=target, suffix=suffix):
                def non_tunnel(argv, **kwargs):
                    value = runner(argv, **kwargs)
                    if argv[0] == target:
                        value.stdout += suffix
                    return value
                row = audit.ipv6_check(settings(), non_tunnel)
                self.assertEqual(row["status"], "warn")
                self.assertFalse(row["required"])
                self.assertIn("尚未证实泄漏", row["detail"])

    def test_loopback_ula_linklocal_and_tunnel_global_are_distinguished(self):
        def varied(argv, **kwargs):
            value = runner(argv, **kwargs)
            if "ifconfig" in argv[0]:
                value.stdout += "    inet6 fd12:3456::1 prefixlen 64\n" \
                                "utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n" \
                                "    inet6 2606:4700::1111 prefixlen 64\n"
                value.stdout = value.stdout.replace("    status: inactive", "    status: active")
            return value
        row = audit.ipv6_check(settings(), varied)
        self.assertEqual(row["status"], "info")
        evidence = " ".join(row["evidence"])
        self.assertIn("lo0（回环接口）：链路本地 ×1、回环 ×1", evidence)
        self.assertIn("ULA 内网 ×1", evidence)
        self.assertIn("utun8（utun 隧道）：公网 ×1", evidence)
        self.assertIn("其他 ×1", evidence)  # Documentation prefix is not a public address.

    def test_multicast_is_not_classified_as_a_public_unicast_path(self):
        def multicast(argv, **kwargs):
            value = runner(argv, **kwargs)
            if "ifconfig" in argv[0]:
                value.stdout = value.stdout.replace("fe80::ab%en0", "ff0e::1")
            return value
        row = audit.ipv6_check(settings(), multicast)
        self.assertEqual(row["status"], "info")
        self.assertIn("en0（物理接口）：其他 ×1", " ".join(row["evidence"]))

    def test_failed_route_inventory_is_unknown_not_no_route(self):
        def failed_route(argv, **kwargs):
            if "netstat" in argv[0]:
                return subprocess.CompletedProcess(argv, 1, "", "private failure")
            return runner(argv, **kwargs)
        row = audit.ipv6_check(settings(), failed_route)
        self.assertEqual(row["status"], "unknown")
        self.assertTrue(row["required"])
        loose = settings()
        loose["privacy_strict"] = False
        self.assertFalse(audit.ipv6_check(loose, failed_route)["required"])


class EnvironmentTests(unittest.TestCase):
    def test_environment_display_is_optional_without_expectations(self):
        rows = audit.environment_checks(settings(), runner)
        self.assertEqual([row["status"] for row in rows], ["info", "info", "info"])
        self.assertTrue(all(not row["required"] for row in rows))
        self.assertIn("America/Los_Angeles", rows[0]["detail"])
        self.assertIn("zh-Hans", rows[2]["detail"])

    def test_environment_expectation_compares_without_mutating(self):
        config = settings()
        config.update(expected_timezone="America/Los_Angeles", expected_locale="zh_CN")
        recorded = Mock(side_effect=runner)
        rows = audit.environment_checks(config, recorded)
        self.assertEqual(rows[0]["status"], "pass")
        self.assertEqual(rows[1]["status"], "warn")
        self.assertTrue(rows[1]["required"])
        self.assertTrue(all("write" not in call.args[0] and "systemsetup" not in call.args[0] for call in recorded.call_args_list))

    def test_unreadable_timezone_never_infers_locale_based_location(self):
        rows = audit.environment_checks(settings(), Mock(return_value=subprocess.CompletedProcess([], 1, "", "")))
        self.assertEqual([row["status"] for row in rows], ["unknown", "unknown", "unknown"])


class GeoIPTests(unittest.TestCase):
    def test_local_database_preferred_no_network_call_and_not_home_guarantee(self):
        config = settings()
        config.update(expected_country="US", expected_asn="AS64512")
        unused_run = Mock(side_effect=AssertionError("Unexpected network call"))
        rows = audit.geoip_checks(config, FakeSurge(), unused_run)
        self.assertEqual([row["status"] for row in rows], ["pass", "pass"])
        self.assertIn("不能保证", rows[1]["detail"])
        self.assertIn("本地数据库", rows[0]["detail"])
        unused_run.assert_not_called()

    @patch.object(audit, "listener_is_surge", return_value=True)
    def test_http_fallback_is_explicit_proxy_without_environment_bypass(self, listener):
        surge = FakeSurge()
        surge.geo = core.Blocked("unsupported")
        data = {"success": True, "ip": "203.0.113.10", "country_code": "US",
                "connection": {"asn": 64512, "org": "Example Network"}}
        run = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(data), ""))
        rows = audit.geoip_checks(settings(), surge, run)
        self.assertEqual(rows[0]["status"], "info")
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("--proxy") + 1], settings()["proxy_url"])
        self.assertEqual(args[args.index("--noproxy") + 1], "")
        self.assertIn("--disable", args)
        self.assertNotIn("--location", args)
        self.assertEqual(run.call_args.kwargs["env"]["NO_PROXY"], "")

    @patch.object(audit, "listener_is_surge", return_value=True)
    def test_wrong_ip_failed_payload_or_timeout_is_unknown(self, listener):
        surge = FakeSurge()
        surge.geo = None
        for payload in ({"success": False}, {"success": True, "ip": "203.0.113.11"}, []):
            with self.subTest(payload=payload):
                run = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), ""))
                rows = audit.geoip_checks(settings(), surge, run)
                self.assertEqual(rows[0]["status"], "unknown")
        rows = audit.geoip_checks(settings(), surge, Mock(side_effect=subprocess.TimeoutExpired("curl", 12)))
        self.assertEqual(rows[0]["status"], "unknown")


class AuditIntegrationTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(audit, "observe_proxy_dns", return_value=browser_probe.check_row(
            "dns_egress", "专用代理 DNS 出口实测", "info", "本次观测完成。", False))
        self.dns = patcher.start()
        self.addCleanup(patcher.stop)

    @patch.object(audit, "chrome_probe_check")
    def test_quick_audit_never_starts_browser_or_reuses_pass(self, browser):
        rows = audit.audit_checks(settings(), surge=FakeSurge(), run=runner, browser=False)
        browser.assert_not_called()
        self.dns.assert_not_called()
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(len(by_id), len(rows))
        self.assertEqual(by_id["browser_webrtc"]["status"], "unknown")
        self.assertTrue(by_id["browser_webrtc"]["required"])
        self.assertFalse(by_id["dns_egress"]["required"])
        for row in rows:
            required_fields = {"id", "title", "status", "detail", "required"}
            self.assertTrue(required_fields <= set(row))
            self.assertTrue(set(row) <= required_fields | {"evidence", "evidence_scope"})
            if "evidence" in row:
                self.assertIsInstance(row["evidence"], list)
                self.assertTrue(all(isinstance(item, str) for item in row["evidence"]))
                self.assertIsInstance(row["evidence_scope"], str)

    @patch.object(audit, "chrome_probe_check")
    def test_default_audit_calls_account_free_probe_once(self, browser):
        browser.return_value = {"id": "browser_webrtc", "title": "probe", "status": "unknown",
                                "detail": "mock only", "required": True}
        audit.audit_checks(settings(), surge=FakeSurge(), run=runner)
        browser.assert_called_once()

    @patch("surge_cc.containment.validate_scope")
    @patch.object(audit, "chrome_probe_check")
    def test_dedicated_scope_checked_before_and_after_browser_probe(self, browser, scope):
        calls = []
        scope.side_effect = lambda *args: calls.append("scope")

        def probe(*args, **kwargs):
            self.assertIs(kwargs.get("containment_verified"), True)
            calls.append("browser")
            return browser_probe.check_row("browser_webrtc", "probe", "pass", "bounded probe", True)

        browser.side_effect = probe
        scoped = dict(settings(), browser_path="/fixture/Surge CC Browser.app/Contents/MacOS/Google Chrome")
        rows = audit.audit_checks(scoped, surge=FakeSurge(), run=runner)
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(calls, ["scope", "browser", "scope"])
        self.assertEqual(by_id["browser_containment"]["status"], "pass")
        self.assertEqual(by_id["browser_webrtc"]["status"], "pass")
        self.assertIn("两个时点", by_id["browser_containment"]["detail"])
        self.assertEqual(len(by_id), len(rows))
        self.dns.assert_called_once_with(scoped, unittest.mock.ANY, run=runner)
        self.assertEqual(by_id["dns_egress"]["status"], "info")

    @patch("surge_cc.containment.validate_scope")
    @patch.object(audit, "chrome_probe_check")
    def test_oauth_inventory_skips_optional_dns_without_reusing_success(self, browser, scope):
        browser.return_value = browser_probe.check_row("browser_webrtc", "probe", "pass", "", True)
        scoped = dict(settings(), browser_path="/fixture/Surge CC Browser.app/Contents/MacOS/Google Chrome")
        by_id = {row["id"]: row for row in audit.audit_checks(
            scoped, surge=FakeSurge(), run=runner, external_dns=False)}
        self.dns.assert_not_called()
        self.assertEqual(scope.call_count, 2)
        self.assertEqual(by_id["browser_containment"]["status"], "pass")
        self.assertEqual(by_id["dns_egress"]["status"], "unknown")

    @patch("surge_cc.containment.validate_scope")
    @patch.object(audit, "chrome_probe_check")
    def test_dns_detected_protection_failure_remains_required(self, browser, scope):
        browser.return_value = browser_probe.check_row("browser_webrtc", "probe", "pass", "", True)
        self.dns.return_value = browser_probe.check_row(
            "dns_egress", "专用代理 DNS 出口实测", "fail", "代理配置变化。", True)
        scoped = dict(settings(), browser_path="/fixture/Surge CC Browser.app/Contents/MacOS/Google Chrome")
        by_id = {row["id"]: row for row in audit.audit_checks(scoped, surge=FakeSurge(), run=runner)}
        self.assertTrue(by_id["dns_egress"]["required"])
        self.assertEqual(by_id["dns_egress"]["status"], "fail")

    @patch("surge_cc.containment.validate_scope")
    @patch.object(audit, "chrome_probe_check")
    def test_post_probe_scope_failure_revokes_pass_even_when_strict_mode_disabled(self, browser, scope):
        scoped = dict(settings(), privacy_strict=False,
                      browser_path="/fixture/Surge CC Browser.app/Contents/MacOS/Google Chrome")
        for exception in (core.Blocked("保护规则已经变化。"), OSError("private diagnostic"),
                          ValueError("private diagnostic"), TypeError("private diagnostic")):
            with self.subTest(exception=type(exception).__name__):
                scope.side_effect = [None, exception]
                browser.return_value = browser_probe.check_row(
                    "browser_webrtc", "probe", "pass", "stale containment claim", False)
                by_id = {row["id"]: row for row in audit.audit_checks(
                    scoped, surge=FakeSurge(), run=runner)}
                self.assertEqual(by_id["browser_containment"]["status"], "fail")
                self.assertTrue(by_id["browser_containment"]["required"])
                self.assertEqual(by_id["browser_webrtc"]["status"], "unknown")
                self.assertTrue(by_id["browser_webrtc"]["required"])
                self.assertNotIn("stale containment claim", by_id["browser_webrtc"]["detail"])
                self.assertNotIn("private diagnostic", json.dumps(by_id))
                self.dns.assert_not_called()

    @patch("surge_cc.containment.validate_scope", side_effect=[None, core.Blocked("范围变化。")])
    @patch.object(audit, "chrome_probe_check")
    def test_post_probe_failure_never_erases_observed_extra_ip(self, browser, scope):
        browser.return_value = browser_probe.check_row(
            "browser_webrtc", "probe", "fail", "额外公网候选：1.1.1.1。", True)
        scoped = dict(settings(), browser_path="/fixture/Surge CC Browser.app/Contents/MacOS/Google Chrome")
        by_id = {row["id"]: row for row in audit.audit_checks(scoped, surge=FakeSurge(), run=runner)}
        self.assertEqual(by_id["browser_webrtc"]["status"], "fail")
        self.assertTrue(by_id["browser_webrtc"]["required"])
        self.dns.assert_not_called()
        self.assertIn("1.1.1.1", by_id["browser_webrtc"]["detail"])
        self.assertEqual(by_id["browser_containment"]["status"], "fail")

    @patch("surge_cc.containment.validate_scope", side_effect=core.Blocked("缺少保护规则。"))
    @patch.object(audit, "chrome_probe_check")
    def test_missing_scope_blocks_before_browser(self, browser, scope):
        scoped = dict(settings(), browser_path="/fixture/Surge CC Browser.app/Contents/MacOS/Google Chrome")
        by_id = {row["id"]: row for row in audit.audit_checks(scoped, surge=FakeSurge(), run=runner)}
        browser.assert_not_called()
        scope.assert_called_once()
        self.assertEqual(by_id["browser_containment"]["status"], "fail")
        self.assertTrue(by_id["browser_webrtc"]["required"])

    @patch("surge_cc.containment.validate_scope")
    @patch.object(audit, "chrome_probe_check")
    def test_quick_scoped_inventory_does_not_infer_browser_pass(self, browser, scope):
        scoped = dict(settings(), browser_path="/fixture/Surge CC Browser.app/Contents/MacOS/Google Chrome")
        by_id = {row["id"]: row for row in audit.audit_checks(
            scoped, surge=FakeSurge(), run=runner, browser=False)}
        browser.assert_not_called()
        scope.assert_called_once()
        self.assertEqual(by_id["browser_webrtc"]["status"], "unknown")
        self.assertTrue(by_id["browser_webrtc"]["required"])


class BrowserReceiptTests(unittest.TestCase):
    @staticmethod
    def receipt():
        return {"schema": 1, "supported": True, "completed": True, "timed_out": False,
                "gathering_state": "complete", "errors": [],
                "candidates": [{"address": "8.8.8.8", "type": "srflx"}]}

    def test_empty_timeout_and_malformed_ice_receipts_never_pass(self):
        for patch_value in (
                {"candidates": []},
                {"timed_out": True},
                {"completed": False},
                {"errors": [{"code": 701}]},
                {"errors": [{"code": "701"}]},
                {"candidates": [{"address": "broken", "type": "host"}]}):
            payload = self.receipt()
            payload.update(patch_value)
            self.assertEqual(browser_probe.assess_ice(payload, "8.8.8.8")["status"], "unknown")

    def test_observed_extra_ipv6_fails_even_if_gathering_times_out(self):
        payload = self.receipt()
        payload["candidates"].append({"address": "2606:4700:4700::1111", "type": "srflx"})
        payload["timed_out"] = True
        self.assertEqual(browser_probe.assess_ice(payload, "8.8.8.8")["status"], "fail")

    def test_loose_mode_does_not_allow_observed_wrong_exit(self):
        row = browser_probe.assess_ice(self.receipt(), "1.1.1.1", required=False)
        self.assertEqual(row["status"], "fail")
        self.assertTrue(row["required"])

    def test_private_or_mdns_only_candidates_remain_unknown(self):
        for address in ("192.168.1.1", "random-host.local"):
            payload = self.receipt()
            payload["candidates"] = [{"address": address, "type": "host"}]
            row = browser_probe.assess_ice(payload, "8.8.8.8")
            self.assertEqual(row["status"], "unknown")

    def test_empty_ice_requires_independent_explicit_containment_proof(self):
        payload = dict(self.receipt(), candidates=[])
        for proof in (False, None, 1, "true"):
            with self.subTest(proof=proof):
                row = browser_probe.assess_ice(payload, "8.8.8.8", containment_verified=proof)
                self.assertEqual(row["status"], "unknown")
        row = browser_probe.assess_ice(payload, "8.8.8.8", containment_verified=True)
        self.assertEqual(row["status"], "pass")
        self.assertIn("专用浏览器未代理UDP被禁用且Surge旁路拒绝已核验；本次无额外公网候选", row["detail"])
        self.assertIn("未测得 WebRTC 公网出口", row["detail"])
        self.assertNotIn("出口匹配", row["detail"])

    def test_private_candidates_use_containment_evidence_not_exit_match(self):
        for address in ("192.168.1.1", "random-host.local"):
            payload = dict(self.receipt(), candidates=[{"address": address, "type": "host"}])
            row = browser_probe.assess_ice(payload, "8.8.8.8", containment_verified=True)
            self.assertEqual(row["status"], "pass")
            self.assertIn("未测得 WebRTC 公网出口", row["detail"])

    def test_containment_never_overrides_incomplete_or_invalid_receipt(self):
        for changes in (
                {"timed_out": True}, {"completed": False}, {"gathering_state": "gathering"},
                {"exception": True}, {"supported": False}, {"errors": [{"code": 701}]},
                {"errors": [{"code": "701"}]}, {"errors": None},
                {"candidates": [{"address": "broken", "type": "host"}]}):
            with self.subTest(changes=changes):
                payload = dict(self.receipt(), candidates=[])
                payload.update(changes)
                row = browser_probe.assess_ice(payload, "8.8.8.8", containment_verified=True)
                self.assertEqual(row["status"], "unknown")
        payload = dict(self.receipt(), candidates=[])
        del payload["errors"]
        self.assertEqual(browser_probe.assess_ice(
            payload, "8.8.8.8", containment_verified=True)["status"], "unknown")

    def test_extra_public_exit_always_fails_even_with_containment_and_loose_mode(self):
        row = browser_probe.assess_ice(self.receipt(), "1.1.1.1", required=False,
                                      containment_verified=True)
        self.assertEqual(row["status"], "fail")
        self.assertTrue(row["required"])

    def test_browser_language_timezone_validated_and_not_inferred(self):
        config = settings()
        config.update(browser_language="en-US", expected_timezone="America/Los_Angeles")
        for payload, status in (
                ({"language": "en-US", "timezone": "America/Los_Angeles"}, "pass"),
                ({"language": "zh-CN", "timezone": "Asia/Shanghai"}, "warn"),
                ({"language": "en-US"}, "unknown"),
                ({"language": "en-US\nsecret", "timezone": "fake/zone"}, "unknown")):
            row = browser_probe._browser_environment({"status": "pass", "detail": ""}, payload, config)
            self.assertEqual(row["status"], status)
            self.assertNotIn("secret", row["detail"])
            self.assertNotIn("fake/zone", row["detail"])
        row = browser_probe._browser_environment({"status": "fail", "detail": ""}, {}, config)
        self.assertEqual(row["status"], "fail")


class BrowserHardeningTests(unittest.TestCase):
    @patch.object(browser_probe.core, "browser_executable", create=True)
    def test_probe_uses_selected_binary_and_supported_chrome_policy_switch(self, executable):
        selected = Path("/Applications/Surge CC Browser.app/Contents/MacOS/Google Chrome")
        executable.return_value = selected
        args = browser_probe.probe_chrome_args(settings(), Path("/tmp/fixture"), "http://127.0.0.1:1/probe/")
        self.assertEqual(args[0], str(selected))
        self.assertIn("--webrtc-ip-handling-policy=disable_non_proxied_udp", args)
        self.assertFalse(any(a.startswith("--force-webrtc-ip-handling-policy") for a in args))
        executable.assert_called_once_with(settings())

    @patch.object(browser_probe, "_stop_browser", return_value=True)
    @patch.object(browser_probe, "ProbeCollector")
    @patch.object(browser_probe.core, "browser_executable", create=True, return_value=Path(__file__))
    @patch.object(browser_probe, "listener_is_surge", return_value=True)
    def test_probe_writes_scoped_policy_without_language_and_forwards_verified_evidence(
            self, listener, executable, collector_type, stop):
        receipt = dict(BrowserReceiptTests.receipt(), candidates=[])
        collector = collector_type.return_value.__enter__.return_value
        collector.url = "http://127.0.0.1:1/probe/"
        collector.event.wait.return_value = True
        collector.payload = receipt
        captured = {}

        def start(args, **kwargs):
            profile = Path(next(a.split("=", 1)[1] for a in args if a.startswith("--user-data-dir=")))
            preferences = profile / "Default/Preferences"
            captured["preferences"] = json.loads(preferences.read_text())
            captured["mode"] = preferences.stat().st_mode & 0o777
            return Mock()

        row = browser_probe.chrome_probe_check(
            settings(), popen=Mock(side_effect=start), containment_verified=True)
        self.assertEqual(row["status"], "pass")
        self.assertEqual(captured, {
            "preferences": {"webrtc": {"ip_handling_policy": "disable_non_proxied_udp",
                                      "ip_handling_url": []}},
            "mode": 0o600})
        self.assertIn("未测得 WebRTC 公网出口", row["detail"])
        stop.assert_called_once()

    @patch.object(browser_probe, "_stop_browser", return_value=True)
    @patch.object(browser_probe, "ProbeCollector")
    @patch.object(browser_probe.core, "browser_executable", create=True, return_value=Path(__file__))
    @patch.object(browser_probe, "listener_is_surge", return_value=True)
    def test_absent_probe_receipt_is_never_pass_even_with_verified_containment(
            self, listener, executable, collector_type, stop):
        collector = collector_type.return_value.__enter__.return_value
        collector.url = "http://127.0.0.1:1/probe/"
        collector.event.wait.return_value = False
        process = Mock()
        process.poll.return_value = 0
        row = browser_probe.chrome_probe_check(
            settings(), popen=Mock(return_value=process), containment_verified=True)
        self.assertEqual(row["status"], "unknown")
        self.assertIn("未收到", row["detail"])


class BrowserCleanupTests(unittest.TestCase):
    def process(self):
        process = Mock()
        process.pid = 42000
        process.poll.return_value = None
        return process

    @patch.object(browser_probe.os, "killpg")
    @patch.object(browser_probe.os, "getpgid", return_value=42001)
    def test_never_signals_a_group_not_owned_by_spawned_process(self, getpgid, killpg):
        self.assertFalse(browser_probe._stop_browser(self.process()))
        killpg.assert_not_called()

    @patch.object(browser_probe.os, "killpg")
    @patch.object(browser_probe.os, "getpgid", return_value=42000)
    def test_rechecks_liveness_after_group_lookup(self, getpgid, killpg):
        process = self.process()
        process.poll.side_effect = [None, 0]
        self.assertTrue(browser_probe._stop_browser(process))
        killpg.assert_not_called()

    @patch.object(browser_probe.os, "killpg")
    @patch.object(browser_probe.os, "getpgid", side_effect=[42000, 42001])
    def test_timeout_rechecks_group_before_kill_escalation(self, getpgid, killpg):
        process = self.process()
        process.wait.side_effect = subprocess.TimeoutExpired("chrome", 3)
        self.assertFalse(browser_probe._stop_browser(process))
        killpg.assert_called_once_with(42000, signal.SIGTERM)

    @patch.object(browser_probe.os, "killpg")
    @patch.object(browser_probe.os, "getpgid", return_value=42000)
    def test_owned_live_process_can_be_stopped(self, getpgid, killpg):
        self.assertTrue(browser_probe._stop_browser(self.process()))
        killpg.assert_called_once_with(42000, signal.SIGTERM)


class STUNValidationTests(unittest.TestCase):
    transaction = b"0123456789ab"

    def packet(self, address, trailing=b""):
        parsed = ipaddress.ip_address(address)
        mask = struct.pack("!I", browser_probe.STUN_COOKIE) + self.transaction
        encoded = bytes(a ^ b for a, b in zip(parsed.packed, mask))
        value = bytes([0, 1 if parsed.version == 4 else 2]) + b"\x00\x00" + encoded
        attrs = struct.pack("!HH", 0x0020, len(value)) + value + trailing
        return struct.pack("!HHI", 0x0101, len(attrs), browser_probe.STUN_COOKIE) + self.transaction + attrs

    def test_ipv6_xor_address_is_decoded(self):
        packet = self.packet("2001:db8::10")
        self.assertEqual(browser_probe.parse_stun_response(packet, self.transaction), "2001:db8::10")

    def test_truncated_attribute_after_valid_xor_is_rejected(self):
        packet = self.packet("203.0.113.10", struct.pack("!HH", 0x7777, 8))
        with self.assertRaises(ValueError):
            browser_probe.parse_stun_response(packet, self.transaction)

    def test_bad_transaction_and_size_rejected(self):
        for packet, transaction in (
                (self.packet("203.0.113.10"), None),
                (self.packet("203.0.113.10"), b"bad"),
                (self.packet("203.0.113.10") + b"\x00", self.transaction)):
            with self.assertRaises(ValueError):
                browser_probe.parse_stun_response(packet, transaction)

    def test_ipv6_stun_timeout_or_malformed_reply_is_unknown(self):
        resolver = Mock(return_value=[(socket.AF_INET6, socket.SOCK_DGRAM, 0, "",
                                      ("2001:db8::1", 19302, 0, 0))])
        for response in (socket.timeout(), b"not-stun"):
            sock = Mock()
            sock.__enter__ = Mock(return_value=sock)
            sock.__exit__ = Mock(return_value=False)
            if isinstance(response, Exception):
                sock.recv.side_effect = response
            else:
                sock.recv.return_value = response
            row = browser_probe.stun_probe_check("2001:db8::10", family=socket.AF_INET6,
                                                 resolver=resolver, socket_factory=Mock(return_value=sock))
            self.assertEqual(row["status"], "unknown")


if __name__ == "__main__":
    unittest.main()

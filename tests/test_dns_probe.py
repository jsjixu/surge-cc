"""Offline contracts for a fresh, proxy-scoped authoritative DNS experiment."""
from copy import deepcopy
import json
import os
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

from surge_cc import dns_probe
from surge_cc.core import Blocked
from test_core import config

IDENTIFIER = "xf5qqgqxzo"


def settings():
    return dict(config(), expected_ip="8.8.4.4", proxy_url="http://127.0.0.1:62919")


def new_receipt():
    return {
        "testId": IDENTIFIER, "zone": dns_probe.ZONE,
        "client": {"ip": settings()["expected_ip"]},
        "hostnames": [f"{IDENTIFIER}-{family}{number:02d}.{dns_probe.ZONE}"
                      for family in ("a", "q") for number in range(1, 7)],
        "resultUrl": f"{dns_probe.BASE}/api/result/{IDENTIFIER}",
    }


def result_receipt():
    return {
        "testId": IDENTIFIER, "client": {"ip": settings()["expected_ip"]},
        "lookups": 12, "truncated": False,
        "verdict": {"status": "no_leak", "headline": "DO NOT TRUST THIS PROSE"},
        "resolvers": [
            {"ip": "8.8.8.8", "role": "resolver", "operator": "Google",
             "countryCode": "US", "count": 8, "firstSeen": int(time.time() * 1000)},
            {"ip": "2001:4860:4860::8888", "role": "resolver", "operator": "Google",
             "countryCode": "BE", "count": 4, "firstSeen": int(time.time() * 1000)},
        ],
    }


class FakeSurge:
    def __init__(self):
        self.calls = []
        self.profile_reads = 0
        self.drift_profile = self.drift_group = self.drift_mode = False

    def call(self, *args, timeout=12):
        self.calls.append((args, timeout))
        if args == ("status",):
            return {"mode": "direct" if self.drift_mode and self.profile_reads else "rule",
                    "features": {"enhanced-mode": True}, "profile-path": "/test/profile.conf"}
        if args == ("dump", "profile", "effective"):
            self.profile_reads += 1
            return {"profile": "PROFILE" + ("CHANGED" if self.drift_profile and self.profile_reads > 1 else "")}
        if args == ("policy-group", "get", "Claude"):
            return {"group": {"selected": "OTHER" if self.drift_group and self.profile_reads > 1 else "Home"}}
        raise AssertionError("Unexpected Surge mutation or request")


class Runner:
    def __init__(self):
        self.new = new_receipt()
        self.results = [result_receipt()]
        self.result_index = 0
        self.exit_values = [settings()["expected_ip"], settings()["expected_ip"]]
        self.exit_index = 0
        self.calls = []
        self.probe_error = None
        self.probe_code = 60
        self.override = {}
        self.lock = threading.Lock()

    def __call__(self, args, **kwargs):
        with self.lock:
            self.calls.append((args, kwargs))
            url = args[-1]
            if url in self.override:
                override = self.override[url]
                if isinstance(override, BaseException):
                    raise override
                return override
            if url == dns_probe.IP_URL:
                value = {"ip": self.exit_values[min(self.exit_index, len(self.exit_values) - 1)]}
                self.exit_index += 1
            elif url == dns_probe.BASE + "/api/new":
                value = self.new
            elif url == f"{dns_probe.BASE}/api/result/{IDENTIFIER}":
                value = self.results[min(self.result_index, len(self.results) - 1)]
                self.result_index += 1
            elif ".t.dnsleak.dev/" in url:
                if self.probe_error:
                    raise self.probe_error
                return subprocess.CompletedProcess(args, self.probe_code, "", "PRIVATE TLS FAILURE")
            else:
                raise AssertionError("Unexpected destination: " + url)
            return subprocess.CompletedProcess(args, 0, json.dumps(value) + "\n200", "")


class DNSProbeTests(unittest.TestCase):
    def observe(self, runner=None, surge=None, **kwargs):
        runner, surge = runner or Runner(), surge or FakeSurge()
        with patch.object(dns_probe, "validate_scope") as validate, \
                patch.object(dns_probe.time, "sleep"):
            value = dns_probe.observe_proxy_dns(kwargs.get("config", settings()), surge, run=runner)
        return value, runner, surge, validate

    def test_complete_measurement_is_scoped_information_never_universal_pass(self):
        row, runner, surge, validate = self.observe()
        self.assertEqual(row["id"], "dns_egress")
        self.assertEqual(row["status"], "info")
        self.assertFalse(row["required"])
        self.assertEqual(validate.call_count, 2)
        self.assertEqual(runner.exit_index, 2)
        self.assertEqual(runner.result_index, 1)
        evidence = " ".join(row["evidence"])
        self.assertIn("8.8.8.8", evidence)
        self.assertIn("2001:4860:4860::8888", evidence)
        self.assertIn("12 个", evidence)
        self.assertIn("检查时间", evidence)
        self.assertNotIn("DO NOT TRUST", str(row))
        self.assertNotIn("PRIVATE", str(row))
        self.assertIn("IPv6 旁路", row["evidence_scope"])
        self.assertIn("不代表整台 Mac", row["evidence_scope"])
        self.assertTrue(all(timeout <= 2 for _, timeout in surge.calls))

    def test_every_request_uses_exact_proxy_and_sanitized_environment(self):
        with patch.dict(os.environ, {
            "NO_PROXY": "*", "https_proxy": "http://attacker.invalid",
            "SSLKEYLOGFILE": "/private/secret", "CURL_CA_BUNDLE": "/untrusted",
            "DYLD_INSERT_LIBRARIES": "/untrusted", "SECRET": "do-not-inherit",
        }):
            row, runner, _, _ = self.observe()
        self.assertEqual(row["status"], "info")
        self.assertEqual(len(runner.calls), 16)
        for args, kwargs in runner.calls:
            self.assertEqual(args[:2], ["/usr/bin/curl", "--disable"])
            for flag, expected in (("--proxy", settings()["proxy_url"]), ("--noproxy", ""),
                                   ("--proto", "=https"), ("--max-redirs", "0")):
                self.assertEqual(args[args.index(flag) + 1], expected)
            self.assertNotIn("--location", args)
            self.assertNotIn("--insecure", args)
            self.assertLessEqual(kwargs["timeout"], 3.25)
            self.assertEqual(kwargs["env"]["NO_PROXY"], "")
            self.assertEqual(kwargs["env"]["HTTPS_PROXY"], settings()["proxy_url"])
            for key in ("SSLKEYLOGFILE", "CURL_CA_BUNDLE", "DYLD_INSERT_LIBRARIES", "SECRET"):
                self.assertNotIn(key, kwargs["env"])

    def test_both_families_sent_only_to_exact_session_hostnames(self):
        _, runner, _, _ = self.observe()
        urls = [args[-1] for args, _ in runner.calls if "--output" in args]
        self.assertEqual(set(urls), {"https://" + host + "/" for host in new_receipt()["hostnames"]})
        self.assertEqual(len(urls), 12)

    def test_no_cached_report_each_call_creates_fresh_session_request(self):
        runner = Runner()
        self.observe(runner)
        self.observe(runner)
        self.assertEqual(sum(args[-1].endswith("/api/new") for args, _ in runner.calls), 2)

    def test_probe_tls_or_connection_failures_need_authoritative_receipt_not_local_success(self):
        for error in (None, subprocess.TimeoutExpired("PRIVATE", 2), OSError("PRIVATE")):
            with self.subTest(error=error):
                runner = Runner()
                runner.probe_error = error
                self.assertEqual(self.observe(runner)[0]["status"], "info")

    def test_partial_results_poll_then_complete(self):
        runner = Runner()
        partial = result_receipt()
        partial["lookups"] = 4
        runner.results = [partial, result_receipt()]
        self.assertEqual(self.observe(runner)[0]["status"], "info")
        self.assertEqual(runner.result_index, 2)

    def test_incomplete_results_stay_unknown_after_bounded_polling(self):
        runner = Runner()
        runner.results[0]["lookups"] = 0
        row, _, _, _ = self.observe(runner)
        self.assertEqual(row["status"], "unknown")
        self.assertEqual(runner.result_index, 3)

    def test_split_warns_and_inconclusive_does_not_pass(self):
        for verdict, status in (("split", "warn"), ("inconclusive", "unknown"), ("new_status", "unknown")):
            runner = Runner()
            runner.results[0]["verdict"]["status"] = verdict
            self.assertEqual(self.observe(runner)[0]["status"], status)

    def test_wrong_exit_at_any_stage_invalidates_measurement(self):
        for stage in ("before", "new", "report", "after"):
            runner = Runner()
            if stage == "before":
                runner.exit_values[0] = "1.1.1.1"
            elif stage == "after":
                runner.exit_values[1] = "1.1.1.1"
            elif stage == "new":
                runner.new["client"]["ip"] = "1.1.1.1"
            else:
                runner.results[0]["client"]["ip"] = "1.1.1.1"
            row, _, _, _ = self.observe(runner)
            self.assertEqual(row["status"], "fail", stage)
            self.assertTrue(row["required"])

    def test_hostile_new_receipts_never_trigger_probe_urls(self):
        mutations = [
            lambda value: value["hostnames"].__setitem__(0, "evil.invalid"),
            lambda value: value["hostnames"].__setitem__(0, "127.0.0.1"),
            lambda value: value["hostnames"].__setitem__(0, value["hostnames"][1]),
            lambda value: value["hostnames"].pop(),
            lambda value: value.update(testId="../secrets"),
            lambda value: value.update(zone="evil.invalid"),
            lambda value: value.update(resultUrl="http://127.0.0.1/secrets"),
            lambda value: value["hostnames"].__setitem__(0, value["hostnames"][0] + ".evil.invalid"),
        ]
        for mutate in mutations:
            runner = Runner()
            mutate(runner.new)
            self.assertEqual(self.observe(runner)[0]["status"], "unknown")
            self.assertFalse(any("--output" in args for args, _ in runner.calls))

    def test_invalid_reports_never_show_success(self):
        mutations = [
            lambda value: value.update(truncated=True),
            lambda value: value.pop("truncated"),
            lambda value: value.update(lookups=True),
            lambda value: value.update(lookups=13),
            lambda value: value.update(testId="aaaaaaaaaa"),
            lambda value: value.pop("testId"),
            lambda value: value.update(resolvers=[]),
            lambda value: value["verdict"].update(leaking=True),
            lambda value: value["resolvers"].append(deepcopy(value["resolvers"][0])),
            lambda value: value["resolvers"][0].update(role="unknown"),
            lambda value: value["resolvers"][0].update(ip="127.0.0.1"),
            lambda value: value["resolvers"][0].update(ip="10.0.0.1"),
            lambda value: value["resolvers"][0].update(ip="169.254.1.1"),
            lambda value: value["resolvers"][0].update(ip="100.64.0.1"),
            lambda value: value["resolvers"][0].update(ip="fe80::1"),
            lambda value: value["resolvers"][0].update(count=0),
            lambda value: value["resolvers"][0].pop("firstSeen"),
            lambda value: value.update(resolvers=[dict(value["resolvers"][0], role="observer")]),
        ]
        for mutate in mutations:
            runner = Runner()
            mutate(runner.results[0])
            self.assertEqual(self.observe(runner)[0]["status"], "unknown")

    def test_observer_addresses_are_not_reported_as_actual_resolvers(self):
        runner = Runner()
        runner.results[0]["resolvers"].append({
            "ip": "9.9.9.9", "role": "observer", "count": 1, "firstSeen": 123456,
        })
        row = self.observe(runner)[0]
        self.assertEqual(row["status"], "info")
        self.assertNotIn("9.9.9.9", str(row))

    def test_untrusted_labels_and_verdict_prose_cannot_inject_evidence(self):
        runner = Runner()
        runner.results[0]["resolvers"][0].update(operator="PRIVATE\nInjected", org="Fallback")
        row = self.observe(runner)[0]
        self.assertEqual(row["status"], "info")
        self.assertIn("Fallback", str(row))
        self.assertNotIn("Injected", str(row))
        self.assertNotIn("DO NOT TRUST", str(row))

    def test_http_failures_redirects_limits_and_malformed_json_stay_unknown(self):
        for response in [
            subprocess.CompletedProcess([], 0, "{}\n302", ""),
            subprocess.CompletedProcess([], 0, "{}\n429", ""),
            subprocess.CompletedProcess([], 0, '{"testId":"a","testId":"b"}\n200', ""),
            subprocess.CompletedProcess([], 0, "NaN\n200", ""),
            subprocess.CompletedProcess([], 0, "x" * 70000, ""),
            subprocess.CompletedProcess([], 7, "", "PRIVATE"),
            subprocess.TimeoutExpired("PRIVATE", 2),
            OSError("PRIVATE"),
        ]:
            runner = Runner()
            runner.override[dns_probe.BASE + "/api/new"] = response
            row = self.observe(runner)[0]
            self.assertEqual(row["status"], "unknown")
            self.assertNotIn("PRIVATE", str(row))

    def test_route_configuration_drift_revokes_complete_report(self):
        for kind in ("drift_profile", "drift_group", "drift_mode"):
            surge = FakeSurge()
            setattr(surge, kind, True)
            row = self.observe(surge=surge)[0]
            self.assertEqual(row["status"], "fail", kind)
            self.assertTrue(row["required"])
            self.assertIn("发生变化", row["detail"])

    def test_failed_scope_prevents_network_probe(self):
        runner = Runner()
        with patch.object(dns_probe, "validate_scope", side_effect=Blocked("PRIVATE")):
            row = dns_probe.observe_proxy_dns(settings(), FakeSurge(), run=runner)
        self.assertEqual(row["status"], "fail")
        self.assertTrue(row["required"])
        self.assertFalse(runner.calls)
        self.assertNotIn("PRIVATE", str(row))

    def test_failed_final_scope_revokes_report(self):
        with patch.object(dns_probe, "validate_scope", side_effect=[None, Blocked("PRIVATE")]):
            row = dns_probe.observe_proxy_dns(settings(), FakeSurge(), run=Runner())
        self.assertEqual(row["status"], "fail")
        self.assertTrue(row["required"])
        self.assertNotIn("PRIVATE", str(row))

    def test_service_error_still_rechecks_scope_and_cannot_mask_drift(self):
        runner = Runner()
        runner.override[dns_probe.BASE + "/api/new"] = subprocess.CompletedProcess([], 0, "{}\n429", "")
        surge = FakeSurge()
        surge.drift_profile = True
        row, _, _, validate = self.observe(runner, surge)
        self.assertEqual(validate.call_count, 2)
        self.assertEqual(row["status"], "fail")
        self.assertTrue(row["required"])

    def test_actual_exit_unavailable_blocks_instead_of_becoming_optional_warning(self):
        runner = Runner()
        runner.override[dns_probe.IP_URL] = subprocess.TimeoutExpired("PRIVATE", 3)
        row = self.observe(runner)[0]
        self.assertEqual(row["status"], "fail")
        self.assertTrue(row["required"])

    def test_invalid_proxy_or_expected_ip_prevents_network_probe(self):
        for key, value in (("proxy_url", "http://127.0.0.1:6152"),
                           ("proxy_url", "http://example.com:62919"),
                           ("expected_ip", "127.0.0.1"), ("expected_ip", "invalid")):
            cfg = settings()
            cfg[key] = value
            row, runner, _, _ = self.observe(config=cfg)
            self.assertEqual(row["status"], "fail")
            self.assertTrue(row["required"])
            self.assertFalse(runner.calls)

    def test_deadline_exhaustion_during_required_scope_blocks_without_network(self):
        with patch.object(dns_probe.time, "monotonic", side_effect=[0, 50]), \
                patch.object(dns_probe, "validate_scope"):
            runner = Runner()
            row = dns_probe.observe_proxy_dns(settings(), FakeSurge(), run=runner)
        self.assertEqual(row["status"], "fail")
        self.assertFalse(runner.calls)

    def test_interrupt_is_not_swallowed(self):
        runner = Runner()
        runner.override[dns_probe.BASE + "/api/new"] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.observe(runner)


if __name__ == "__main__":
    unittest.main()

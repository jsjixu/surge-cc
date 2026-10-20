"""Fresh authoritative DNS observations for the dedicated HTTP proxy chain.

The public protocol is documented at https://dnsleak.dev/api. This module never
changes a resolver, opens a browser, runs a local DNS query, or reuses a report.
An observed resolver is evidence about this experiment, not a universal privacy
verdict. In particular, a public resolver need not share the proxy's IP or ASN.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
import re
import subprocess
import time

from .browser_probe import check_row
from .containment import _endpoint, validate_scope
from .core import Blocked, Surge, now, proxy_env, validate_config

BASE = "https://dnsleak.dev"
ZONE = "t.dnsleak.dev"
IP_URL = "https://api.ipify.org?format=json"
TOTAL_SECONDS = 22.0
BODY_LIMIT = 65536
SCOPE = (
    "仅观测本次经专用 HTTP 代理发送的随机域名解析链；不代表整台 Mac、"
    "浏览器其他解析路径或所有时刻均无 DNS 泄漏。解析器 IP、ASN 或地区"
    "不同于代理出口不单独构成泄漏证据。解析器的 IPv6 地址不证明 Mac 存在"
    "IPv6 旁路；权威端的 UDP/TCP 观测也不能证明客户端 DNS 是否加密。"
    "未修改系统 DNS 或任何代理规则。"
)


class _Unobserved(Exception):
    """Only fixed, safe user-facing explanations belong in this exception."""


class _SafetyBlocked(Exception):
    """Required routing checks failed; optional diagnostics must not mask this."""


def _remaining(deadline, maximum=3.0):
    remaining = deadline - time.monotonic()
    if remaining <= 0.1:
        raise _Unobserved("本次外部 DNS 观测超时；未沿用以前的结果。")
    return min(remaining, maximum)


class _BoundedSurge(Surge):
    def __init__(self, source, deadline):
        self.source, self.deadline = source, deadline

    def call(self, *args, timeout=12):
        return self.source.call(*args, timeout=_remaining(self.deadline, min(timeout, 2.0)))


def _row(status, detail, evidence=(), *, required=False):
    row = check_row("dns_egress", "专用代理 DNS 出口实测", status, detail, required)
    row.update(evidence=list(evidence), evidence_scope=SCOPE)
    return row


def _ip(value):
    if not isinstance(value, str) or len(value) > 45:
        raise ValueError("invalid IP")
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast or "%" in value:
        raise ValueError("invalid public observation")
    return str(address)


def _text(value, limit=100):
    return (value[:limit] if isinstance(value, str) and
            all(ord(c) >= 32 and ord(c) != 127 for c in value) else "")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _curl(config, url, deadline, run, *, probe=False):
    maximum = _remaining(deadline)
    # Do not inherit curl CA overrides, key logs, injected proxy variables,
    # loader variables, or a user's curlrc. TLS verification remains enabled.
    env = proxy_env(config["proxy_url"], base={
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8",
    })
    args = [
        "/usr/bin/curl", "--disable", "--silent", "--show-error",
        "--proxy", config["proxy_url"], "--noproxy", "",
        "--proto", "=https", "--proto-redir", "=https",
        "--max-redirs", "0", "--connect-timeout", str(min(maximum, 2.0)),
        "--max-time", str(maximum), "--max-filesize", str(BODY_LIMIT),
    ]
    if probe:
        args += ["--output", "/dev/null"]
    else:
        args += ["--header", "Accept: application/json", "--write-out", "\n%{http_code}"]
    args.append(url)
    try:
        response = run(args, capture_output=True, text=True, timeout=maximum + 0.25,
                       check=False, env=env)
    except (OSError, subprocess.SubprocessError):
        if probe:
            return None
        raise _Unobserved("外部 DNS 观测服务暂时不可用，未取得本次有效报告。") from None
    if probe:
        # These names deliberately need not serve a valid TLS certificate.
        # Only the authoritative receipt can establish that a lookup arrived.
        return None
    if (response.returncode or not isinstance(response.stdout, str) or
            len(response.stdout) > BODY_LIMIT + 16):
        raise _Unobserved("外部 DNS 观测请求失败或响应过大，未取得本次有效报告。")
    try:
        body, status = response.stdout.rsplit("\n", 1)
        if status == "429":
            raise _Unobserved("外部 DNS 服务暂时限流，请稍后重新检查；未沿用旧报告。")
        if status != "200":
            raise ValueError("non-success response")
        payload = json.loads(body, object_pairs_hook=_pairs,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
        if not isinstance(payload, dict):
            raise ValueError("not an object")
        return payload
    except (ValueError, TypeError):
        raise _Unobserved("外部 DNS 服务返回了无法验证的报告，未判定通过。") from None


def _actual_exit(config, deadline, run):
    try:
        response = _curl(config, IP_URL, deadline, run)
        if set(response) != {"ip"} or _ip(response["ip"]) != config["expected_ip"]:
            raise ValueError("wrong exit")
    except (_Unobserved, KeyError, TypeError, ValueError):
        raise _SafetyBlocked("专用入口实际出口无法核验或与预期不一致，已撤回启动资格。") from None


def _snapshot(config, surge):
    status, profile, group = surge.status(), surge.profile(), surge.group(config["group"])
    if not isinstance(status, dict) or not isinstance(profile, str) or not isinstance(group, dict):
        raise _Unobserved("无法确认当前代理配置；未进行有效 DNS 观测。")
    try:
        state = {
            "mode": status.get("mode"), "profile": status.get("profile-path"),
            "features": status.get("features"), "group": group,
            "profile_hash": hashlib.sha256(profile.encode()).hexdigest(),
        }
        return json.dumps(state, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        raise _Unobserved("代理配置状态无法核验；未进行有效 DNS 观测。") from None


def _protected_state(config, surge):
    try:
        validate_scope(config, surge)
        return _snapshot(config, surge)
    except (_Unobserved, Blocked, OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError):
        raise _SafetyBlocked("DNS 观测时未能确认专用线路保护，已撤回启动资格；请重新检查线路。") from None


def _verify_after(config, surge, before, deadline, run):
    _actual_exit(config, deadline, run)
    if _protected_state(config, surge) != before:
        raise _SafetyBlocked("观测期间代理配置或策略发生变化，已撤回启动资格，请重新检查。")


def _new_receipt(value, expected_ip):
    try:
        identifier = value["testId"]
        if not isinstance(identifier, str) or re.fullmatch(r"[a-z0-9]{10}", identifier) is None:
            raise ValueError("test identifier")
        allowed = {f"{identifier}-{family}{index:02d}.{ZONE}"
                   for family in ("a", "q") for index in range(1, 7)}
        names = value["hostnames"]
        if (value.get("zone") != ZONE or not isinstance(names, list) or len(names) != 12 or
                any(not isinstance(name, str) for name in names) or set(names) != allowed or
                value.get("resultUrl") != f"{BASE}/api/result/{identifier}" or
                not isinstance(value.get("client"), dict)):
            raise ValueError("unsafe receipt")
        if _ip(value["client"]["ip"]) != expected_ip:
            raise _SafetyBlocked("DNS 观测服务看到的入口 IP 与预期不一致，已撤回启动资格。")
        return identifier, names
    except (KeyError, TypeError, ValueError):
        raise _Unobserved("DNS 测试会话或随机域名不符合已验证协议，未向未知目标发起请求。") from None


def _report(value, identifier, expected_ip):
    """Return complete evidence, or None while authoritative lookups are pending."""
    try:
        if value.get("testId") != identifier or not isinstance(value.get("client"), dict):
            raise ValueError("wrong session or exit")
        if _ip(value["client"]["ip"]) != expected_ip:
            raise _SafetyBlocked("DNS 报告中的实际出口与预期不一致，已撤回启动资格。")
        count = value.get("lookups")
        if type(count) is not int or not 0 <= count <= 12 or value.get("truncated") is not False:
            raise ValueError("missing count or truncated result")
        if count != 12:
            return None
        verdict = value.get("verdict")
        if not isinstance(verdict, dict) or verdict.get("status") not in {"no_leak", "split", "inconclusive"}:
            raise ValueError("unknown verdict")
        if "leaking" in verdict and (
                type(verdict["leaking"]) is not bool or
                verdict["leaking"] != (verdict["status"] == "split")):
            raise ValueError("contradictory verdict")
        resolvers = value.get("resolvers")
        if not isinstance(resolvers, list) or not 1 <= len(resolvers) <= 128:
            raise ValueError("missing resolvers")
        addresses, observed = set(), []
        for resolver in resolvers:
            if not isinstance(resolver, dict) or resolver.get("role") not in {"resolver", "observer"}:
                raise ValueError("unknown resolver role")
            if (type(resolver.get("count")) is not int or resolver["count"] < 1 or
                    type(resolver.get("firstSeen")) is not int or resolver["firstSeen"] <= 0):
                raise ValueError("missing measurement metadata")
            address = _ip(resolver["ip"])
            if address in addresses:
                raise ValueError("duplicate resolver")
            addresses.add(address)
            if resolver["role"] == "resolver":
                label = (_text(resolver.get("operator")) or _text(resolver.get("org")) or
                         _text(resolver.get("hostname")) or "机构未提供")
                observed.append((address, label))
        if not observed:
            raise ValueError("only observers")
        return verdict["status"], observed
    except (KeyError, TypeError, ValueError):
        raise _Unobserved("DNS 报告的出口、解析器或完整性无法验证，未判定通过。") from None


def observe_proxy_dns(config, surge, run=subprocess.run):
    """Perform one bounded, fresh probe. No cached success or network mutation."""
    deadline = time.monotonic() + TOTAL_SECONDS
    before = None
    try:
        try:
            config = validate_config(config)
            config["expected_ip"] = _ip(config["expected_ip"])
            _endpoint(config)
        except (Blocked, ValueError, TypeError, KeyError):
            raise _SafetyBlocked("专用入口或预期公网 IP 配置无效，已阻止本次检查和启动。") from None
        bounded = _BoundedSurge(surge, deadline)
        before = _protected_state(config, bounded)
        _actual_exit(config, deadline, run)
        # Leave time to recheck protection even if the observation service fails.
        data_deadline = deadline - 6.0
        identifier, names = _new_receipt(
            _curl(config, BASE + "/api/new", data_deadline, run), config["expected_ip"])
        with ThreadPoolExecutor(max_workers=6, thread_name_prefix="surge-cc-dns") as pool:
            futures = [pool.submit(_curl, config, "https://" + name + "/", data_deadline, run, probe=True)
                       for name in names]
            for future in futures:
                future.result()
        observation = None
        for attempt in range(3):
            observation = _report(
                _curl(config, f"{BASE}/api/result/{identifier}", data_deadline, run),
                identifier, config["expected_ip"])
            if observation is not None:
                break
            if attempt < 2:
                time.sleep(min(0.35, _remaining(data_deadline)))
        if observation is None:
            raise _Unobserved("随机域名的权威查询尚未完整到达；本次 DNS 观测未完成。")
        _verify_after(config, bounded, before, deadline, run)
        _remaining(deadline)
        verdict, resolvers = observation
        evidence = [
            "观测服务：https://dnsleak.dev；检查时间：" + now() + "。",
            "专用代理实际出口：" + config["expected_ip"] + "（观测前后均核对）。",
            "本次单次随机域名：12 个；权威服务已观测：12 个。",
            "代理配置与保护规则：观测前后复核一致；两次核验不代表期间每个瞬间。",
        ]
        evidence += ["递归解析器：" + address + "；" + label + "。" for address, label in resolvers]
        if verdict == "inconclusive":
            return _row("unknown", "已取得本次解析器观测，但服务未能作出结论；需结合所选 DNS 核对。", evidence)
        if verdict == "split":
            return _row("warn", "检测服务观察到不同解析器分流，需核对是否符合预期；尚不能单凭此认定泄漏。", evidence)
        providers = list(dict.fromkeys(label for _, label in resolvers))
        labels = "、".join(providers[:3]) + ("等" if len(providers) > 3 else "")
        return _row("info", "12/12 个随机域名已测；观察到 " + labels + " 解析器。仅代表本次专用代理链。", evidence)
    except _SafetyBlocked as exc:
        return _row("fail", str(exc), required=True)
    except _Unobserved as exc:
        if before is not None:
            try:
                _verify_after(config, bounded, before, deadline, run)
            except _SafetyBlocked as unsafe:
                return _row("fail", str(unsafe), required=True)
        return _row("unknown", str(exc))
    except (Blocked, OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError):
        return _row("unknown", "专用线路或外部 DNS 观测未能完成核验；未判定通过，也未修改网络设置。")

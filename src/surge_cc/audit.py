"""Read-only environment observations with explicit evidence limits.

Every returned row distinguishes a failed observation from an unobserved property.
No command writes a system preference, network setting or Surge configuration.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import subprocess
from urllib.parse import urlsplit

from .browser_probe import check_row, chrome_probe_check
from .core import Blocked, Surge, listener_is_surge, proxy_env
from .dns_probe import observe_proxy_dns

DNS_DOMAIN = "claude.ai"
FAKE_IPV4 = ipaddress.ip_network("198.18.0.0/15")
FAKE_IPV6 = ipaddress.ip_network("fd00:6152::/48")
ULA_IPV6 = ipaddress.ip_network("fc00::/7")


def _evidence_row(identifier, title, status, detail, required, evidence, scope):
    """Add optional, display-only evidence without changing check-row semantics."""
    row = check_row(identifier, title, status, detail, required)
    row.update(evidence=evidence, evidence_scope=scope)
    return row


def _run(run, args, timeout=8):
    try:
        value = run(args, capture_output=True, text=True, timeout=timeout, check=False)
        if value.returncode or not isinstance(value.stdout, str) or len(value.stdout) > 262144:
            return None
        return value.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _safe_text(value, limit=120):
    return (value[:limit] if isinstance(value, str) and
            all(ord(c) >= 32 and c not in "\x7f" for c in value) else "")


def _address(value):
    try:
        return ipaddress.ip_address(value.split("%", 1)[0])
    except (AttributeError, ValueError):
        return None


def is_fake_ip(value):
    parsed = _address(value)
    return parsed is not None and (parsed in (FAKE_IPV4 if parsed.version == 4 else FAKE_IPV6))


def dns_servers(text):
    if not isinstance(text, str):
        return []
    return list(dict.fromkeys(m for m in re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", text)
                              if _address(m) is not None))


def resolver_addresses(text):
    if not isinstance(text, str):
        return []
    return list(dict.fromkeys(m for m in re.findall(r"(?:ipv6_address|ip_address):\s*(\S+)", text)
                              if _address(m) is not None))


def safe_dns_server(value):
    """DoH paths often contain private tokens. Never expose path/query/userinfo."""
    if not isinstance(value, str):
        return "未提供"
    direct = _address(value)
    if direct is not None:
        return str(direct)
    try:
        parsed = urlsplit(value)
        if parsed.scheme in {"https", "tls", "quic", "h3"} and parsed.hostname:
            host = _safe_text(parsed.hostname)
            if not host:
                return "未提供"
            if ":" in host:
                host = "[" + host + "]"
            return parsed.scheme + "://" + host + (":" + str(parsed.port) if parsed.port else "") + "/…"
    except ValueError:
        pass
    return "上游地址格式未识别（已隐藏）"


def dns_checks(config, surge, status, run):
    strict = config.get("privacy_strict", True) is not False
    system_text = _run(run, ["/usr/sbin/scutil", "--dns"])
    servers = dns_servers(system_text)
    resolve_text = _run(run, ["/usr/bin/dscacheutil", "-q", "host", "-a", "name", DNS_DOMAIN], timeout=10)
    addresses = resolver_addresses(resolve_text)
    try:
        response = surge.call("dns", "lookup", DNS_DOMAIN, timeout=12)
    except (Blocked, OSError, ValueError, TypeError):
        response = {}
    if not isinstance(response, dict):
        response = {}
    values = []
    for field in ("v4Addresses", "v6Addresses"):
        if isinstance(response.get(field), list):
            values += [str(_address(v)) for v in response[field] if _address(v) is not None]
    lookup_ok = response.get("domain") == DNS_DOMAIN and bool(values)
    features = status.get("features", {}) if isinstance(status, dict) else {}
    enhanced = isinstance(features, dict) and features.get("enhanced-mode") is True
    fake = any(is_fake_ip(value) for value in addresses)
    surge_resolver = any(is_fake_ip(value) for value in servers)
    if not servers or not addresses or not lookup_ok:
        takeover_status = "unknown"
        detail = "解析结果不完整，本次无法核对 DNS 接管。"
    elif enhanced and (fake or surge_resolver):
        takeover_status = "pass"
        detail = "观察到 Surge/FakeIP 接管迹象，测试域名解析成功。"
    else:
        takeover_status = "warn"
        detail = "系统与 Surge 均能解析，但接管证据不足。"
    evidence = [
        "测试域名：" + DNS_DOMAIN + "。",
        "系统 DNS：" + ("、".join(servers[:8]) if servers else "未读取到有效地址") + "。",
        "系统解析：" + ("、".join(addresses[:8]) if addresses else "未取得有效结果") + "。",
        "Surge 增强模式：" + ("已开启" if enhanced else "未确认开启") + "。",
    ]
    if lookup_ok:
        interface = _safe_text(response.get("interface")) or "接口未提供"
        evidence.append("Surge 上游：" + safe_dns_server(response.get("server")) + "；" + interface + "。")
    else:
        evidence.append("Surge 解析：未取得有效结果。")
    return [
        _evidence_row("dns_takeover", "DNS 接管与解析", takeover_status, detail, strict, evidence,
                      "本机配置与解析路径的有限证据。FakeIP 不是递归 DNS 出口证明，缓存也可能参与解析。"),
        _evidence_row("dns_egress", "专用代理 DNS 出口实测", "unknown",
                      "本次尚未执行外部观测；完整检查通过专用入口核验后才测量。", False,
                      ["仅快速检查、缺少专用入口或必需检查未通过时，不发送外部 DNS 探针。",
                       "递归 DNS 服务商的公网 IP 通常不必等于住宅代理出口。"],
                      "此项未执行外部观测，不能用于判断 DNS 已泄漏或没有泄漏。"),
    ]


def ipv6_interfaces(text):
    """Return active interfaces and IPv6 addresses; inactive interfaces excluded."""
    if not isinstance(text, str):
        return None
    interfaces = []
    current = None
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+):\s+flags=.*?<([^>]+)>", line)
        if match:
            current = {"name": match.group(1), "flags": match.group(2).split(","),
                       "status": None, "addresses": []}
            interfaces.append(current)
        elif current is not None:
            state = re.search(r"\bstatus:\s*(\w+)", line)
            if state:
                current["status"] = state.group(1)
            addr = re.search(r"\binet6\s+(\S+)", line)
            if re.search(r"\binet6\b", line):
                parsed = _address(addr.group(1)) if addr else None
                if parsed is None or parsed.version != 6:
                    return None
                current["addresses"].append(addr.group(1))
    if not interfaces:
        return None
    return [value for value in interfaces if value["status"] != "inactive" and
            (value["status"] == "active" or {"UP", "RUNNING"}.issubset(value["flags"]))]


def ipv6_defaults(text):
    if (not isinstance(text, str) or "Internet6:" not in text or
            re.search(r"(?m)^Destination\s+Gateway\s+Flags\s+Netif\b", text) is None):
        return None
    defaults = []
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] == "default":
            if len(fields) < 4 or not re.fullmatch(r"[A-Za-z0-9_.-]+", fields[3]):
                return None
            gateway = _address(fields[1])
            if not ((gateway is not None and gateway.version == 6) or
                    re.fullmatch(r"link#[0-9]+", fields[1])):
                return None
            defaults.append({"gateway": fields[1], "interface": fields[3]})
    return defaults


def _ipv6_address_kind(value):
    parsed = _address(value)
    if parsed.is_loopback:
        return "回环"
    if parsed.is_link_local:
        return "链路本地"
    if parsed in ULA_IPV6:
        return "ULA 内网"
    if parsed.is_global and not parsed.is_multicast:
        return "公网"
    return "其他"


def _ipv6_interface_kind(name, flags=()):
    if "LOOPBACK" in flags or re.fullmatch(r"lo\d+", name):
        return "回环接口"
    if re.fullmatch(r"utun\d+", name):
        return "utun 隧道"
    if re.fullmatch(r"(?:en|eth|wlan)\d+", name):
        return "物理接口"
    return "其他接口"


def ipv6_check(config, run):
    strict = config.get("privacy_strict", True) is not False
    interfaces = ipv6_interfaces(_run(run, ["/sbin/ifconfig", "-a"]))
    defaults = ipv6_defaults(_run(run, ["/usr/sbin/netstat", "-rn", "-f", "inet6"]))
    scope = ("仅观察当前系统接口与路由，未进行 IPv6 HTTP/UDP 或浏览器旁路实测。"
             "utun 可能属于不同的 VPN，不能仅凭接口名称确认其流量由 Surge 接管。")
    if interfaces is None or defaults is None:
        return _evidence_row("ipv6_paths", "IPv6 接口与路由", "unknown",
                             "接口或路由读取不完整，无法判断当前 IPv6 路径。", strict,
                             ["活跃接口：" + ("读取失败" if interfaces is None else "已读取") + "。",
                              "默认路由：" + ("读取失败" if defaults is None else "已读取") + "。"], scope)
    kinds = {value["name"]: _ipv6_interface_kind(value["name"], value["flags"]) for value in interfaces}
    non_tunnel_kinds = {"物理接口", "其他接口"}
    global_interfaces = []
    evidence = []
    for value in interfaces:
        address_kinds = [_ipv6_address_kind(address) for address in value["addresses"]]
        if not address_kinds:
            continue
        kind = kinds[value["name"]]
        if "公网" in address_kinds and kind in non_tunnel_kinds:
            global_interfaces.append(value["name"])
        counts = "、".join(label + " ×" + str(address_kinds.count(label))
                          for label in ("公网", "链路本地", "ULA 内网", "回环", "其他")
                          if label in address_kinds)
        evidence.append(value["name"] + "（" + kind + "）：" + counts + "。")
    if not evidence:
        evidence.append("活跃接口未发现 IPv6 地址。")
    non_tunnel_defaults = []
    for value in defaults:
        name = value["interface"]
        kind = kinds.get(name, _ipv6_interface_kind(name))
        if kind in non_tunnel_kinds:
            non_tunnel_defaults.append(name)
        evidence.append("默认路由：" + name + "（" + kind + "）。")
    if not defaults:
        evidence.append("未发现 IPv6 默认路由。")
    if global_interfaces or non_tunnel_defaults:
        evidence.append("需核对的非 utun 接口：" +
                        "、".join(dict.fromkeys(global_interfaces + non_tunnel_defaults)) + "。")
        return _evidence_row("ipv6_paths", "IPv6 接口与路由", "warn",
                             "发现非隧道公网地址或默认路由；存在可能的旁路，尚未证实泄漏。",
                             False, evidence, scope)
    detail = "未观测到物理接口公网 IPv6 或非隧道默认路由；不能据此证明没有旁路。"
    return _evidence_row("ipv6_paths", "IPv6 接口与路由", "info", detail, False, evidence, scope)


def _comparison(identifier, title, actual, expected, scope):
    required = bool(expected)
    if not actual:
        return check_row(identifier, title, "unknown", "无法读取" + title + "。", required)
    if expected:
        matched = actual == expected
        return check_row(identifier, title, "pass" if matched else "warn",
                         "当前：" + actual + "；预期：" + expected + "。" + scope, required)
    return check_row(identifier, title, "info", "当前：" + actual + "。" + scope, False)


def environment_checks(config, run):
    link = _run(run, ["/usr/bin/readlink", "/etc/localtime"])
    timezone = ""
    if link and "/zoneinfo/" in link:
        timezone = _safe_text(link.split("/zoneinfo/", 1)[1])
    locale = _safe_text(_run(run, ["/usr/bin/defaults", "read", "-g", "AppleLocale"]))
    language_text = _run(run, ["/usr/bin/defaults", "read", "-g", "AppleLanguages"])
    languages = []
    if language_text:
        languages = re.findall(r'["\']([A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*)["\']', language_text)
        if not languages:
            languages = re.findall(r"(?m)^\s*([A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*)\s*,?\s*$", language_text)
    return [
        _comparison("system_timezone", "系统时区", timezone, config.get("expected_timezone", ""), "仅比较设置，不证明实际所在地。"),
        _comparison("system_locale", "系统区域格式", locale, config.get("expected_locale", ""), "区域格式不等于国籍或居住地。"),
        check_row("system_languages", "系统语言", "info" if languages else "unknown",
                  "当前顺序：" + "、".join(languages) + "；浏览器语言以浏览器实测回执为准。" if languages else "无法读取系统语言顺序。", False),
    ]


def _valid_geo(payload, expected_ip):
    if not isinstance(payload, dict):
        return False
    try:
        return ipaddress.ip_address(payload.get("address", payload.get("ip", ""))) == ipaddress.ip_address(expected_ip)
    except (TypeError, ValueError):
        return False


def _date(value):
    try:
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return "未知"
        return dt.datetime.fromtimestamp(value, dt.timezone.utc).strftime("%Y-%m-%d")
    except (ValueError, OSError, OverflowError):
        return "未知"


def _geoip_via_proxy(config, run):
    if not listener_is_surge(config, run=run):
        return None
    try:
        address = str(ipaddress.ip_address(config["expected_ip"]))
        output = run(["/usr/bin/curl", "--disable", "--silent", "--show-error", "--fail",
                      "--connect-timeout", "5", "--max-time", "10", "--max-filesize", "65536",
                      "--proto", "=https", "--proxy", config["proxy_url"], "--noproxy", "",
                      "https://ipwho.is/" + address], capture_output=True, text=True, timeout=12,
                     check=False, env=proxy_env(config["proxy_url"]))
        if output.returncode or not isinstance(output.stdout, str) or len(output.stdout) > 65536:
            return None
        value = json.loads(output.stdout)
        if not isinstance(value, dict) or value.get("success") is not True or not _valid_geo(value, address):
            return None
        connection = value.get("connection")
        if not isinstance(connection, dict):
            connection = {}
        return {"address": value.get("ip"), "country": value.get("country_code"),
                "asn": connection.get("asn"), "organization": connection.get("org")}
    except (OSError, subprocess.SubprocessError, TypeError, ValueError, KeyError):
        return None


def geoip_checks(config, surge, run):
    country_expected = config.get("expected_country", "").upper()
    asn_expected = config.get("expected_asn", "").upper().removeprefix("AS")
    try:
        payload = surge.call("geoip", config["expected_ip"])
    except (Blocked, OSError, ValueError, TypeError, KeyError):
        payload = None
    source = "Surge 本地数据库"
    dates = ""
    if _valid_geo(payload, config.get("expected_ip", "")) and (payload.get("country") or payload.get("asn")):
        dates = "；GeoIP 库 " + _date(payload.get("geoip-db-date")) + "，ASN 库 " + _date(payload.get("asn-db-date"))
    else:
        payload = _geoip_via_proxy(config, run)
        source = "ipwho.is（经显式本地代理查询）"
    country = payload.get("country") if isinstance(payload, dict) else None
    asn = payload.get("asn") if isinstance(payload, dict) else None
    country = country.upper() if isinstance(country, str) and re.fullmatch(r"[A-Za-z]{2}", country) else ""
    asn = str(asn) if isinstance(asn, int) and not isinstance(asn, bool) and 0 < asn < 2 ** 32 else ""
    organization = _safe_text(payload.get("organization")) if isinstance(payload, dict) else ""
    suffix = " 来源：" + source + dates + "；查询对象是保存的预期出口，实际出口另由线路检查验证。"
    country_row = _comparison("geoip_country", "出口 GeoIP 国家", country, country_expected, suffix)
    asn_row = _comparison("geoip_asn", "出口 ASN", asn, asn_expected, suffix +
                          (" 机构：" + organization + "。" if organization else "") + " ASN 或运营商品牌不能保证该地址是真实住宅线路。")
    return [country_row, asn_row]


def audit_checks(config, surge=None, run=subprocess.run, browser=True, external_dns=True):
    """Return scoped observations; Chrome is short-lived and account-free.

    `browser=False` is a read-only quick inventory without launching Chrome. It
    deliberately leaves the WebRTC result unknown, never reuses a prior pass.
    """
    surge = surge or Surge(run=run)
    strict = config.get("privacy_strict", True) is not False
    try:
        status = surge.status()
    except (Blocked, OSError, ValueError, TypeError):
        status = {}
    if not isinstance(status, dict):
        status = {}
    features = status.get("features")
    features = features if isinstance(features, dict) else {}
    rows = []
    for name, title in (("enhanced-mode", "Surge 增强模式"), ("system-proxy", "Surge 系统代理")):
        enabled = features.get(name)
        observed = isinstance(enabled, bool)
        rows.append(check_row("audit_" + name.replace("-", "_"), title,
                              "info" if observed else "unknown",
                              ("已开启。" if enabled else "未开启。") + "这里只读展示；本工具启动的程序使用显式本地代理。"
                              if observed else "无法读取当前开关状态。", False))
    rows.extend(dns_checks(config, surge, status, run))
    rows.append(ipv6_check(config, run))
    rows.extend(environment_checks(config, run))
    rows.extend(geoip_checks(config, surge, run))
    containment_verified = False
    containment_row = None
    if config.get("browser_path"):
        from .containment import validate_scope
        try:
            validate_scope(config, surge)
            containment_verified = True
            containment_row = check_row("browser_containment", "Claude 专用入口与旁路阻断", "pass",
                                        "专用代理端口固定到唯一节点；Surge 规则核验显示专用浏览器的旁路 TCP/UDP 请求会被拒绝。", True)
            rows.append(containment_row)
        except (Blocked, OSError, ValueError, TypeError) as exc:
            rows.append(check_row("browser_containment", "Claude 专用入口与旁路阻断", "fail",
                                  str(exc) if isinstance(exc, Blocked) else "未能确认专用浏览器的网络边界。", True))
            rows.append(check_row("browser_webrtc", "浏览器 WebRTC ICE 实测", "unknown",
                                  "先修复专用入口与旁路拒绝规则；未启动浏览器探针。", True))
            return rows
    if browser:
        if containment_verified:
            browser_row = chrome_probe_check(config, run=run, containment_verified=True)
            # A complete empty ICE receipt is accepted only with independent
            # scope evidence. Recheck after the asynchronous browser experiment
            # so it cannot retain a pass based solely on the earlier snapshot.
            try:
                validate_scope(config, surge)
            except (Blocked, OSError, ValueError, TypeError) as exc:
                containment_row.update(
                    status="fail",
                    detail="浏览器探测结束后的范围复核失败：" +
                           (str(exc) if isinstance(exc, Blocked) else "无法确认当前专用入口与旁路拒绝规则。"))
                browser_row["required"] = True
                if browser_row["status"] == "fail":
                    browser_row["detail"] += " 探测结束后也未能重新核验旁路保护范围。"
                else:
                    browser_row.update(
                        status="unknown",
                        detail="浏览器探测结束后，专用入口与旁路拒绝规则未能重新核验；"
                               "已撤回依赖先前保护状态的通过结论，请重新检查。")
            else:
                containment_row["detail"] += (
                    " 浏览器探测前后均完成范围复核；这些是两个时点的规则核验，"
                    "不证明期间每个瞬间的状态或系统防火墙级阻断。")
            rows.append(browser_row)
        else:
            rows.append(chrome_probe_check(config, run=run))
    else:
        rows.append(check_row("browser_webrtc", "浏览器 WebRTC ICE 实测", "unknown",
                              "本次选择不启动检测浏览器，未进行 WebRTC 实测。", strict))
    if (browser and external_dns and containment_verified and
            all(not item.get("required", True) or item["status"] == "pass" for item in rows)):
        observed = observe_proxy_dns(config, surge, run=run)
        rows = [observed if item["id"] == "dns_egress" else item for item in rows]
    return rows

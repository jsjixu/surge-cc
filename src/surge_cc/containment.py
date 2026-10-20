"""Dedicated browser routing scope while Surge rule mode and VIF are active.

This validates Surge's current routing decisions, not an OS firewall. A separate
Chrome profile using the personal Chrome binary is not a separate process scope.
No function in this module applies a profile, changes Surge, or starts a browser.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from .core import Blocked, CHROME, profile_sections, route_is_fixed, safe_name, split_fields, validate_topology

BEGIN = "# BEGIN SURGE CC CONTAINMENT"
END = "# END SURGE CC CONTAINMENT"
DEFAULT_EXISTING_LISTENER = "127.0.0.1:6152"


def _quoted(value: str) -> str:
    if not isinstance(value, str) or not value or any(c in value for c in '\r\n\0"'):
        raise Blocked("专用线路的名称或路径包含无法安全生成的字符。")
    return '"' + value + '"'


def _browser_identity(config: dict, *, require_files: bool) -> tuple[Path, Path, Path | None]:
    value = config.get("browser_path")
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise Blocked("尚未设置独立浏览器的完整可执行路径。")
    binary = Path(value)
    if (not binary.is_absolute() or str(binary) != os.path.normpath(value) or
            binary.parts[-3:] != ("Contents", "MacOS", "Google Chrome")):
        raise Blocked("独立浏览器必须指向 app 内 Contents/MacOS/Google Chrome。")
    bundle = binary.parents[2]
    if bundle.name != "Surge CC Browser.app" or binary == CHROME:
        raise Blocked("必须使用 Surge CC Browser.app，不能把个人 Chrome 作为隔离浏览器。")
    _quoted(str(bundle))
    if not require_files:
        return binary, bundle, None
    try:
        if (not binary.is_file() or not os.access(binary, os.X_OK) or
                binary.resolve(strict=True) != binary):
            raise Blocked("独立浏览器不存在、不可执行，或路径经过符号链接。")
        if CHROME.exists() and binary.samefile(CHROME):
            raise Blocked("独立浏览器不能与个人 Chrome 使用同一个可执行文件。")
        versions = bundle / "Contents/Frameworks/Google Chrome Framework.framework/Versions"
        relative = Path("Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper")
        candidates = [versions / "Current" / relative]
        candidates += sorted(versions.glob("*/" + str(relative)))
        for candidate in candidates:
            if not candidate.is_file() or not os.access(candidate, os.X_OK):
                continue
            helper = candidate.resolve(strict=True)
            if helper.is_relative_to(bundle):
                return binary, bundle, helper
    except OSError:
        raise Blocked("无法确认独立浏览器及其辅助进程的文件位置。") from None
    raise Blocked("未找到位于独立浏览器 app 内的可执行 Chrome Helper。")


def _endpoint(config: dict) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int, str]:
    try:
        value = urlsplit(config["proxy_url"])
        address = ipaddress.ip_address(value.hostname or "")
        port = value.port
    except (KeyError, TypeError, ValueError):
        raise Blocked("独立代理入口格式不正确。") from None
    if (value.scheme != "http" or not address.is_loopback or port is None or
            not 1 <= port <= 65535 or port in {6152, 6153} or value.username is not None or value.password is not None or
            value.path not in {"", "/"} or value.query or value.fragment):
        raise Blocked("独立浏览器需要单独的本机 HTTP 端口，不能使用原有默认 6152/6153 入口。")
    host = f"[{address}]" if address.version == 6 else str(address)
    return address, port, f"{host}:{port}"


def _content_comment(value: str) -> tuple[str, str]:
    """Split trailing comments outside quotes, keeping their original whitespace."""
    quoted = None
    for index, character in enumerate(value):
        if character in {'"', "'"}:
            if quoted is None:
                quoted = character
            elif quoted == character:
                quoted = None
        if (quoted is None and index > 0 and value[index - 1].isspace() and
                (character in "#;" or value[index:index + 2] == "//")):
            prefix = value[:index].rstrip()
            return prefix, value[len(prefix):]
    return value, ""


def _listen_address(value: str, *, default_port: int = 6152) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int, bool]:
    endpoint = value.strip()
    authenticated = "@" in endpoint
    endpoint = endpoint.rsplit("@", 1)[-1]
    try:
        if endpoint.startswith("["):
            match = re.fullmatch(r"\[([^\]]+)\](?::([0-9]+))?", endpoint)
            if match is None:
                raise ValueError()
            address = ipaddress.ip_address(match[1])
            port = int(match[2]) if match[2] else default_port
        else:
            try:
                address = ipaddress.ip_address(endpoint)
                port = default_port
            except ValueError:
                host, separator, text_port = endpoint.rpartition(":")
                if not separator or not text_port.isdecimal():
                    raise ValueError()
                address, port = ipaddress.ip_address(host), int(text_port)
        if not 1 <= port <= 65535:
            raise ValueError()
        return address, port, authenticated
    except ValueError:
        raise Blocked("现有 HTTP 监听地址无法可靠解析，未生成可能改变原入口的配置。") from None


def _listeners(profile: str) -> list[str]:
    found = []
    for line in profile_sections(profile).get("general", []):
        if "=" in line and line.split("=", 1)[0].strip().lower() == "http-listen":
            content, _ = _content_comment(line.split("=", 1)[1].strip())
            found.append(content)
    if len(found) != 1:
        raise Blocked("生效配置必须包含唯一且明确的 http-listen。")
    listeners = [entry.strip() for entry in split_fields(found[0])]
    if not listeners or any(not entry for entry in listeners):
        raise Blocked("HTTP 监听入口为空或不完整。")
    return listeners


def _expected_rules(config: dict, bundle: Path, port: int) -> tuple[list[str], list[str]]:
    _quoted(config.get("group"))
    return (["IN-PORT", str(port), config["group"]],
            ["PROCESS-NAME", str(bundle) + "/", "REJECT"])


def _rule_fields(line: str) -> list[str]:
    content, _ = _content_comment(line)
    return [field.strip() for field in split_fields(content)]


def _scope_state(config: dict, surge) -> tuple[dict, str, dict]:
    status = surge.status()
    if (not isinstance(status, dict) or status.get("mode") != "rule" or
            not isinstance(status.get("features"), dict) or
            status["features"].get("enhanced-mode") is not True):
        raise Blocked("独立浏览器范围保护要求 Surge 规则模式和增强模式同时有效。")
    if config.get("profile_path") and status.get("profile-path") != config["profile_path"]:
        raise Blocked("当前 Surge 配置与独立线路设置不一致。")
    profile = surge.profile()
    group = surge.group(config["group"])
    validate_topology(profile, group, config)
    if group.get("selected") != config["policy"]:
        raise Blocked("独立入口的固定节点未选中。")
    return status, profile, group


def _rejects(response: dict) -> bool:
    # Surge upgrades frequent REJECT hits to REJECT-DROP; both remain terminal
    # rejection. Require the exact observed policy/type pair, never a proxy hop.
    # https://manual.nssurge.com/policies/reject.html
    return (isinstance(response, dict) and response.get("rule-policy") == "REJECT" and
            response.get("final") in ("REJECT", "REJECT-DROP") and
            response.get("final-type") == response.get("final") and
            response.get("steps") == [])


def validate_scope(config: dict, surge) -> None:
    """Reject missing/uncertain dedicated scope; this does not send test traffic."""
    binary, bundle, helper = _browser_identity(config, require_files=True)
    address, port, _ = _endpoint(config)
    status, profile, group = _scope_state(config, surge)
    matched = False
    for listener in _listeners(profile):
        bound, listen_port, authenticated = _listen_address(listener)
        if listen_port == port:
            if not bound.is_loopback or authenticated:
                raise Blocked("专用端口不能对公网监听，也不能使用本工具未配置的入口认证。")
            matched = matched or bound == address
    if not matched:
        raise Blocked("生效配置没有专用的本机 HTTP 监听入口。")
    rules = profile_sections(profile).get("rule", [])
    expected = _expected_rules(config, bundle, port)
    if len(rules) < 2 or tuple(_rule_fields(line) for line in rules[:2]) != expected:
        raise Blocked("规则开头必须先固定专用入口，再拒绝独立浏览器绕过入口的连接。")
    # TCP/UDP include IPv6. Explicit zero listen-port models raw VIF traffic,
    # not a request accepted by the dedicated HTTP listener.
    raw_cases = (
        ("203.0.113.1", "192.0.2.2", "TCP", 443),
        ("203.0.113.1", "192.0.2.2", "UDP", 3478),
        ("203.0.113.1", "192.0.2.2", "STUN", 3478),
        ("203.0.113.1", "192.0.2.2", "QUIC", 443),
        ("2001:db8::1", "2001:db8::2", "TCP", 443),
        ("2001:db8::1", "2001:db8::2", "UDP", 3478),
    )
    for process in (binary, helper):
        for hostname, source, protocol, destination_port in raw_cases:
            response = surge.call(
                "rule", "explain", hostname, f"dest-port={destination_port}",
                f"protocol={protocol}", f"source-address={source}", "source-port=42123",
                "is-local=on", "listen-port=0", f"process-path={process}")
            if not _rejects(response):
                role = "主程序" if process == binary else "辅助进程"
                family = "IPv6" if ":" in hostname else "IPv4"
                observed = {key: response.get(key) for key in ("rule-policy", "final", "final-type")}
                details = "；".join(f"{key}={value if safe_name(value) else '未知'}"
                                   for key, value in observed.items())
                raise Blocked(f"独立浏览器存在未被拒绝或无法确认的原始路径：{role} {family} {protocol}。{details}")
        for hostname, protocol, destination_port in (
                ("example.com", "HTTP", 80), ("api.anthropic.com", "HTTPS", 443)):
            response = surge.call(
                "rule", "explain", hostname, f"dest-port={destination_port}", f"protocol={protocol}",
                f"sni={hostname}", f"http-host={hostname}", f"source-address={address}",
                "is-local=on", f"listen-port={port}", f"process-path={process}")
            if not route_is_fixed(response, config):
                raise Blocked("专用 HTTP 入口没有固定到指定的单一节点。")
    final_status, final_profile, final_group = _scope_state(config, surge)
    if (final_status.get("profile-path") != status.get("profile-path") or
            final_profile != profile or final_group != group):
        raise Blocked("检查期间 Surge 生效配置或策略组发生变化。")


def _remove_owned_blocks(lines: list[str]) -> list[str]:
    output, block = [], None
    section = ""
    for line in lines:
        stripped = line.strip()
        if stripped == BEGIN:
            if block is not None or section != "rule":
                raise Blocked("专用范围规则标记位置不完整，未自动改写。")
            block = []
            continue
        if stripped == END:
            if block is None:
                raise Blocked("专用范围规则结束标记缺少开头。")
            active = [item.strip() for item in block
                      if item.strip() and not item.lstrip().startswith(("#", ";", "//"))]
            if (len(active) != 2 or _rule_fields(active[0])[:1] != ["IN-PORT"] or
                    len(_rule_fields(active[0])) != 3 or
                    _rule_fields(active[1])[:1] != ["PROCESS-NAME"] or
                    len(_rule_fields(active[1])) != 3 or _rule_fields(active[1])[-1] != "REJECT"):
                raise Blocked("受管理规则段包含未知内容，请人工确认后再生成。")
            block = None
            continue
        if block is not None:
            block.append(line)
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
        output.append(line)
    if block is not None:
        raise Blocked("专用范围规则缺少结束标记，未自动改写。")
    return output


def patch_profile(text: str, config: dict) -> str:
    """Generate only a text proposal; keep unrelated settings and credentials."""
    _, bundle, _ = _browser_identity(config, require_files=False)
    address, port, endpoint = _endpoint(config)
    expected = _expected_rules(config, bundle, port)
    if not isinstance(text, str):
        raise Blocked("Surge 配置必须是完整文本。")
    newline = "\r\n" if "\r\n" in text and "\n" not in text.replace("\r\n", "") else "\n"
    lines = _remove_owned_blocks(text.splitlines(keepends=True))
    headers: dict[str, list[int]] = {}
    entries: dict[str, list[tuple[int, str]]] = {}
    current = ""
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1].strip().lower()
            headers.setdefault(current, []).append(index)
        elif current == "general" and "=" in line and not stripped.startswith(("#", ";", "//")):
            key, value = line.split("=", 1)
            entries.setdefault(key.strip().lower(), []).append((index, value.rstrip("\r\n")))
    if len(headers.get("rule", [])) != 1 or len(headers.get("general", [])) > 1:
        raise Blocked("需要唯一 Rule 段和最多一个 General 段，不能合并存在歧义的配置。")
    for key in ("http-listen", "interface", "port", "socks5-listen", "socks-interface", "socks-port"):
        if len(entries.get(key, [])) > 1:
            raise Blocked("监听入口存在重复设置，不能确认原有入口。")
    if ((entries.get("http-listen") and (entries.get("interface") or entries.get("port"))) or
            (entries.get("socks5-listen") and (entries.get("socks-interface") or entries.get("socks-port")))):
        raise Blocked("新旧监听语法同时存在，无法确认优先级，请先明确原有入口。")
    if entries.get("http-listen"):
        _, raw = entries["http-listen"][0]
        content, comment = _content_comment(raw)
        listeners = [entry.strip() for entry in split_fields(content.strip())]
        existing_value = content.rstrip()
    else:
        comment = ""
        interface = _content_comment(entries.get("interface", [(-1, "127.0.0.1")])[0][1])[0].strip()
        legacy_port = _content_comment(entries.get("port", [(-1, "6152")])[0][1])[0].strip()
        try:
            ip = ipaddress.ip_address(interface)
            if not legacy_port.isdecimal() or not 1 <= int(legacy_port) <= 65535:
                raise ValueError()
        except ValueError:
            raise Blocked("旧版 interface/port 无法确认，未更改原有入口。") from None
        host = f"[{ip}]" if ip.version == 6 else str(ip)
        listeners = [f"{host}:{int(legacy_port)}"]
        existing_value = " " + listeners[0]
    present = False
    for listener in listeners:
        bound, number, authenticated = _listen_address(listener)
        if number == port:
            if not bound.is_loopback or authenticated:
                raise Blocked("专用端口已被公开监听或认证入口使用，请选择另一端口。")
            present = present or bound == address
    value = existing_value + ("" if present else ", " + endpoint) + comment
    replacement = "http-listen =" + value + newline
    socks_replacement = None
    if entries.get("socks5-listen"):
        content, _ = _content_comment(entries["socks5-listen"][0][1])
        for listener in split_fields(content.strip()):
            _, socks_number, authenticated = _listen_address(listener, default_port=6153)
            if authenticated:
                raise Blocked("SOCKS 入口不支持密码语法，无法确认原有配置。")
            if socks_number == port:
                raise Blocked("专用 HTTP 端口与已有 SOCKS 入口冲突。")
    else:
        socks_interface = _content_comment(entries.get("socks-interface", [(-1, "127.0.0.1")])[0][1])[0].strip()
        socks_port = _content_comment(entries.get("socks-port", [(-1, "6153")])[0][1])[0].strip()
        try:
            socks_ip = ipaddress.ip_address(socks_interface)
            if not socks_port.isdecimal() or not 1 <= int(socks_port) <= 65535:
                raise ValueError()
        except ValueError:
            raise Blocked("旧版 SOCKS 入口无法确认，未更改原有入口。") from None
        if int(socks_port) == port:
            raise Blocked("专用 HTTP 端口与已有 SOCKS 入口冲突。")
        socks_host = f"[{socks_ip}]" if socks_ip.version == 6 else str(socks_ip)
        socks_replacement = f"socks5-listen = {socks_host}:{int(socks_port)}" + newline
    # Convert legacy HTTP listener keys as one related setting; do not leave
    # ambiguous precedence between legacy and current syntax.
    legacy_keys = ("interface", "port", "socks-interface", "socks-port")
    skip = {index for key in legacy_keys for index, _ in entries.get(key, [])}
    listen_index = entries["http-listen"][0][0] if entries.get("http-listen") else None
    rule_header = headers["rule"][0]
    general_header = headers.get("general", [None])[0]
    output = []
    if general_header is None:
        output.extend(["[General]" + newline, replacement])
        if socks_replacement is not None:
            output.append(socks_replacement)
        output.append(newline)
    for index, line in enumerate(lines):
        if index in skip:
            continue
        if index == listen_index:
            output.append(replacement)
        else:
            output.append(line)
        if index == general_header and listen_index is None:
            if not output[-1].endswith(("\n", "\r")):
                output[-1] += newline
            output.append(replacement)
        if index == general_header and socks_replacement is not None:
            if not output[-1].endswith(("\n", "\r")):
                output[-1] += newline
            output.append(socks_replacement)
        if index == rule_header:
            if not output[-1].endswith(("\n", "\r")):
                output[-1] += newline
            output.extend([
                BEGIN + newline,
                f"IN-PORT,{expected[0][1]},{_quoted(expected[0][2])}" + newline,
                f"PROCESS-NAME,{_quoted(expected[1][1])},REJECT" + newline,
                END + newline,
            ])
    return "".join(output)

from __future__ import annotations

import csv
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import uuid
from urllib.parse import urlsplit

SURGE_CLI = Path("/Applications/Surge.app/Contents/Applications/surge-cli")
CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
APP_SUPPORT = Path.home() / "Library/Application Support/Surge CC"
DEFAULT_CONFIG = APP_SUPPORT / "config.json"
DEFAULT_HOSTS = (
    "claude.ai", "claude.com", "platform.claude.com", "code.claude.com",
    "api.anthropic.com", "console.anthropic.com", "statsig.anthropic.com",
    "claudeusercontent.com", "claudemcpcontent.com", "claude.app",
)
PROXY_VARIABLES = {
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "npm_config_proxy", "npm_config_https_proxy", "npm_config_noproxy",
}
CHECK_IDS = {"surge", "mode", "group", "definition", "route", "proxy", "exit", "stable"}


class Blocked(Exception):
    """A safe user-facing diagnostic, never containing subprocess output."""


class BrowserProfileBusy(Blocked):
    """Known browser singleton state eligible for an explicit safe repair check."""


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def row(key: str, title: str, ok: bool, detail: str) -> dict:
    return {"id": key, "title": title, "status": "pass" if ok else "fail", "detail": detail}


def result(checks: list[dict], config: dict | None = None, summary: str | None = None) -> dict:
    identifiers = [c["id"] for c in checks]
    good = bool(checks) and all(c["status"] == "pass" for c in checks if c.get("required", True))
    good = good and len(set(identifiers)) == len(identifiers) and CHECK_IDS.issubset(identifiers)
    incomplete = any(c["status"] in {"unknown", "warn", "fail"} for c in checks if not c.get("required", True))
    headline = ("基础检查通过，部分项目待确认" if incomplete else "本次已执行的检查通过，可以启动") if good else "检查未通过，已阻止启动"
    return {"schema": 1, "ok": good, "summary": summary or headline,
            "checked_at": now(), "checks": checks, "settings": config or {}}


def global_mode_allowed(report: dict) -> bool:
    """Recognize only the explicit global-mode exception; never bless a failed gate."""
    if (not isinstance(report, dict) or type(report.get("schema")) is not int or
            report.get("schema") != 1 or report.get("ok") is not False or
            report.get("paused") is not True or
            report.get("pause_reason") != "surge-global-mode" or
            report.get("surge_mode") != "proxy" or
            report.get("launch_allowed") is not True or
            report.get("protection_active") is not False):
        return False
    checks = report.get("checks")
    if not isinstance(checks, list) or not checks:
        return False
    indexed = {}
    for item in checks:
        if (not isinstance(item, dict) or not isinstance(item.get("id"), str) or
                not item["id"] or item["id"] in indexed or
                type(item.get("required", True)) is not bool or
                not isinstance(item.get("status"), str) or
                item.get("status") not in {"pass", "fail", "warn", "unknown", "info"}):
            return False
        indexed[item["id"]] = item
        if (item["id"] != "mode" and item.get("required", True) and
                item["status"] != "pass"):
            return False
    return (indexed.get("surge", {}).get("status") == "pass" and
            indexed.get("surge", {}).get("required", True) is True and
            indexed.get("mode", {}).get("status") == "fail" and
            indexed.get("mode", {}).get("required", True) is True)


def _global_mode_report(config: dict) -> dict:
    checks = [row("surge", "Surge 连接", True, "已通过本机控制接口连接。"),
              row("mode", "规则模式", False,
                  "Surge 当前为全局代理模式；固定出口保护已挂起，允许启动并跟随 Surge 全局出口；此状态不代表线路检查通过。")]
    report = result(checks, config)
    report.update(paused=True, pause_reason="surge-global-mode", surge_mode="proxy",
                  launch_allowed=True, protection_active=False,
                  summary="保护已挂起：允许启动，流量跟随 Surge 全局代理；固定出口与断线阻断保护未生效。")
    return report


def fresh_global_mode_report(config: dict, surge) -> dict | None:
    """Re-observe a deliberate mode change without turning ordinary failure into pass."""
    try:
        status = surge.status()
    except Exception:
        # This is only an optional, fresh global-mode observation after failure.
        # Preserve the original failure whenever the observation is unavailable.
        return None
    if (isinstance(status, dict) and isinstance(status.get("features"), dict)
            and status.get("mode") == "proxy"):
        return _global_mode_report(config)
    return None


def _finish_checks(checks: list[dict], config: dict, surge) -> dict:
    report = result(checks, config)
    if report["ok"] is not True:
        return fresh_global_mode_report(config, surge) or report
    return report


def safe_name(value: str) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 160 and not any(ord(c) < 32 for c in value)


def validate_config(config: dict) -> dict:
    if not isinstance(config, dict) or config.get("schema") != 1:
        raise Blocked("配置格式不支持，请重新保存设置。")
    allowed = {"schema", "group", "policy", "expected_ip", "proxy_url", "profile_path", "hosts",
               "expected_timezone", "expected_locale", "expected_country", "expected_asn",
               "browser_language", "privacy_strict", "guard_interval", "workspace", "browser_path",
               "cli_process_paths", "default_model", "default_effort", "browser_start_page"}
    if set(config) - allowed:
        raise Blocked("配置包含不支持的字段。")
    for key in ("group", "policy"):
        if not safe_name(config.get(key, "")):
            raise Blocked("请填写有效的策略组和节点名称。")
    if config["policy"].upper() in {"DIRECT", "REJECT", "REJECT-DROP", "REJECT-TINYGIF", "PROXY"}:
        raise Blocked("必须指定实际代理节点，不能使用 DIRECT 或系统内置策略。")
    try:
        config = dict(config)
        config["expected_ip"] = str(ipaddress.ip_address(config["expected_ip"]))
        proxy = urlsplit(config["proxy_url"])
        port = proxy.port
        address = ipaddress.ip_address(proxy.hostname or "")
    except (KeyError, TypeError, ValueError):
        raise Blocked("固定出口 IP 或本地代理地址格式不正确。") from None
    if (proxy.scheme != "http" or not address.is_loopback or not port or
            proxy.username is not None or proxy.password is not None or
            proxy.path not in ("", "/") or proxy.query or proxy.fragment):
        raise Blocked("只接受本机回环地址上的 HTTP 代理，例如 http://127.0.0.1:6152。")
    profile = config.get("profile_path", "")
    if not isinstance(profile, str) or (profile and (not Path(profile).is_absolute() or "\n" in profile)):
        raise Blocked("配置文件路径必须是绝对路径。")
    hosts = config.get("hosts", list(DEFAULT_HOSTS))
    if (not isinstance(hosts, list) or len(hosts) > 100 or
            any(not isinstance(h, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", h) for h in hosts)):
        raise Blocked("待检查域名列表格式不正确。")
    # User additions can extend, never silently remove, the baseline.
    config["hosts"] = list(dict.fromkeys([*DEFAULT_HOSTS, *hosts]))
    config["profile_path"] = profile
    browser = config.get("browser_path", "")
    if (not isinstance(browser, str) or any(ord(c) < 32 for c in browser)
            or "," in browser or (browser and (
                not Path(browser).is_absolute()
                or not browser.endswith(".app/Contents/MacOS/Google Chrome")
                or Path(browser).resolve() == CHROME.resolve()))):
        raise Blocked("专用浏览器必须使用独立应用路径，不能复用个人 Chrome。")
    config["browser_path"] = browser
    from .containment import validate_cli_process_paths
    config["cli_process_paths"] = validate_cli_process_paths(config.get("cli_process_paths", []))
    model = config.get("default_model", "")
    if not isinstance(model, str) or (model and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:\[\]-]{0,127}", model)):
        raise Blocked("默认模型必须是模型别名或 ID；留空可使用 Claude 默认值。")
    effort = config.get("default_effort", "")
    if effort not in ("", "low", "medium", "high", "max"):
        raise Blocked("默认 Effort 不受支持。")
    page = config.get("browser_start_page", "claude")
    if page not in ("claude", "newtab"):
        raise Blocked("浏览器启动页只能选择 Claude 或新标签页。")
    config.update(default_model=model, default_effort=effort, browser_start_page=page)
    for key in ("expected_timezone", "expected_locale", "expected_country", "expected_asn", "browser_language"):
        val = config.get(key, "")
        if not isinstance(val, str) or len(val) > 100 or any(ord(c) < 32 for c in val):
            raise Blocked("预期环境设置格式不正确。")
        config[key] = val.strip()
    if config["expected_country"] and not re.fullmatch(r"[A-Z]{2}", config["expected_country"]):
        raise Blocked("预期国家使用两位大写国家代码，例如 US 或 CA。")
    if config["expected_asn"] and not re.fullmatch(r"AS[0-9]+", config["expected_asn"]):
        raise Blocked("预期 ASN 使用 AS 加数字，例如 AS64500。")
    if config["browser_language"] and not re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*", config["browser_language"]):
        raise Blocked("浏览器语言格式不正确，例如 zh-CN 或 en-US。")
    strict = config.get("privacy_strict", True)
    interval = config.get("guard_interval", 10)
    workspace = config.get("workspace", "A")
    if type(strict) is not bool or type(interval) is not int or not 2 <= interval <= 60:
        raise Blocked("保护检查间隔必须为 2–60 秒，严格检查必须为布尔值。")
    if not isinstance(workspace, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", workspace):
        raise Blocked("工作区名称只允许 1–32 位字母、数字、下划线或连字符。")
    config.update(privacy_strict=strict, guard_interval=interval, workspace=workspace)
    return config


def load_config(path: Path) -> dict:
    try:
        return validate_config(json.loads(path.read_text(encoding="utf-8")))
    except FileNotFoundError:
        raise Blocked("尚未配置：先填写 Claude 策略组、固定节点、出口 IP 和本地代理地址。") from None
    except (OSError, ValueError):
        raise Blocked("无法读取配置文件。") from None


def save_config(path: Path, config: dict) -> dict:
    config = validate_config(config)
    if path.is_symlink() or any(p.is_symlink() for p in path.parents if p.exists()):
        raise Blocked("配置位置不能使用符号链接。")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".surge-cc-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(config, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return config


def proxy_env(proxy_url: str, base: dict | None = None) -> dict:
    env = dict(os.environ if base is None else base)
    for key in list(env):
        if key.lower() in PROXY_VARIABLES:
            del env[key]
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env[key] = proxy_url
    env["NO_PROXY"] = env["no_proxy"] = ""
    return env


def default_claude() -> Path:
    # Resolve a managed terminal entry back to its verified native executable;
    # invoking the shim here would recursively launch the guard. Invalid state
    # raises Blocked instead of silently finding an unprotected alternative.
    from .terminal import original_claude
    primary = Path.home() / ".local/bin/claude"
    managed = original_claude(primary)
    if managed != primary:
        return managed
    for candidate in (primary, Path("/opt/homebrew/bin/claude"), Path("/usr/local/bin/claude")):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return original_claude(candidate)
    path = shutil.which("claude")
    return original_claude(Path(path)) if path else primary


def split_fields(text: str) -> list[str]:
    try:
        return next(csv.reader([text], skipinitialspace=True, strict=True))
    except (csv.Error, StopIteration):
        raise Blocked("Surge 生效配置的语法无法可靠解析。") from None


def profile_sections(text: str) -> dict[str, list[str]]:
    """Only inspect names and topology. Never return or log node credentials."""
    sections: dict[str, list[str]] = {}
    current = ""
    for source in text.splitlines():
        line = source.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip().lower()
            sections.setdefault(current, [])
        elif current:
            sections[current].append(line)
    return sections


def definition(sections: dict, section: str, name: str) -> list[str]:
    matches = []
    for line in sections.get(section, []):
        if "=" in line:
            key, value = line.split("=", 1)
            if key.strip().strip('"') == name:
                matches.append(split_fields(value.strip()))
    if len(matches) != 1 or not matches[0] or not matches[0][0].strip():
        raise Blocked("生效配置中没有唯一的指定策略定义。")
    return matches[0]


def validate_topology(profile: str, group: dict, config: dict) -> None:
    if not isinstance(profile, str) or not isinstance(group, dict):
        raise Blocked("Surge 未返回有效的策略定义。")
    sections = profile_sections(profile)
    options = group.get("options")
    if not isinstance(options, list) or len(options) != 1:
        raise Blocked("Claude 策略组必须只含指定的一个节点，不能有备用节点或 DIRECT。")
    option = options[0]
    if (not isinstance(option, dict) or
            option.get("name") != config["policy"] or option.get("enabled") is not True or
            option.get("isGroup") is not False):
        raise Blocked("指定策略不是已启用的独立节点，或组内还存在其他路由。")
    fields = definition(sections, "proxy group", config["group"])
    if fields[0].strip().lower() != "select":
        raise Blocked("Claude 必须使用手动选择组；不接受自动测速或故障切换组。")
    members = [v.strip() for v in fields[1:] if "=" not in v]
    if members != [config["policy"]]:
        raise Blocked("生效策略组不是仅含指定节点的固定组。")
    for field in fields[1:]:
        if "=" not in field:
            continue
        key, value = (s.strip().lower() for s in field.split("=", 1))
        if key == "underlying-proxy":
            raise Blocked("策略组包含额外底层代理链。")
        if key in {"policy-path", "include-other-group", "include-all-proxies",
                   "include-all-proxy-groups"} and value not in {"0", "false"}:
            raise Blocked("策略组会动态引入其他节点，不能视为固定出口。")
    node = definition(sections, "proxy", config["policy"])
    if node[0].strip().lower() not in {"ss", "snell", "vmess", "vless", "trojan", "http", "https",
                                    "socks5", "socks5-tls", "hysteria2", "tuic", "tuic-v5",
                                    "wireguard", "ssh", "h2-connect"}:
        raise Blocked("节点类型未得到本版本验证。")
    for field in node[1:]:
        if "=" in field and field.split("=", 1)[0].strip().lower() == "underlying-proxy":
            raise Blocked("节点包含额外底层代理链，本版本不将它视为单一固定线路。")


def route_is_fixed(route: dict, config: dict) -> bool:
    if not isinstance(route, dict):
        return False
    if route.get("rule-policy") != config["group"] or route.get("final") != config["policy"]:
        return False
    final_type = route.get("final-type")
    if (not isinstance(final_type, str) or
            final_type.strip().lower() in {"", "direct", "reject", "substitute", "unknown"}):
        return False
    steps = route.get("steps")
    # No implicit substitution, nested automatic groups or underlying proxy chain.
    return (isinstance(steps, list) and len(steps) == 1 and isinstance(steps[0], dict) and
            steps[0].get("group") == config["group"] and
            steps[0].get("selected") == config["policy"] and
            steps[0].get("reason") == "user selection")


class Surge:
    def __init__(self, executable: Path = SURGE_CLI, run=subprocess.run):
        self.executable = executable
        self.run = run

    def call(self, *args: str, timeout: int = 12) -> dict:
        try:
            value = self.run([str(self.executable), *args, "--raw"], capture_output=True,
                             text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Blocked("无法连接 Surge：请确认应用正在运行，并允许本机控制接口访问。") from None
        if value.returncode != 0:
            raise Blocked("Surge 命令失败；可能未启动、接口不可用或当前版本不支持。")
        try:
            parsed = json.loads(value.stdout)
        except (TypeError, ValueError):
            raise Blocked("Surge 返回了无法识别的数据，检查按失败处理。") from None
        if not isinstance(parsed, dict) or parsed.get("error"):
            raise Blocked("Surge 返回错误或不支持的数据格式。")
        return parsed

    def status(self) -> dict:
        return self.call("status")

    def group(self, name: str) -> dict:
        group = self.call("policy-group", "get", name).get("group")
        if not isinstance(group, dict):
            raise Blocked("Surge 未返回有效的策略组。")
        return group

    def profile(self) -> str:
        profile = self.call("dump", "profile", "effective").get("profile")
        if not isinstance(profile, str) or not profile:
            raise Blocked("无法读取应用了模块后的实际配置。")
        return profile

    def route(self, host: str, config: dict, process: str) -> dict:
        proxy = urlsplit(config["proxy_url"])
        return self.call("rule", "explain", host, "dest-port=443", "protocol=HTTPS",
                         f"sni={host}", f"http-host={host}", "is-local=on",
                         f"source-address={proxy.hostname}", f"listen-port={proxy.port}",
                         f"process-path={process}")

    def pin(self, config: dict) -> None:
        group = self.group(config["group"])
        validate_topology(self.profile(), group, config)
        self.call("policy-group", "set", config["group"], config["policy"])
        if self.group(config["group"]).get("selected") != config["policy"]:
            raise Blocked("指定节点未选中，已停止。")

    def exit_matches(self, config: dict) -> bool:
        marker = "SURGE_CC_" + uuid.uuid4().hex + ":"
        # Only a match boolean reaches Surge's logs; the residential IP is never logged.
        script = (
            "const expected=" + json.dumps(config["expected_ip"]) + ";"
            "$httpClient.get({url:'https://api.ipify.org?format=json',policy:" +
            json.dumps(config["policy"], ensure_ascii=True) +
            ",timeout:12,'auto-redirect':false,'auto-cookie':false},function(e,r,d){"
            "let v={match:false,status:r?Number(r.status):0};"
            "if(!e&&v.status===200){try{v.match=JSON.parse(d).ip===expected;}catch(x){}}"
            "console.log(" + json.dumps(marker) + "+JSON.stringify(v));$done();});"
        )
        fd, name = tempfile.mkstemp(prefix="surge-cc-probe-", suffix=".js")
        try:
            with os.fdopen(fd, "w") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(script)
            response = self.call("script", "evaluate", name, "cron", "16", timeout=20)
        finally:
            os.unlink(name)
        output = response.get("output")
        if not isinstance(output, str):
            raise Blocked("出口检查没有返回有效结果。")
        matches = re.findall(re.escape(marker) + r"(\{[^\r\n]*\})", output)
        if len(matches) != 1:
            raise Blocked("出口检查输出不完整，不能视为通过。")
        try:
            parsed = json.loads(matches[0])
        except ValueError:
            raise Blocked("出口检查无法解析。") from None
        if not isinstance(parsed, dict):
            raise Blocked("出口检查返回了不支持的数据格式。")
        return parsed.get("status") == 200 and parsed.get("match") is True


def listener_is_surge(config: dict, run=subprocess.run) -> bool:
    """Require the selected loopback listener to be owned by the actual Surge app."""
    proxy = urlsplit(config["proxy_url"])
    expected_address = f"{proxy.hostname}:{proxy.port}"
    if ":" in (proxy.hostname or ""):
        expected_address = f"[{proxy.hostname}]:{proxy.port}"
    try:
        response = run(
            ["/usr/sbin/lsof", "-nP", f"-iTCP:{proxy.port}", "-sTCP:LISTEN", "-Fpcn"],
            capture_output=True, text=True, timeout=5, check=False)
        if response.returncode:
            return False
        pid = None
        owners = set()
        for line in response.stdout.splitlines():
            if line.startswith("p"):
                pid = line[1:] if line[1:].isdigit() else None
            elif line.startswith("n") and line[1:] in {expected_address, f"*:{proxy.port}"}:
                if not pid:
                    return False
                owners.add(pid)
        if len(owners) != 1:
            return False
        process = run(["/bin/ps", "-p", owners.pop(), "-o", "comm="],
                      capture_output=True, text=True, timeout=5, check=False)
        return (process.returncode == 0 and
                process.stdout.strip() == "/Applications/Surge.app/Contents/MacOS/Surge")
    except (OSError, subprocess.TimeoutExpired):
        return False


def local_proxy_check(config: dict, run=subprocess.run) -> tuple[bool, str]:
    """HTTPS CONNECT through the explicitly selected local listener, never env defaults."""
    if not listener_is_surge(config, run=run):
        return False, "无法确认本地代理端口属于 Surge；检查已停止。"
    try:
        response = run(
            ["/usr/bin/curl", "--disable", "--silent", "--show-error",
             "--connect-timeout", "5", "--max-time", "10", "--proxy", config["proxy_url"],
             "--noproxy", "", "--output", "/dev/null", "--write-out", "%{http_code}",
             "https://api.anthropic.com/v1/models"],
            capture_output=True, text=True, timeout=12, env=proxy_env(config["proxy_url"]), check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False, "本地代理连接失败或超时。"
    code = response.stdout.strip()
    if response.returncode or not re.fullmatch(r"[1-5]\d\d", code):
        return False, "HTTPS 代理连接失败；不会尝试直连。"
    if int(code) >= 500 or code == "407":
        return False, f"代理或目标返回 HTTP {code}。"
    return True, f"入口属于 Surge，HTTPS 已连通（HTTP {code}）；此项不代表账号已登录。"


def run_checks(config: dict, surge: Surge | None = None, probe=local_proxy_check,
               claude_path: Path | None = None) -> dict:
    config = validate_config(config)
    surge = surge or Surge()
    checks = []
    try:
        initial = surge.status()
        if not isinstance(initial.get("features"), dict):
            raise Blocked("Surge 状态缺少必要字段。")
        active_path = initial.get("profile-path")
        checks.append(row("surge", "Surge 连接", True, "已通过本机控制接口连接。"))
        mode_ok = initial.get("mode") == "rule"
        mode = initial.get("mode")
        mode_label = {"proxy": "全局代理", "direct": "直连"}.get(mode) if isinstance(mode, str) else None
        detail = ("使用规则模式。" if mode_ok else
                  "Surge 当前为全局代理模式；固定出口保护已挂起，允许启动并跟随 Surge 全局出口；此状态不代表线路检查通过。"
                  if mode == "proxy" else
                  "Surge 当前为直连模式，已阻止启动；请切回规则模式或全局代理模式。"
                  if mode_label else "无法确认 Surge 出站模式，已阻止启动。")
        checks.append(row("mode", "规则模式", mode_ok, detail))
        if not mode_ok:
            if mode == "proxy":
                return _global_mode_report(config)
            report = result(checks, config)
            if mode_label:
                report.update(paused=True, pause_reason="surge-mode", surge_mode=mode,
                              summary="已阻止启动：Surge 当前为直连模式。")
            return report
        if config["profile_path"] and active_path != config["profile_path"]:
            raise Blocked("Surge 当前使用的配置文件与指定配置不同。")
        group = surge.group(config["group"])
        profile_text = surge.profile()
        validate_topology(profile_text, group, config)
        selected = group.get("selected") == config["policy"]
        checks.append(row("definition", "固定节点定义", True, "仅一个已启用节点，无自动候补或底层代理链。"))
        checks.append(row("group", "当前选择", selected, "已选中指定节点。" if selected else "当前选中的不是指定节点。"))
        if not selected:
            return _finish_checks(checks, config, surge)
        processes = [str(claude_path or default_claude()), str(browser_executable(config)), "/usr/bin/curl"]
        mismatches = []
        for host in config["hosts"]:
            for process in processes:
                if not route_is_fixed(surge.route(host, config, process), config):
                    mismatches.append(host)
                    break
        checks.append(row("route", "Claude 规则", not mismatches,
                          f"已核对 {len(config['hosts'])} 个域名及 CLI、浏览器、检测请求。"
                          if not mismatches else "以下域名没有固定到指定组：" + "、".join(mismatches)))
        if mismatches:
            return _finish_checks(checks, config, surge)
        connected, detail = probe(config)
        checks.append(row("proxy", "本地代理入口", connected, detail))
        if not connected:
            return _finish_checks(checks, config, surge)
        matches = surge.exit_matches(config)
        checks.append(row("exit", "固定出口", matches,
                          "指定节点的实际出口与保存的 IP 一致。" if matches else "出口不匹配或查询失败；不会自动接受新 IP。"))
        # Detect drift over the duration of the probes. Every launch calls this anew.
        final = surge.status()
        final_profile = surge.profile()
        stable = (final.get("mode") == "rule" and final.get("profile-path") == active_path and
                  surge.group(config["group"]) == group and final_profile == profile_text)
        if stable:
            validate_topology(final_profile, surge.group(config["group"]), config)
            for host in config["hosts"]:
                for process in processes:
                    stable = stable and route_is_fixed(surge.route(host, config, process), config)
        checks.append(row("stable", "检查期间配置一致", stable,
                          "检查期间未检测到策略或配置切换。" if stable else "检查期间配置发生变化，请重新检查。"))
    except Blocked as exc:
        checks.append(row("error", "检查中断", False, str(exc)))
    return _finish_checks(checks, config, surge)


def provider_environment_ok(env: dict) -> bool:
    for name in ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"):
        if env.get(name, "").lower() not in ("", "0", "false"):
            return False
    url = env.get("ANTHROPIC_BASE_URL", "").rstrip("/")
    return not url or url == "https://api.anthropic.com"


def chrome_args(config: dict, profile_dir: Path) -> list[str]:
    args = [
        str(browser_executable(config)), f"--user-data-dir={profile_dir}",
        f"--proxy-server={config['proxy_url']}", "--proxy-bypass-list=<-loopback>",
        "--profile-directory=Default",
        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-quic", "--no-first-run", "--no-default-browser-check", "--new-window",
        "chrome://newtab/" if config.get("browser_start_page") == "newtab" else "https://claude.ai/",
    ]
    if config.get("browser_language"):
        args.insert(-1, "--lang=" + config["browser_language"])
    return args


def browser_executable(config: dict) -> Path:
    return Path(config["browser_path"]) if config.get("browser_path") else CHROME

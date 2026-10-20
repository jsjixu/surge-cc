"""Short-lived, account-free Chrome ICE observation and optional UDP STUN probes.

No probe runs at import time. The caller must explicitly invoke chrome_probe_check
(or stun_probe_check). Results describe this experiment, not a universal leak
proof. The collector is loopback-only and accepts a single token-bound response.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import core
from .core import listener_is_surge, proxy_env

DEFAULT_STUN_URLS = ("stun:stun.l.google.com:19302",)
STUN_COOKIE = 0x2112A442
WEBRTC_POLICY = "disable_non_proxied_udp"


def check_row(identifier, title, status, detail, required=False):
    return {"id": identifier, "title": title, "status": status,
            "detail": detail, "required": bool(required)}


def _valid_proxy(config):
    try:
        ipaddress.ip_address(config["expected_ip"])
        value = urlsplit(config["proxy_url"])
        return (value.scheme == "http" and ipaddress.ip_address(value.hostname).is_loopback
                and value.port is not None and value.username is None and value.password is None
                and value.path in ("", "/") and not value.query and not value.fragment)
    except (KeyError, TypeError, ValueError):
        return False


def _valid_stun_url(value):
    # Only ordinary STUN URIs: no TURN credentials, arbitrary URL schemes or JS.
    return (isinstance(value, str) and len(value) < 255 and
            re.fullmatch(r"stuns?:[A-Za-z0-9.-]+:\d{1,5}", value) is not None and
            0 < int(value.rsplit(":", 1)[1]) <= 65535)


def probe_html(token, stun_urls=DEFAULT_STUN_URLS, timeout_seconds=12):
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", token):
        raise ValueError("Invalid collector token")
    if not isinstance(stun_urls, (list, tuple)) or any(not _valid_stun_url(u) for u in stun_urls):
        raise ValueError("Invalid STUN URLs")
    milliseconds = int(max(1, min(timeout_seconds, 30)) * 1000)
    settings = json.dumps({"iceServers": [{"urls": list(stun_urls)}] if stun_urls else [],
                           "iceTransportPolicy": "all", "iceCandidatePoolSize": 0})
    return ("<!doctype html><meta charset='utf-8'><title>Surge CC privacy probe</title>"
            "<p>Surge CC 临时浏览器检测，结束后自动关闭。</p>"
            f"<script nonce='{token}'>" + """
(async function () {
  const report = {schema:1, supported:typeof RTCPeerConnection==='function',
    completed:false, timed_out:false, candidates:[], errors:[],
    language:navigator.language, languages:Array.from(navigator.languages||[]),
    timezone:Intl.DateTimeFormat().resolvedOptions().timeZone};
  let pc=null, sent=false, timer=null;
  async function finish(completed, timedOut) {
    if(sent)return; sent=true; clearTimeout(timer);
    report.completed=completed; report.timed_out=timedOut;
    if(pc){report.gathering_state=pc.iceGatheringState;pc.close();}
    try { await fetch('result',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(report),credentials:'omit',cache:'no-store'}); }
    catch(e) { document.body.textContent='Local collector unavailable'; }
  }
  if(!report.supported){await finish(false,false);return;}
  try {
    pc=new RTCPeerConnection(CONFIG);
    pc.onicecandidate=function(e){
      if(e.candidate&&report.candidates.length<256){
        report.candidates.push({candidate:e.candidate.candidate,
          address:e.candidate.address||'',type:e.candidate.type||'',
          protocol:e.candidate.protocol||''});
      } else if(!e.candidate&&pc.iceGatheringState==='complete'){finish(true,false);}
    };
    pc.onicecandidateerror=function(e){
      if(report.errors.length<20)report.errors.push({code:Number(e.errorCode)||0});
    };
    pc.onicegatheringstatechange=function(){
      if(pc.iceGatheringState==='complete')finish(true,false);
    };
    timer=setTimeout(function(){finish(false,true);},TIMEOUT);
    pc.createDataChannel('surge-cc-probe');
    await pc.setLocalDescription(await pc.createOffer());
  } catch(e) {report.exception=true;await finish(false,false);}
})();
""".replace("CONFIG", settings).replace("TIMEOUT", str(milliseconds)) + "</script>")


class ProbeCollector:
    """A local, nonce-bound one-result collector; never logs received data."""
    def __init__(self, token, html):
        self.token = token
        self.html = html.encode("utf-8")
        self.payload = None
        self.event = threading.Event()
        self.lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _reply(self, status, content=b"", kind="text/plain"):
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
                self.send_header("Content-Security-Policy",
                                 f"default-src 'none'; script-src 'nonce-{owner.token}'; connect-src 'self'; frame-ancestors 'none'")
                self.end_headers()
                if content:
                    self.wfile.write(content)

            def _host_valid(self):
                return self.headers.get("Host") == owner.authority

            def do_GET(self):
                if not self._host_valid() or self.path != f"/{owner.token}/":
                    return self._reply(404)
                self._reply(200, owner.html, "text/html; charset=utf-8")

            def do_POST(self):
                if (not self._host_valid() or self.path != f"/{owner.token}/result" or
                        self.headers.get("Origin") != owner.origin or
                        self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json"):
                    return self._reply(403)
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 131072:
                        return self._reply(413)
                    self.connection.settimeout(2)
                    raw = self.rfile.read(length)
                    if len(raw) != length:
                        return self._reply(400)
                    value = json.loads(raw)
                except (ValueError, OSError, UnicodeDecodeError):
                    return self._reply(400)
                if not isinstance(value, dict) or value.get("schema") != 1:
                    return self._reply(400)
                with owner.lock:
                    if owner.event.is_set():
                        return self._reply(409)
                    owner.payload = value
                    owner.event.set()
                self._reply(204)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.authority = f"127.0.0.1:{self.server.server_port}"
        self.origin = "http://" + self.authority
        self.url = self.origin + "/" + token + "/"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def probe_chrome_args(config, profile, local_url):
    args = [str(core.browser_executable(config)), "--headless=new", f"--user-data-dir={profile}",
            f"--proxy-server={config['proxy_url']}",
            "--proxy-bypass-list=127.0.0.1;localhost;[::1]",
            "--webrtc-ip-handling-policy=" + WEBRTC_POLICY,
            "--disable-quic", "--no-first-run", "--no-default-browser-check",
            "--disable-background-networking", "--disable-sync", "--disable-extensions",
            "--disable-component-update", "--metrics-recording-only"]
    language = config.get("browser_language", "")
    if language:
        if not isinstance(language, str) or not re.fullmatch(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*", language):
            raise ValueError("Invalid browser language")
        args.append("--lang=" + language)
    args.append(local_url)
    return args


def _candidate_address(candidate):
    if not isinstance(candidate, dict):
        return None, None
    address, kind = candidate.get("address"), candidate.get("type")
    text = candidate.get("candidate", "")
    if isinstance(text, str) and text:
        parts = text.split()
        if not address and len(parts) >= 8:
            address = parts[4]
        if not kind and "typ" in parts:
            position = parts.index("typ")
            kind = parts[position + 1] if len(parts) > position + 1 else None
    if not isinstance(address, str) or not address or kind not in {"host", "srflx", "prflx", "relay"}:
        return None, None
    return address, kind


def assess_ice(payload, expected_ip, required=True, *, containment_verified=False):
    """Assess bounded ICE evidence; containment must be verified by the caller.

    A flag, preference, or absent STUN reply alone cannot establish containment.
    The caller's proof must cover the actual dedicated browser and Surge bypass
    rejection. It does not override an observed extra address or invalid receipt.
    """
    title = "浏览器 WebRTC ICE 实测"
    unknown = lambda detail: check_row("browser_webrtc", title, "unknown", detail, required)
    if not isinstance(payload, dict) or payload.get("schema") != 1 or payload.get("supported") is not True:
        return unknown("未取得有效的浏览器 WebRTC 回执；不能据此判断有无额外出口。")
    try:
        expected = ipaddress.ip_address(expected_ip)
    except (TypeError, ValueError):
        return unknown("预期出口 IP 无效。")
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or len(candidates) > 256:
        return unknown("浏览器候选数据格式不完整。")
    public = set()
    private_count = mdns_count = 0
    invalid = False
    for candidate in candidates:
        address, kind = _candidate_address(candidate)
        if address is None:
            invalid = True
            continue
        try:
            value = ipaddress.ip_address(address)
        except ValueError:
            if address.lower().endswith(".local"):
                mdns_count += 1
            else:
                invalid = True
            continue
        if value.is_global:
            public.add(str(value))
        else:
            private_count += 1
    extra = [address for address in sorted(public) if ipaddress.ip_address(address) != expected]
    if extra:
        return check_row("browser_webrtc", title, "fail",
                         "网页可见的 ICE 候选出现预期出口之外的地址：" + "、".join(extra) +
                         "。这是本次浏览器观测到的额外地址。", True)
    if (payload.get("completed") is not True or payload.get("timed_out") is not False or
            payload.get("gathering_state") != "complete" or payload.get("exception") or invalid):
        return unknown("ICE 探测超时、未完整结束或回执不完整；没有结果不代表没有额外出口。")
    errors = payload.get("errors")
    if (not isinstance(errors, list) or len(errors) > 20 or
            any(not isinstance(error, dict) or
                not isinstance(error.get("code"), int) or isinstance(error.get("code"), bool) or
                not 0 <= error["code"] <= 999 for error in errors)):
        return unknown("ICE 错误记录格式不完整。")
    if errors:
        return unknown("ICE 已结束，但 STUN 出错；不能把无响应当作通过。")
    suffix = f"（公网候选 {len(public)}，mDNS 候选 {mdns_count}，本地候选 {private_count}）"
    if not public:
        if containment_verified is not True:
            return unknown("ICE 已结束，但没有可核对的公网候选；不能把无响应当作通过。")
        return check_row("browser_webrtc", title, "pass",
                         "专用浏览器未代理UDP被禁用且Surge旁路拒绝已核验；本次无额外公网候选" +
                         suffix + "；未测得 WebRTC 公网出口，仅覆盖本次候选收集。", required)
    return check_row("browser_webrtc", title, "pass",
                     "本次独立浏览器 ICE 测试未发现额外公网候选" + suffix +
                     "；仅覆盖本次候选收集，不是所有流量均无泄漏的保证。", required)


def _stop_browser(process):
    if process is None or process.poll() is not None:
        return True
    # Only the process group created by this invocation, never any personal Chrome.
    pid = process.pid
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return False
    try:
        if os.getpgid(pid) != pid:
            return False
        if process.poll() is not None:
            return True
        os.killpg(pid, signal.SIGTERM)
        process.wait(timeout=3)
        return True
    except ProcessLookupError:
        return True
    except subprocess.TimeoutExpired:
        try:
            if process.poll() is not None:
                return True
            if os.getpgid(pid) != pid:
                return False
            if process.poll() is not None:
                return True
            os.killpg(pid, signal.SIGKILL)
            process.wait(timeout=3)
            return True
        except ProcessLookupError:
            return True
        except (OSError, subprocess.TimeoutExpired):
            return False
    except OSError:
        return False


def _browser_environment(result, payload, config):
    """Display observed settings; missing/mismatched expectations never pass."""
    language = payload.get("language")
    if not isinstance(language, str) or not re.fullmatch(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*", language):
        language = ""
    timezone = payload.get("timezone")
    if not isinstance(timezone, str) or len(timezone) > 100:
        timezone = ""
    if timezone:
        try:
            ZoneInfo(timezone)
        except (ValueError, ZoneInfoNotFoundError):
            timezone = ""
    for label, actual, expected in (
            ("语言", language, config.get("browser_language", "")),
            ("时区", timezone, config.get("expected_timezone", ""))):
        if expected:
            result["required"] = True
        result["detail"] += " 浏览器" + label + "：" + (actual or "未取得有效回执") + "。"
        if expected and not actual:
            result["detail"] += " 未能核对预期" + label + "。"
            if result["status"] in {"pass", "warn"}:
                result["status"] = "unknown"
        elif expected and actual.lower() != expected.lower():
            result["detail"] += " 实测" + label + "与预期不同。"
            if result["status"] == "pass":
                result["status"] = "warn"
    return result


def chrome_probe_check(config, run=subprocess.run, popen=subprocess.Popen,
                       timeout=18, stun_urls=DEFAULT_STUN_URLS, *, containment_verified=False):
    """Starts only a fresh temporary headless profile; never uses saved logins.

    Language and non-proxied WebRTC UDP preferences match the launcher. Other
    saved workspace preferences/extensions are not copied, so this is a fresh-
    profile experiment, not a claim about every existing browser workspace.
    containment_verified is independent caller evidence, never inferred here
    from a launch flag, written preference, or empty candidate list.
    """
    required = config.get("privacy_strict", True) is not False
    unknown = lambda text: check_row("browser_webrtc", "浏览器 WebRTC ICE 实测", "unknown", text, required)
    if not _valid_proxy(config) or not listener_is_surge(config, run=run):
        return unknown("未确认本地 Surge 代理，未启动浏览器探测。")
    if not core.browser_executable(config).is_file():
        return unknown("未找到 Google Chrome，浏览器实测未执行。")
    token = secrets.token_urlsafe(32)
    process = None
    cleanup_ok = True
    payload = None
    try:
        html = probe_html(token, stun_urls, max(1, min(timeout - 3, 15)))
        with tempfile.TemporaryDirectory(prefix="surge-cc-ice-") as directory:
            profile = Path(directory) / "Profile"
            profile.mkdir(mode=0o700)
            default = profile / "Default"
            default.mkdir(mode=0o700)
            preferences = default / "Preferences"
            prefs = {"webrtc": {"ip_handling_policy": WEBRTC_POLICY,
                                "ip_handling_url": []}}
            language = config.get("browser_language", "")
            if language:
                prefs["intl"] = {"accept_languages": language}
            preferences.write_text(json.dumps(prefs), encoding="utf-8")
            preferences.chmod(0o600)
            with ProbeCollector(token, html) as collector:
                try:
                    process = popen(probe_chrome_args(config, profile, collector.url),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, env=proxy_env(config["proxy_url"]),
                                    start_new_session=True)
                    deadline = time.monotonic() + max(1, min(timeout, 45))
                    while time.monotonic() < deadline:
                        if collector.event.wait(min(0.2, max(0, deadline - time.monotonic()))):
                            payload = collector.payload
                            break
                        if process.poll() is not None:
                            break
                finally:
                    cleanup_ok = _stop_browser(process)
    except (OSError, ValueError, subprocess.SubprocessError):
        return unknown("独立浏览器探测未能完成；未使用个人 Chrome 资料。")
    if not cleanup_ok:
        return unknown("临时浏览器的结束状态未能确认，本次结果不作为通过。")
    if payload is None:
        return unknown("未收到独立浏览器的完整回执（退出或超时）；不能据此认定没有额外出口。")
    result = assess_ice(payload, config["expected_ip"], required,
                        containment_verified=containment_verified)
    result["detail"] += " 检测使用临时空白资料，未复制已有工作区的扩展与其他偏好。"
    return _browser_environment(result, payload, config)


def parse_stun_response(packet, transaction_id):
    """Decode RFC 8489 Binding Success; validate cookie, transaction and bounds."""
    if (not isinstance(packet, bytes) or len(packet) < 20 or
            not isinstance(transaction_id, bytes) or len(transaction_id) != 12):
        raise ValueError("Incomplete STUN response")
    kind, size, cookie = struct.unpack("!HHI", packet[:8])
    if kind != 0x0101 or cookie != STUN_COOKIE or packet[8:20] != transaction_id or size % 4 or len(packet) != 20 + size:
        raise ValueError("Invalid STUN response")
    position = 20
    mapped = None
    xor_mapped = None
    while position < len(packet):
        if position + 4 > len(packet):
            raise ValueError("Truncated STUN attribute")
        attr_type, length = struct.unpack("!HH", packet[position:position + 4])
        position += 4
        value = packet[position:position + length]
        if len(value) != length:
            raise ValueError("Truncated STUN attribute")
        position += (length + 3) & ~3
        if position > len(packet):
            raise ValueError("Truncated STUN padding")
        if attr_type not in (0x0020, 0x0001):
            continue
        if len(value) < 4 or value[0] != 0 or value[1] not in (1, 2):
            raise ValueError("Invalid STUN address")
        width = 4 if value[1] == 1 else 16
        if len(value) != 4 + width:
            raise ValueError("Invalid STUN address length")
        address = value[4:]
        if attr_type == 0x0020:
            mask = struct.pack("!I", STUN_COOKIE) + transaction_id
            address = bytes(a ^ b for a, b in zip(address, mask))
        decoded = str(ipaddress.ip_address(address))
        if attr_type == 0x0020:
            if xor_mapped is not None and xor_mapped != decoded:
                raise ValueError("Conflicting STUN mapped addresses")
            xor_mapped = decoded
        else:
            if mapped is not None and mapped != decoded:
                raise ValueError("Conflicting STUN mapped addresses")
            mapped = decoded
    if xor_mapped is not None:
        return xor_mapped
    if mapped is None:
        raise ValueError("No STUN mapped address")
    return mapped


def stun_probe_check(expected_ip, family=socket.AF_INET, host="stun.l.google.com", port=19302,
                     timeout=3, socket_factory=socket.socket, resolver=socket.getaddrinfo):
    """Optional explicit UDP experiment, not the browser and not HTTP-proxied.

    Never called by audit_checks. The remote STUN endpoint sees this experiment's
    source address. A timeout is unknown, not evidence of IPv6/UDP protection.
    """
    label = "IPv6" if family == socket.AF_INET6 else "IPv4"
    title, identifier = label + " UDP STUN 辅助实测", "stun_ipv6" if family == socket.AF_INET6 else "stun_ipv4"
    if family not in (socket.AF_INET, socket.AF_INET6):
        return check_row(identifier, title, "unknown", "地址族无效，未执行辅助探测。")
    transaction = secrets.token_bytes(12)
    packet = struct.pack("!HHI", 1, 0, STUN_COOKIE) + transaction
    try:
        destination = resolver(host, port, family, socket.SOCK_DGRAM)[0][4]
        with socket_factory(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect(destination)
            sock.send(packet)
            reply = sock.recv(2048)
        actual = parse_stun_response(reply, transaction)
        same = ipaddress.ip_address(actual) == ipaddress.ip_address(expected_ip)
        return check_row(identifier, title, "pass" if same else "fail",
                         ("本次 UDP STUN 映射地址与预期一致。" if same else "本次 UDP STUN 观测到额外映射地址：" + actual + "。") +
                         "这是系统 UDP 辅助观测，不代表浏览器或全部流量。")
    except (OSError, ValueError, IndexError, TypeError):
        return check_row(identifier, title, "unknown", "UDP STUN 超时、不可达或回执无效；不能把无响应视为保护生效。")

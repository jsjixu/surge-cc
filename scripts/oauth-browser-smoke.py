#!/usr/bin/env python3
"""Opt-in, no-login OAuth browser smoke test against the installed Surge setup.

Runs the real OAuth broker and BROWSER hook with a synthetic authorization URL.
Only the final browser destination is replaced by a local fixture, and Chrome is
made headless. Proxy and callback-bypass arguments are left untouched. Existing
Surge rules, personal browsers, user profiles, and account sessions are not edited.

The only external browser request made by the fixture is to api.ipify.org.
This does not test an actual provider login, consent, or token exchange.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlencode

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from surge_cc import core, oauth  # noqa: E402
from surge_cc.guard import stop_owned_child  # noqa: E402


def write_private_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(".writing")
    with temporary.open("w", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream)
    os.replace(temporary, path)


def serve_fixture(root: Path) -> int:
    """Separate child process owns both listening ports, as a CLI would."""
    config = core.load_config(root / "config.json")
    expected = ipaddress.ip_address(config["expected_ip"])
    lock = threading.Lock()
    results = {
        "fixture_loaded": False,
        "callback_received": False,
        "exit_request_succeeded": False,
        "exit_matches_expected": False,
        "wrong_port_attempted": False,
        "wrong_port_received_request": False,
    }

    def update(**values) -> None:
        with lock:
            results.update(values)
            write_private_json(root / "result.json", results)

    class WrongPortHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            pass

        def do_GET(self) -> None:
            update(wrong_port_received_request=True)
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

        do_POST = do_GET
        do_OPTIONS = do_GET

    wrong_server = ThreadingHTTPServer(("127.0.0.1", 0), WrongPortHandler)
    wrong_port = wrong_server.server_address[1]
    page = """<!doctype html><meta charset="utf-8"><title>Surge CC OAuth smoke</title>
<p>Synthetic callback test. No account login.</p>
<script>
(async () => {
  const report = {wrong_port_attempted: true, exit_request_succeeded: false};
  try {
    await fetch("http://127.0.0.1:WRONG_PORT/unexpected", {
      mode: "no-cors", cache: "no-store", signal: AbortSignal.timeout(5000)
    });
  } catch (_) {}
  try {
    const response = await fetch("https://api.ipify.org?format=json", {
      cache: "no-store", signal: AbortSignal.timeout(20000)
    });
    if (response.ok) {
      const body = await response.json();
      if (typeof body.ip === "string") {
        report.exit_request_succeeded = true;
        report.ip = body.ip;
      }
    }
  } catch (_) {}
  await fetch("/callback", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify(report), signal: AbortSignal.timeout(5000)
  });
})();
</script>""".replace("WRONG_PORT", str(wrong_port)).encode()

    class CallbackHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            pass

        def do_GET(self) -> None:
            if self.path != "/fixture":
                self.send_error(404)
                return
            update(fixture_loaded=True)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def do_POST(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if self.path != "/callback" or not 0 < length <= 2048:
                    raise ValueError()
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError()
                matches = False
                try:
                    matches = ipaddress.ip_address(body.get("ip", "")) == expected
                except ValueError:
                    pass
                update(
                    callback_received=True,
                    exit_request_succeeded=body.get("exit_request_succeeded") is True,
                    exit_matches_expected=matches,
                    wrong_port_attempted=body.get("wrong_port_attempted") is True,
                )
                self.send_response(204)
                self.end_headers()
            except (ValueError, TypeError):
                self.send_error(400)

    callback_server = ThreadingHTTPServer(("127.0.0.1", 0), CallbackHandler)
    servers = (callback_server, wrong_server)
    try:
        update()
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        write_private_json(root / "ready.json", {
            "callback_port": callback_server.server_address[1],
            "wrong_port": wrong_port,
        })
        threading.Event().wait()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
    return 0


def read_when_ready(path: Path, child, seconds: float) -> dict:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("fixture_stopped")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            time.sleep(0.1)
    raise RuntimeError("fixture_timeout")


def smoke(config_path: Path) -> tuple[dict, int]:
    checks = {
        "callback_owner_verified": False,
        "browser_hook_succeeded": False,
        "proxy_arguments_preserved": False,
        "exact_callback_bypass_preserved": False,
        "pre_and_post_launch_checks_passed": False,
        "fixture_loaded": False,
        "callback_received": False,
        "browser_exit_matches_expected": False,
        "wrong_loopback_port_not_reached": False,
        "owned_processes_stopped": False,
    }
    report = {
        "ok": False,
        "checks": checks,
        "scope": {
            "real_broker_and_browser_hook": True,
            "real_chrome_headless": True,
            "checker": "surge_cc.cli.oauth_checks before and after launch",
            "external_probe": "api.ipify.org, HTTPS JSON",
            "callback": "synthetic HTTP callback on one exact owned loopback port",
            "wrong_port": "second local listener must receive no request",
            "actual_provider_login_or_token_exchange": False,
            "surge_configuration_changed": False,
            "personal_browser_or_profiles_changed": False,
        },
    }
    server = None
    browsers = []
    successful_checks = 0
    phase = "load_config"
    try:
        config = core.load_config(config_path)
        from surge_cc.cli import oauth_checks

        def checker(value: dict) -> dict:
            nonlocal successful_checks
            checked = oauth_checks(value)
            if isinstance(checked, dict) and checked.get("ok") is True:
                successful_checks += 1
            return checked

        with tempfile.TemporaryDirectory(prefix="surge-cc-oauth-smoke-",
                                         dir="/private/tmp") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            private_config = root / "config.json"
            config = dict(config, workspace="smoke")
            core.save_config(private_config, config)
            phase = "start_fixture"
            server = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--serve-fixture", str(root)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True,
            )
            try:
                ready = read_when_ready(root / "ready.json", server, 10)
                callback_port = ready["callback_port"]
                verifier = secrets.token_urlsafe(48)
                challenge = base64.urlsafe_b64encode(
                    hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                # Synthetic data only. Never request this official URL.
                authorization_url = "https://claude.ai/oauth/authorize?" + urlencode({
                    "response_type": "code",
                    "client_id": "surge-cc-synthetic-smoke",
                    "redirect_uri": f"http://localhost:{callback_port}/callback",
                    "state": secrets.token_urlsafe(32),
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                })
                authorization = oauth.validate_authorization_url(authorization_url)
                checks["callback_owner_verified"] = oauth.callback_owned_by(server, callback_port)
                if not checks["callback_owner_verified"]:
                    raise RuntimeError("callback_owner_unverified")

                def fixture_browser(args, **kwargs):
                    args = list(args)
                    if args[-1] != authorization.url:
                        raise RuntimeError("unexpected_browser_destination")
                    checks["proxy_arguments_preserved"] = (
                        f"--proxy-server={config['proxy_url']}" in args)
                    checks["exact_callback_bypass_preserved"] = (
                        f"--proxy-bypass-list=<-loopback>;http://localhost:{callback_port};http://127.0.0.1:{callback_port}"
                        in args)
                    if not (checks["proxy_arguments_preserved"]
                            and checks["exact_callback_bypass_preserved"]):
                        raise RuntimeError("unexpected_browser_arguments")
                    # Deliberately preserve every real proxy and bypass option.
                    args[-1] = f"http://localhost:{callback_port}/fixture"
                    args.insert(-1, "--headless=new")
                    browser = subprocess.Popen(args, **kwargs)
                    browsers.append(browser)
                    return browser

                phase = "broker_and_browser"
                with oauth.OAuthSession(config, private_config, checker=checker,
                                        popen=fixture_browser) as session:
                    session.set_child(server)
                    env = core.proxy_env(config["proxy_url"])
                    env["BROWSER"] = str(session.browser_hook)
                    # Exercise the actual generated executable, never OS open().
                    hook = subprocess.run(
                        [env["BROWSER"], authorization.url], env=env,
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=290, check=False,
                    )
                    checks["browser_hook_succeeded"] = hook.returncode == 0
                    checks["pre_and_post_launch_checks_passed"] = successful_checks >= 2
                    if not checks["browser_hook_succeeded"]:
                        raise RuntimeError("browser_hook_blocked")
                    phase = "browser_network_and_callback"
                    deadline = time.monotonic() + 40
                    observed = {}
                    while time.monotonic() < deadline:
                        observed = read_when_ready(root / "result.json", server, 1)
                        if observed.get("callback_received") is True:
                            break
                        if session.browser is None or session.browser.poll() is not None:
                            raise RuntimeError("browser_stopped")
                        time.sleep(0.2)
                    checks["fixture_loaded"] = observed.get("fixture_loaded") is True
                    checks["callback_received"] = observed.get("callback_received") is True
                    checks["browser_exit_matches_expected"] = (
                        observed.get("exit_request_succeeded") is True
                        and observed.get("exit_matches_expected") is True)
                    checks["wrong_loopback_port_not_reached"] = (
                        observed.get("wrong_port_attempted") is True
                        and observed.get("wrong_port_received_request") is False)
            finally:
                # Only handles created here; never search or stop processes by name.
                for browser in browsers:
                    stop_owned_child(browser)
                stop_owned_child(server)
    except Exception:
        # Exceptions may embed a URL or local config details; emit only the phase.
        report["failure_phase"] = phase
    finally:
        stopped = True
        for child in [*browsers, server]:
            if child is not None:
                try:
                    stop_owned_child(child)
                    stopped = stopped and child.poll() is not None
                except Exception:
                    stopped = False
        checks["owned_processes_stopped"] = stopped
    report["ok"] = all(checks.values())
    return report, 0 if report["ok"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=core.DEFAULT_CONFIG)
    parser.add_argument("--serve-fixture", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.serve_fixture is not None:
        return serve_fixture(args.serve_fixture)
    report, code = smoke(args.config)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())

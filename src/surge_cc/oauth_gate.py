"""No-login verification through the actual dedicated HTTP proxy entrance."""
from __future__ import annotations

import ipaddress
import json
import subprocess

from .core import Blocked, proxy_env, validate_config
from .containment import _endpoint


def verify_proxy_exit(config: dict, run=subprocess.run) -> None:
    config = validate_config(config)
    _endpoint(config)  # Dedicated loopback-only entry, not the general 6152/6153.
    try:
        response = run(
            ["/usr/bin/curl", "--disable", "--silent", "--show-error", "--fail",
             "--proxy", config["proxy_url"], "--noproxy", "",
             "--proto", "=https", "--connect-timeout", "5", "--max-time", "15",
             "--max-filesize", "1024", "--max-redirs", "0",
             "--write-out", "\n%{http_code}",
             "https://api.ipify.org?format=json"],
            capture_output=True, text=True, timeout=20,
            env=proxy_env(config["proxy_url"]))
        if response.returncode or not isinstance(response.stdout, str) or len(response.stdout) > 2048:
            raise ValueError()
        payload, status = response.stdout.rsplit("\n", 1)
        if status != "200":
            raise ValueError()
        value = json.loads(payload)
        if (not isinstance(value, dict) or set(value) != {"ip"} or
                ipaddress.ip_address(value["ip"]) != ipaddress.ip_address(config["expected_ip"])):
            raise ValueError()
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, KeyError):
        raise Blocked("专用入口的实际出口检查失败，授权页面未放行；不会使用其他节点或普通浏览器。") from None

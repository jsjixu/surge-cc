"""Validation for ordinary browser links; never grants an OAuth callback bypass."""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import unquote, urlsplit

from . import core


MAX_URL_BYTES = 16384


def validate_url(value: str) -> str:
    """Return the original HTTP(S) URL or a deliberately URL-free error.

    Keep query strings in memory only: they can contain private document IDs or
    tokens. Do not include the rejected value in exceptions or diagnostics.
    """
    try:
        if (not isinstance(value, str) or not value
                or len(value.encode("utf-8")) > MAX_URL_BYTES
                or any(c.isspace() or unicodedata.category(c) == "Cc" for c in value)
                or "\\" in value or re.search(r"%(?![0-9A-Fa-f]{2})", value)):
            raise ValueError
        decoded = unquote(value, errors="strict")
        if "\\" in decoded or any(unicodedata.category(c) == "Cc" for c in decoded):
            raise ValueError
        parsed = urlsplit(value)
        if (parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc
                or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or "@" in parsed.netloc
                or "%" in parsed.netloc or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
            raise ValueError
        hostname = parsed.hostname
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            hostname = hostname.rstrip(".").encode("idna").decode("ascii")
            if (len(hostname) > 253 or not hostname
                    or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                           for part in hostname.split("."))):
                raise ValueError
        return value
    except (ValueError, TypeError, UnicodeError):
        raise core.Blocked("网页地址无效；只接受不含账号密码或控制字符的 HTTP/HTTPS 链接。") from None

"""Explicit parent-launcher access to one current-user setup-token credential.

Only the trusted launcher may call read_token(), before entering the child
sandbox. This module never persists the secret or reads inherited credentials.
The caller must put its return value only in the intended Claude child process
environment, and must not log that environment or fall back after an error.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

from .core import Blocked
from . import isolated_preferences as safe


MARKER = "keychain-auth.json"
SERVICE = "claude-code-oauth-token"
TIMEOUT = 15
MAX_TOKEN = 16384
_ERROR = "钥匙串 Token 配置或读取失败，已阻止启动；不会改用其他凭据或自动打开网页登录。"


def _identity():
    identity = pwd.getpwuid(os.getuid())
    if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", identity.pw_name)
            or not Path(identity.pw_dir).is_absolute()
            or any(ord(char) < 32 for char in identity.pw_dir)):
        raise ValueError("invalid current user identity")
    return identity


def validate(config) -> dict | None:
    """Validate an in-memory credential reference; never accept secret fields."""
    try:
        if config is None:
            return None
        if type(config) is not dict or type(config.get("enabled")) is not bool:
            raise ValueError("invalid opt-in")
        if "schema" in config:
            if type(config["schema"]) is not int or config["schema"] != 2:
                raise ValueError("invalid workspace reference schema")
            workspace = _workspace(config.get("workspace"))
            if config == {"schema": 2, "workspace": workspace, "enabled": False}:
                return None
            fields = {"schema", "workspace", "enabled", "service", "account"}
            if config.get("legacy") is True:
                fields.add("legacy")
                if config.get("service") != SERVICE or config.get("account") != _identity().pw_name:
                    raise ValueError("invalid legacy reference")
            elif (config.get("service") != WORKSPACE_SERVICE
                    or not isinstance(config.get("account"), str)
                    or not re.fullmatch(re.escape(_identity().pw_name) + r"\.surge-cc\.[a-f0-9]{64}", config["account"])):
                raise ValueError("invalid workspace item")
            if set(config) != fields or config["enabled"] is not True:
                raise ValueError("invalid workspace reference fields")
            return dict(config)
        if config == {"enabled": False}:
            return None
        if (set(config) != {"enabled", "service", "account"}
                or config["service"] != SERVICE
                or config["account"] != _identity().pw_name):
            raise ValueError("unapproved keychain item")
        if not config["enabled"]:
            return None
        return {"enabled": True, "service": SERVICE, "account": config["account"]}
    except Exception:
        pass
    raise Blocked(_ERROR)


def _load_legacy(config_path) -> dict | None:
    """Read the private opt-in marker adjacent to the launcher's config file.

    No file or directory is created. A missing terminal directory or marker is
    disabled; an existing unsafe or corrupt entry blocks instead of disabling.
    """
    descriptors = []
    try:
        config = Path(config_path)
        if (not config.is_absolute() or ".." in config.parts
                or any(ord(char) < 32 for char in str(config))):
            raise ValueError("invalid config path")
        parent = config.parent
        if parent.resolve() != parent:
            raise ValueError("aliased config directory")
        try:
            root = safe._open_dir(parent)
        except FileNotFoundError:
            return None
        descriptors.append(root)
        try:
            terminal = safe._open_dir("terminal", parent=root, private=True)
        except FileNotFoundError:
            return None
        descriptors.append(terminal)
        if stat.S_IMODE(os.fstat(terminal).st_mode) != 0o700:
            raise ValueError("unexpected terminal directory permissions")
        data, fingerprint = safe._read(terminal, MARKER, private=True, limit=4096)
        if fingerprint is None:
            return None
        if stat.S_IMODE(fingerprint[5]) != 0o600:
            raise ValueError("unexpected marker permissions")
        return validate(data)
    except Exception:
        pass
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    raise Blocked(_ERROR)


def _decode_token(output):
    if not isinstance(output, bytes) or len(output) > MAX_TOKEN + 2:
        raise ValueError("invalid keychain response")
    if output.endswith(b"\r\n"):
        output = output[:-2]
    elif output.endswith(b"\n"):
        output = output[:-1]
    token = output.decode("ascii")
    prefix = "sk-ant-oat01-"
    if (not token.startswith(prefix) or not len(prefix) + 32 <= len(token) <= MAX_TOKEN
            or any(not 33 <= ord(char) <= 126 for char in token)):
        raise ValueError("invalid setup token format")
    return token


def read_token(config) -> str | None:
    """Return the approved token in memory only, or None when disabled.

    Missing, denied, timed-out and malformed keychain responses all block with
    the same non-sensitive error. The host environment is never inherited.
    """
    normalized = validate(config)
    if normalized is None:
        return None
    try:
        identity = _identity()
        result = subprocess.run(
            ["/usr/bin/security", "find-generic-password", "-s", normalized["service"],
             "-a", normalized["account"], "-w"],
            shell=False, capture_output=True, stdin=subprocess.DEVNULL,
            timeout=TIMEOUT, check=False, close_fds=True, cwd="/",
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": identity.pw_dir,
                 "USER": identity.pw_name, "LOGNAME": identity.pw_name,
                 "LANG": "C", "LC_ALL": "C"},
        )
        if result.returncode != 0:
            raise ValueError("keychain item unavailable")
        return _decode_token(result.stdout)
    except Exception:
        pass
    raise Blocked(_ERROR)


WORKSPACE_SERVICE = "surge-cc.workspace-oauth-token"
MIGRATION = "keychain-auth-migration.json"


def _workspace(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,32}", value) is None:
        raise ValueError("invalid workspace")
    return value


def _config_root(config_path):
    path = Path(config_path)
    if (not path.is_absolute() or ".." in path.parts or path.parent.resolve() != path.parent
            or any(ord(c) < 32 for c in str(path))):
        raise ValueError("invalid configuration root")
    return path.parent


@contextmanager
def _directory(config_path, parts=(), *, create=False):
    """Pin owned, private account state without following directory aliases."""
    descriptors = []
    try:
        root = _config_root(config_path)
        current = safe._open_dir(root)
        descriptors.append(current)
        for part in parts:
            if not isinstance(part, str) or part in (".", "..") or "/" in part:
                raise ValueError("invalid state component")
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                except FileExistsError:
                    pass
            current = safe._open_dir(part, parent=current, private=True)
            descriptors.append(current)
            if stat.S_IMODE(os.fstat(current).st_mode) != 0o700:
                raise ValueError("account directory must be private")
        yield current
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _read_marker(directory, name):
    data, state = safe._read(directory, name, private=True, limit=4096)
    if state is not None and stat.S_IMODE(state[5]) != 0o600:
        raise ValueError("account marker must be private")
    return data, state


def _selected(config_path, workspace):
    if workspace is not None:
        return _workspace(workspace)
    with _directory(config_path) as root:
        data, state = safe._read(root, Path(config_path).name, private=True, limit=1024 * 1024)
        if state is None:
            raise ValueError("active configuration unavailable")
        return _workspace(data.get("workspace"))


def _owner(config_path):
    try:
        with _directory(config_path, ("terminal",)) as root:
            data, state = _read_marker(root, MIGRATION)
    except FileNotFoundError:
        return None
    if state is None:
        return None
    required = {"schema", "workspace", "legacy_marker_present"}
    if (set(data) not in (required, required | {"native_storage"})
            or type(data.get("schema")) is not int or data["schema"] != 1
            or type(data.get("legacy_marker_present")) is not bool
            or ("native_storage" in data and data["native_storage"] not in ("Auth", "Claude"))):
        raise ValueError("invalid migration ownership")
    _workspace(data.get("workspace"))
    return data


def legacy_workspace(config_path):
    """Read the once-captured owner of pre-workspace state; never guess A/B."""
    try:
        owner = _owner(config_path)
        return owner["workspace"] if owner else None
    except Exception:
        pass
    raise Blocked(_ERROR)


def _account(config_path, workspace):
    root = _config_root(config_path)
    digest = hashlib.sha256(os.fsencode(root) + b"\0" + _workspace(workspace).encode()).hexdigest()
    return _identity().pw_name + ".surge-cc." + digest


def _load_marker(config_path, workspace):
    try:
        with _directory(config_path, ("workspaces", workspace)) as folder:
            data, state = _read_marker(folder, MARKER)
    except FileNotFoundError:
        return None, False
    if state is None:
        return None, False
    if data.get("workspace") != workspace or data.get("schema") != 2:
        raise ValueError("reference belongs to a different workspace")
    normalized = validate(data)
    if normalized is not None:
        if normalized.get("legacy"):
            owner = _owner(config_path)
            if not owner or owner["workspace"] != workspace or not owner["legacy_marker_present"]:
                raise ValueError("legacy item is not owned by this workspace")
        elif normalized["account"] != _account(config_path, workspace):
            raise ValueError("reference belongs to a different installation")
    return normalized, True


def load(config_path, workspace=None) -> dict | None:
    """Load only this account's explicit reference. Never consult legacy state.

    A missing reference is OAuth mode, not permission to reuse any other
    workspace or the former machine-wide keychain marker. Migration is explicit.
    """
    try:
        return _load_marker(config_path, _selected(config_path, workspace))[0]
    except Exception:
        pass
    raise Blocked(_ERROR)


def migrate_legacy(config_path, workspace) -> bool:
    """Bind the legacy reference once to the active account, without reading it.

    Call under the application's account-switch lock, before changing the active
    workspace. The old file and Keychain item are retained unchanged for rollback.
    A partial migration retries for its recorded owner, never the new selection.
    """
    try:
        workspace = _workspace(workspace)
        with _directory(config_path, ("terminal",), create=True) as terminal:
            owner = _owner(config_path)
            if owner is None:
                legacy = _load_legacy(config_path)
                _, legacy_state = _read_marker(terminal, MARKER)
                owner = {"schema": 1, "workspace": workspace,
                         "legacy_marker_present": legacy_state is not None,
                         # Native OAuth previously hashed CLAUDE_CONFIG_DIR.
                         # Preserve that namespace by reference, never by copy.
                         "native_storage": "Auth" if legacy is not None else "Claude"}
                safe._write(terminal, MIGRATION, owner, None)
            else:
                workspace = owner["workspace"]
                # A complete migration does not depend on the old marker ever
                # again. Keep it only as an unchanged rollback artifact.
                _, complete = _load_marker(config_path, workspace)
                if complete:
                    return False
                legacy = _load_legacy(config_path) if owner["legacy_marker_present"] else None
            with _directory(config_path, ("workspaces", workspace), create=True) as account:
                _, existing = _read_marker(account, MARKER)
                if existing is not None:
                    _load_marker(config_path, workspace)
                    return False
                marker = {"schema": 2, "workspace": workspace, "enabled": legacy is not None}
                if legacy is not None:
                    marker.update(service=legacy["service"], account=legacy["account"], legacy=True)
                safe._write(account, MARKER, marker, None)
                return True
    except Exception:
        pass
    raise Blocked(_ERROR)


def configure_oauth(config_path, workspace) -> dict:
    """Select this workspace's native OAuth store; never delete saved tokens."""
    try:
        workspace = _workspace(workspace)
        with _directory(config_path, ("workspaces", workspace), create=True) as account:
            _, state = _read_marker(account, MARKER)
            safe._write(account, MARKER, {"schema": 2, "workspace": workspace, "enabled": False}, state)
        return status(config_path, workspace)
    except Exception:
        pass
    raise Blocked(_ERROR)


def status(config_path, workspace=None) -> dict:
    """Return mode and configuration presence only; never probe/read secrets."""
    try:
        workspace = _selected(config_path, workspace)
        reference, configured = _load_marker(config_path, workspace)
        return {"workspace": workspace, "mode": "token" if reference else "oauth",
                "configured": configured, "legacy_reference": bool(reference and reference.get("legacy"))}
    except Exception:
        pass
    raise Blocked(_ERROR)


def workspace_storage(config_path, workspace, *, create=True) -> Path:
    """Stable native secure-storage scope shared by this account's CLI entries.

    Current native Claude uses this path for its plaintext fallback and as the
    hash input for its macOS Keychain service. No other account path is allowed.
    """
    try:
        workspace = _workspace(workspace)
        owner = _owner(config_path)
        storage = (owner.get("native_storage", "Auth")
                   if owner and owner["workspace"] == workspace else "Auth")
        parts = ("workspaces", workspace, "data", storage)
        path = _config_root(config_path).joinpath(*parts)
        with _directory(config_path, parts, create=create) as folder:
            native_lock = path.with_name(path.name + ".lock")
            if os.path.lexists(native_lock):
                info = native_lock.lstat()
                safe._check(info, directory=stat.S_ISDIR(info.st_mode), limit=4096)
            # Inspect file metadata without copying or surfacing native secrets.
            if os.path.lexists(path / ".credentials.json"):
                fd = os.open(".credentials.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=folder)
                try:
                    safe._check(os.fstat(fd), private=True, limit=1024 * 1024)
                finally:
                    os.close(fd)
        return path
    except Exception:
        pass
    raise Blocked(_ERROR)


def _write_native_token(service, account, token):
    """Use Security.framework directly: no secret argv, stdin protocol, or disk."""
    sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    ptr, uint, sint = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32
    sec.SecKeychainFindGenericPassword.argtypes = [ptr, uint, ctypes.c_char_p, uint, ctypes.c_char_p,
                                                  ctypes.POINTER(uint), ctypes.POINTER(ptr), ctypes.POINTER(ptr)]
    sec.SecKeychainFindGenericPassword.restype = sint
    sec.SecKeychainAddGenericPassword.argtypes = [ptr, uint, ctypes.c_char_p, uint, ctypes.c_char_p, uint, ptr, ctypes.POINTER(ptr)]
    sec.SecKeychainAddGenericPassword.restype = sint
    sec.SecKeychainItemModifyAttributesAndData.argtypes = [ptr, ptr, uint, ptr]
    sec.SecKeychainItemModifyAttributesAndData.restype = sint
    cf.CFRelease.argtypes = [ptr]
    cf.CFRelease.restype = None
    service_bytes, account_bytes = service.encode(), account.encode()
    token_bytes = token.encode("ascii")
    secret = ctypes.create_string_buffer(token_bytes)
    item = ptr()
    try:
        result = sec.SecKeychainFindGenericPassword(None, len(service_bytes), service_bytes,
            len(account_bytes), account_bytes, None, None, ctypes.byref(item))
        if result == 0:
            result = sec.SecKeychainItemModifyAttributesAndData(item, None, len(token_bytes), secret)
        elif result == -25300:  # errSecItemNotFound
            result = sec.SecKeychainAddGenericPassword(None, len(service_bytes), service_bytes,
                len(account_bytes), account_bytes, len(token_bytes), secret, None)
        if result != 0:
            raise ValueError("keychain update unavailable")
    finally:
        ctypes.memset(secret, 0, len(secret))
        if item.value:
            cf.CFRelease(item)


def store_token(config_path, workspace, token) -> dict:
    """Store a user-supplied setup token in only the named workspace's Keychain item.

    The caller must read the token from a protected UI/stdin, never an argv value,
    and hold the account mutation lock with managed sessions stopped.
    """
    try:
        workspace = _workspace(workspace)
        if not isinstance(token, str) or _decode_token(token.encode("ascii")) != token:
            raise ValueError("invalid setup token")
        reference = {"schema": 2, "workspace": workspace, "enabled": True,
                     "service": WORKSPACE_SERVICE, "account": _account(config_path, workspace)}
        with _directory(config_path, ("workspaces", workspace), create=True) as account:
            _, state = _read_marker(account, MARKER)
            _write_native_token(reference["service"], reference["account"], token)
            safe._write(account, MARKER, reference, state)
        return status(config_path, workspace)
    except Exception:
        pass
    raise Blocked(_ERROR)


# Public names used by the launch and UI command layers.
auth_directory = workspace_storage
set_oauth = configure_oauth

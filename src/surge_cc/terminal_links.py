"""Opt-in synchronous zsh web opens for verified Orca terminal ancestry.

This is a shell entry point, not interception of execve or a security boundary
against the same user deliberately invoking ``command /usr/bin/open``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile

from . import core, link_router, shortcuts, terminal
from .web_urls import validate_url


MAX_REQUEST_BYTES = 65536
BEGIN = b"# >>> Surge CC Orca web links v1 >>>"
END = b"# <<< Surge CC Orca web links v1 <<<"
_FIELDS = {"schema", "router_config", "zshrc", "block", "original_exists", "original_mode", "original_sha256"}


def _result(action, message, *, code=0, **extra):
    return {"ok": code == 0, "action": action, "message": message, "exit_code": code, **extra}


def _paths(router_config):
    router_config = shortcuts.absolute_path(router_config)
    data = link_router.load(router_config)
    folder = Path(data["config"]).parent / "terminal-links"
    return router_config, data, folder, Path.home() / ".zshrc"


def _read(path, *, missing=False, private=False, maximum=1024 * 1024):
    shortcuts.no_links(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        if missing:
            return None
        raise
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_mode & (0o077 if private else 0o022)
                or before.st_size > maximum):
            raise core.Blocked("终端网页入口文件的所有者、权限或类型异常，未修改。")
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        raw = bytes(raw)
        after = os.fstat(fd)
        current = path.lstat()
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (len(raw) != before.st_size or len(raw) > maximum or any(getattr(before, k) != getattr(item, k)
                                    for item in (after, current) for k in fields)):
            raise core.Blocked("终端配置读取期间发生变化，未修改。")
        return raw, before
    finally:
        os.close(fd)


def _same(snapshot, other):
    if snapshot is None or other is None:
        return snapshot is other
    raw, info = snapshot
    value, current = other
    return raw == value and all(getattr(info, k) == getattr(current, k) for k in (
        "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_mode", "st_uid", "st_nlink"))


def _replace(path, original, raw, mode):
    """Preserve and validate the displaced file before accepting a replacement."""
    shortcuts.no_links(path)
    if not _same(original, _read(path, missing=True)):
        raise core.Blocked("终端配置已经变化，请重新操作；未覆盖新内容。")
    fd, name = tempfile.mkstemp(prefix=".surge-cc-web-", dir=path.parent)
    staged = Path(name)
    cleanup = True
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if original is None:
            os.link(staged, path)  # No-replace publication; never overwrite a newly-created rc.
        else:
            replacement = _read(staged)
            terminal._exchange(staged, path)
            cleanup = False
            try:
                if not _same(original, _read(staged)):
                    raise core.Blocked("终端配置同时被修改。")
            except Exception:
                # Never delete a displaced file after failed verification.
                # Restore only while our replacement remains unchanged; retain
                # the staging path even if rollback itself fails.
                if _same(replacement, _read(path)):
                    terminal._exchange(staged, path)
                raise core.Blocked("终端配置同时被修改，已保留恢复文件，未接受覆盖；请检查后重试。") from None
            cleanup = True
    finally:
        if cleanup and os.path.lexists(staged):
            staged.unlink()


def _script(data, router_config):
    q = shlex.quote
    backend = str(Path(data["app"]) / "Contents/Resources/scripts/surge-cc")
    command = " ".join(q(v) for v in (data["python"], backend, "--config", data["config"], "links"))
    options = "--router-config " + q(str(router_config))
    return f'''# Surge CC managed Orca web entry; source only in interactive zsh.
[[ -n ${{ZSH_VERSION-}} && -o interactive ]] || return 0
# Controlled Claude shells keep their session-specific BROWSER and PATH.
if [[ -n ${{SURGE_CC_TERMINAL_ENTRY-}} || ${{BROWSER-}} == /private/tmp/surge-cc-oauth-*/browser ]]; then
  return 0
fi
if (( $+functions[open] || $+functions[/usr/bin/open] || $+functions[_surge_cc_orca_open_v1] || $+aliases[open] || $+aliases[/usr/bin/open] )); then
  [[ ${{_SURGE_CC_ORCA_WEB_HOOK-}} == {q(str(router_config))} ]] || builtin print -u2 -- 'Surge CC: an existing open function or alias was kept; Orca web hook was not installed.'
  return 0
fi
{command} shell-eligible {options} >/dev/null 2>/dev/null
case $? in
  0) ;;
  3) return 0 ;;
  *) builtin print -u2 -- 'Surge CC: could not verify this terminal; web hook is inactive. Check the link integration before opening webpages.'; return 78 ;;
esac
function '_surge_cc_orca_open_v1'() {{
  emulate -L zsh
  # A newly inherited Claude broker takes priority over the generic A entry.
  if [[ -n ${{SURGE_CC_TERMINAL_ENTRY-}} || ${{BROWSER-}} == /private/tmp/surge-cc-oauth-*/browser ]]; then
    if [[ ${{BROWSER-}} == /private/tmp/surge-cc-oauth-*/browser && -x ${{BROWSER:h}}/open && $(builtin whence -p open) == ${{BROWSER:h}}/open ]]; then
      command "${{BROWSER:h}}/open" "$@"
      return $?
    fi
    builtin print -u2 -- 'Surge CC: use this Claude session’s private browser opener; generic workspace A opening was blocked.'
    return 78
  fi
  local _surge_web=0
  if (( $# == 1 )); then
    [[ $1 == [hH][tT][tT][pP]://* || $1 == [hH][tT][tT][pP][sS]://* ]] && _surge_web=1
  elif (( $# == 2 )) && [[ $1 == -- ]]; then
    [[ $2 == [hH][tT][tT][pP]://* || $2 == [hH][tT][tT][pP][sS]://* ]] && _surge_web=1
  fi
  if (( ! _surge_web )); then
    local _surge_arg _surge_has_web=0 _surge_explicit=0
    for _surge_arg in "$@"; do
      [[ $_surge_arg == [hH][tT][tT][pP]://* || $_surge_arg == [hH][tT][tT][pP][sS]://* ]] && _surge_has_web=1
      [[ $_surge_arg == -a || $_surge_arg == -b ]] && _surge_explicit=1
    done
    if (( _surge_has_web && ! _surge_explicit )); then
      builtin print -u2 -- 'Surge CC: open one HTTP(S) URL without other options; unsupported webpage arguments were blocked.'
      return 78
    fi
    command /usr/bin/open "$@"
    return $?
  fi
  if [[ ! -x {q(data['python'])} || ! -f {q(backend)} || -L {q(backend)} || ! -f {q(str(router_config))} || -L {q(str(router_config))} ]]; then
    builtin print -u2 -- 'Surge CC: browser integration unavailable; webpage opening was blocked.'
    return 78
  fi
  builtin printf '%s\\0' "$@" | {command} shell-open {options}
  return ${{pipestatus[-1]}}
}}
function 'open'() {{ _surge_cc_orca_open_v1 "$@"; }}
function '/usr/bin/open'() {{ _surge_cc_orca_open_v1 "$@"; }}
typeset -g _SURGE_CC_ORCA_WEB_HOOK={q(str(router_config))}
'''.encode()


def _block(script, separator=b""):
    return separator + BEGIN + b"\n" + ("source " + shlex.quote(str(script)) + "\n").encode() + END + b"\n"


def _manifest(folder, router_config, rc):
    raw, _ = _read(folder / "manifest.json", private=True, maximum=32768)
    data = json.loads(raw)
    if (not isinstance(data, dict) or set(data) != _FIELDS or type(data["schema"]) is not int or data["schema"] != 1
            or data["router_config"] != str(router_config) or data["zshrc"] != str(rc)
            or type(data["original_exists"]) is not bool or type(data["original_mode"]) is not int
            or data["original_mode"] & ~0o777 or data["original_mode"] & 0o022):
        raise core.Blocked("终端网页入口安装记录无效，未修改配置。")
    block = base64.b64decode(data["block"], validate=True)
    if block not in (_block(folder / "open.zsh"), _block(folder / "open.zsh", b"\n")):
        raise core.Blocked("终端网页入口标记内容异常，未修改配置。")
    backup, _ = _read(folder / "zshrc.original", private=True)
    if hashlib.sha256(backup).hexdigest() != data["original_sha256"]:
        raise core.Blocked("终端配置备份已变化，未修改配置。")
    return data, block


def install(router_config):
    router_config, data, folder, rc = _paths(router_config)
    shortcuts.no_links(rc.parent)
    home = rc.parent.stat()
    if not stat.S_ISDIR(home.st_mode) or home.st_uid != os.getuid() or home.st_mode & 0o022:
        raise core.Blocked("用户目录的所有者或权限异常，未修改终端配置。")
    with terminal._lock(folder):
        old = _read(rc, missing=True)
        original = old[0] if old else b""
        if (folder / "manifest.json").exists():
            _, block = _manifest(folder, router_config, rc)
            if original.count(block) != 1 or original.count(BEGIN) != 1 or original.count(END) != 1:
                raise core.Blocked("现有终端标记已变化，请先检查；未重复安装或覆盖。")
            script = _read(folder / "open.zsh", private=True)[0]
            if script != _script(data, router_config):
                raise core.Blocked("终端网页脚本已变化，请先移除后重新安装。")
            return _result("installed", "终端网页入口已经安装，无需重复修改。", installed=True, changed=False)
        if BEGIN in original or END in original:
            raise core.Blocked("已有不完整的终端网页标记，未覆盖。")
        for leaf in ("zshrc.original", "open.zsh"):
            _read(folder / leaf, missing=True, private=True)
        # Exact original bytes are kept privately, including a missing trailing newline.
        block = _block(folder / "open.zsh", b"\n" if original and not original.endswith(b"\n") else b"")
        mode = stat.S_IMODE(old[1].st_mode) if old else 0o600
        terminal._write_private(folder / "zshrc.original", original)
        terminal._write_private(folder / "open.zsh", _script(data, router_config))
        manifest = {"schema": 1, "router_config": str(router_config), "zshrc": str(rc),
                    "block": base64.b64encode(block).decode(), "original_exists": old is not None,
                    "original_mode": mode, "original_sha256": hashlib.sha256(original).hexdigest()}
        terminal._write_private(folder / "manifest.json", json.dumps(manifest).encode())
        try:
            _replace(rc, old, original + block, mode)
        except Exception:
            (folder / "manifest.json").unlink()
            raise
    return _result("installed", "终端网页入口已安装；请新建 Orca 终端以启用，其他终端保持原行为。",
                   installed=True, changed=True)


def status(router_config):
    router_config, data, folder, rc = _paths(router_config)
    if not os.path.lexists(folder / "manifest.json"):
        return _result("absent", "尚未安装 Orca 终端网页入口。", installed=False)
    terminal._private_dir(folder)
    _, block = _manifest(folder, router_config, rc)
    value = _read(rc, missing=True)
    intact = (value is not None and value[0].count(block) == 1 and value[0].count(BEGIN) == 1
              and value[0].count(END) == 1 and _read(folder / "open.zsh", private=True)[0] == _script(data, router_config))
    return _result("installed" if intact else "damaged", "终端网页入口完整。" if intact else "终端网页入口已变化，请检查。",
                   code=0 if intact else 78, installed=True)


def remove(router_config):
    router_config, _, folder, rc = _paths(router_config)
    if not os.path.lexists(folder / "manifest.json"):
        return _result("absent", "终端网页入口未安装，无需移除。", installed=False, changed=False)
    with terminal._lock(folder):
        manifest, block = _manifest(folder, router_config, rc)
        current = _read(rc)
        if current[0].count(block) != 1 or current[0].count(BEGIN) != 1 or current[0].count(END) != 1:
            raise core.Blocked("终端标记已被修改，未删除其他配置；请检查后重试。")
        prefix, suffix = current[0].split(block, 1)
        separator = b"\n" if block.startswith(b"\n") and prefix and suffix and not prefix.endswith(b"\n") else b""
        cleaned = prefix + separator + suffix
        # Preserve edits made elsewhere since installation, rather than restore
        # the entire backup and silently discard newer user configuration.
        _replace(rc, current, cleaned, stat.S_IMODE(current[1].st_mode))
        # Keep an empty rc if none existed originally. Unlinking after the
        # atomic replacement could erase a concurrent new user edit.
        (folder / "manifest.json").unlink()
        # Keep the original backup. Open shells keep their in-memory function;
        # missing registration causes those protected web calls to fail closed.
        (folder / "open.zsh").unlink()
    return _result("removed", "终端网页入口已移除，其他配置和备份已保留；请新建终端使移除生效。",
                   installed=False, changed=True)


def _source():
    chain, seen, pid = [], set(), os.getppid()
    while pid > 1 and pid not in seen and len(chain) < 16:
        value = link_router._identity(pid)
        if value is None:
            break
        chain.append(value)
        seen.add(pid)
        pid = value["parent"]
    return {"chain": chain}


def _session_owned(data, source):
    # Never steal a controlled B session's browser into generic workspace A.
    return any(link_router._controlled_claude(data, item) for item in source["chain"])


def eligible(router_config):
    try:
        router_config, data, folder, rc = _paths(router_config)
        terminal._private_dir(folder)
        _manifest(folder, router_config, rc)
        source = _source()
        if _session_owned(data, source):
            return _result("session_owned", "保留 Claude 会话自己的网页入口。", code=3, eligible=False)
        if not link_router._source_matches(data, {"source": source}):
            if not source["chain"] or source["chain"][-1]["parent"] > 1:
                raise core.Blocked("无法完整核验终端来源。")
            return _result("unrelated", "当前不是已验证的 Orca 终端。", code=3, eligible=False)
        return _result("eligible", "已验证 Orca 终端。", eligible=True)
    except Exception:
        return _result("blocked", "终端网页入口无法验证，未启用。", code=78, eligible=False)


def _arguments(payload):
    if not isinstance(payload, bytes) or len(payload) > MAX_REQUEST_BYTES or not payload.endswith(b"\0"):
        raise core.Blocked("终端网页参数无效，未打开。")
    parts = payload[:-1].split(b"\0")
    if len(parts) > 128:
        raise core.Blocked("终端网页参数过多，未打开。")
    return [part.decode("utf-8", errors="strict") for part in parts]


def _system(args):
    result = subprocess.run(["/usr/bin/open", *args], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
    return _result("system", "已交给系统原有打开方式。", code=result.returncode if 0 <= result.returncode <= 255 else 78)


def dispatch(router_config, payload):
    """NUL-framed arguments only; never return or log URL/argument contents."""
    try:
        args = _arguments(payload)
        candidate = args[1:] if args[:1] == ["--"] else args
        web = len(candidate) == 1 and candidate[0].lower().startswith(("http://", "https://"))
        if not web:
            if any(arg.lower().startswith(("http://", "https://")) for arg in args) and not any(
                    arg in ("-a", "-b") for arg in args):
                raise core.Blocked("请每次打开一个 HTTP(S) 链接；含其他参数或多个网页的调用已阻止。")
            return _system(args)
        url = validate_url(candidate[0])
        router_config, data, folder, rc = _paths(router_config)
        terminal._private_dir(folder)
        _manifest(folder, router_config, rc)
        source = _source()
        if _session_owned(data, source):
            raise core.Blocked("请使用当前 Claude 会话自己的网页入口；未切换到工作区 A。")
        if not link_router._source_matches(data, {"source": source}):
            if not source["chain"] or source["chain"][-1]["parent"] > 1:
                raise core.Blocked("无法完整核验终端来源，未改用个人浏览器。")
            return _system(args)
        if core.load_config(Path(data["config"])).get("workspace", "A") != "A":
            raise core.Blocked("当前为工作区 B；请在 Surge CC 中确认切换到 A 后重试，未结束 B 会话。")
        result = shortcuts.open_url(Path(data["config"]), "A", url,
                                    Path(data["app"]) / "Contents/Resources/SurgeCCShortcut")
        if result.get("action") not in ("focus", "opened"):
            raise core.Blocked("专用浏览器未能打开；请在 Surge CC 中检查，未改用个人浏览器。")
        return _result("opened", "已在当前 A 专用浏览器打开。")
    except core.Blocked as exc:
        return _result("blocked", str(exc), code=78)
    except Exception:
        return _result("blocked", "终端网页入口无法验证，未打开或更换浏览器。", code=78)

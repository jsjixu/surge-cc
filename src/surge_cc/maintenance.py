"""Reviewable native Claude maintenance without exposing an unguarded launcher.

The official macOS binary is authenticated by Apple's code-signature trust
anchor and Anthropic PBC's Developer ID team and code identifier. Downloads additionally
match the official HTTPS manifest checksum. No installer script is executed.
Account/session leases and a persistent terminal barrier cover commit/recovery;
A/B credential stores, browser profiles, Surge profiles and personal apps are
never rewritten here.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from . import terminal, workspaces
from .core import Blocked, load_config, now, proxy_env
from .sessions import assert_no_stop_failures

RELEASES = "https://downloads.claude.ai/claude-code-releases"
OPERATIONS = {"repair-terminal", "update-claude"}
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
PLAN_TTL = 1800
MAX_BINARY = 512 * 1024 * 1024
# Pin Anthropic's Apple Developer ID team and signed code identifier, plus
# the Developer ID CA/application certificate extensions. The certificate's
# organization name is not reliably the application's displayed publisher.
PUBLISHER_REQUIREMENT = ('anchor apple generic and identifier "com.anthropic.claude-code" '
                         'and certificate leaf[subject.OU] = "Q6L2SF6YDW" '
                         'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
                         'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists')
MACHO = {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _hash_file(path: Path):
    terminal._plain_path(path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        terminal._regular(path, executable=True)
        if not 0 < before.st_size <= MAX_BINARY:
            raise Blocked("Claude 原生程序大小异常，未接受此文件。")
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if terminal._update_signature(before) != terminal._update_signature(after) or terminal._update_signature(path.stat()) != terminal._update_signature(before):
        raise Blocked("核验期间 Claude 原生程序发生变化，请重新检查。")
    return {"identity": list(terminal._update_signature(before)), "sha256": digest.hexdigest()}


def _snapshot(path: Path):
    terminal._plain_path(path, leaf=False)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"kind": "missing"}
    if info.st_uid != os.getuid():
        raise Blocked("维护文件不属于当前用户，未修改。")
    identity = list(terminal._update_signature(info))
    if stat.S_ISLNK(info.st_mode):
        return {"kind": "link", "identity": identity, "value": os.readlink(path)}
    if stat.S_ISREG(info.st_mode):
        signature, body = terminal._update_snapshot(path)
        return {"kind": "file", "identity": list(signature), "sha256": hashlib.sha256(body).hexdigest()}
    raise Blocked("维护文件类型异常，未修改。")


def _same(path, expected):
    try:
        return _snapshot(path) == expected
    except (OSError, ValueError, Blocked):
        return False


def _folders(config_path, state_dir):
    config_path = Path(config_path)
    terminal._plain_path(config_path)
    terminal._regular(config_path)
    folder = terminal._state_dir(state_dir)
    terminal._private_dir(folder)
    maintenance = config_path.parent / "maintenance"
    terminal._plain_path(maintenance)
    return config_path, folder, maintenance


def _registration(config_path, folder):
    data = terminal._read_registration(folder)
    if Path(data["config_path"]) != config_path:
        raise Blocked("终端接管记录属于另一份配置，未修改任何入口。")
    command = Path(data["command_path"])
    terminal._plain_path(command, leaf=False)
    info = command.parent.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise Blocked("Claude 命令目录权限不安全，不能维护。")
    for key in ("entrypoint", "config_path"):
        terminal._regular(Path(data[key]))
    terminal._regular(Path(data["python_executable"]), executable=True)
    if command.is_symlink():
        target = command.resolve(strict=True)
        if target.parent != _versions() or not VERSION.fullmatch(target.name):
            raise Blocked("Claude 命令被改为未知链接，未覆盖；请先核对终端入口。")
    elif command.exists():
        # Bound reads before comparing a potentially replaced command entry.
        terminal._update_snapshot(command)
        if command.read_bytes() != terminal._shim(data):
            raise Blocked("Claude 命令被改为未知程序，未覆盖；请先核对终端入口。")
        terminal._regular(command, executable=True)
    return data


def _versions():
    return Path.home() / ".local/share/claude/versions"


def _native_path(path):
    path = Path(path)
    terminal._plain_path(path)
    if path.parent != _versions() or not VERSION.fullmatch(path.name):
        raise Blocked("自动维护只支持官方原生 versions 目录；包管理器安装请使用对应更新工具。")
    info = path.parent.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise Blocked("Claude 原生版本目录不可被其他用户修改。")
    return path


def _verify_native(path: Path, *, expected_version=None):
    path = _native_path(path)
    if sys.platform != "darwin":
        raise Blocked("自动维护目前仅支持可验证 Apple 签名的 macOS 原生 Claude Code。")
    before = _hash_file(path)
    with path.open("rb") as stream:
        if stream.read(4) not in MACHO:
            raise Blocked("所选文件不是 macOS 原生程序，未执行或登记。")
    verified = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "-R=" + PUBLISHER_REQUIREMENT, str(path)],
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    if verified.returncode:
        raise Blocked("Claude 程序未通过 Apple 信任链及 Anthropic 发布者签名校验，未执行或登记。")
    if _hash_file(path) != before:
        raise Blocked("签名核验期间 Claude 程序发生变化，已停止。")
    # Version probes run only AFTER publisher verification, with an empty home
    # and environment. They neither receive account tokens nor load old settings.
    with tempfile.TemporaryDirectory(prefix="surge-cc-version-") as temporary:
        env = {"HOME": temporary, "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8",
               "CLAUDE_CONFIG_DIR": temporary, "CLAUDE_SECURESTORAGE_CONFIG_DIR": temporary,
               "DISABLE_UPDATES": "1", "DISABLE_AUTOUPDATER": "1",
               "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"}
        captured = subprocess.run([str(path), "--version"], cwd=temporary, env=env,
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    version = captured.stdout.strip()
    if captured.returncode or version != path.name + " (Claude Code)" or (expected_version and path.name != expected_version):
        raise Blocked("Claude 程序版本与官方版本目录不一致，未登记。")
    if _hash_file(path) != before:
        raise Blocked("版本核验期间 Claude 程序发生变化，已停止。")
    return {"path": str(path), "version": version, **before}


def _candidate(data):
    command = Path(data["command_path"])
    if command.is_symlink():
        return _native_path(command.resolve(strict=True))
    current = _native_path(Path(data["original_path"]))
    if current.exists():
        return current
    candidates = [p for p in current.parent.iterdir() if VERSION.fullmatch(p.name)]
    if not candidates:
        raise Blocked("原生 Claude 程序已缺失；请先在维护中心检查官方更新。")
    return sorted(candidates, key=lambda p: tuple(map(int, p.name.split("."))))[-1]


def _state(config_path, folder, data):
    result = {"config": _snapshot(config_path), "manifest": _snapshot(folder / "manifest.json"),
              "command": _snapshot(Path(data["command_path"])), "backup": _snapshot(folder / "original-link"),
              "barrier": _snapshot(folder / "maintenance-active.json"),
              "backend": _small_or_large(Path(data["entrypoint"])),
              "python": _hash_file(Path(data["python_executable"]))}
    original = Path(data["original_path"])
    result["original"] = _hash_file(original) if original.exists() else {"kind": "missing"}
    return result


def _small_or_large(path):
    # Backend source is not executable, unlike a native program.
    info = terminal._regular(path)
    if info.st_size > 2 * 1024 * 1024:
        raise Blocked("后端文件大小异常。")
    body = path.read_bytes()
    if terminal._update_signature(path.stat()) != terminal._update_signature(info):
        raise Blocked("后端文件在维护检查期间发生变化。")
    return {"identity": list(terminal._update_signature(info)), "sha256": hashlib.sha256(body).hexdigest()}


def _fetch(url, config, destination: Path, limit: int):
    # Fixed release origin, no shell, no curlrc, no redirect or direct fallback.
    if not url.startswith(RELEASES + "/") or any(c in url for c in "\r\n"):
        raise Blocked("维护下载地址不属于官方发布源。")
    result = subprocess.run(["/usr/bin/curl", "--disable", "--fail", "--silent", "--show-error",
                             "--proto", "=https", "--noproxy", "", "--proxy", config["proxy_url"],
                             "--connect-timeout", "15", "--max-time", "300", "--max-filesize", str(limit),
                             "--output", str(destination), url],
                            stdin=subprocess.DEVNULL, capture_output=True, env=proxy_env(config["proxy_url"], base={"PATH": "/usr/bin:/bin"}), timeout=310)
    if result.returncode or destination.stat().st_size > limit or not destination.stat().st_size:
        raise Blocked("官方更新下载失败，请检查当前 Surge 线路后重试；未更改终端入口。")


def _release(config):
    if sys.platform != "darwin" or platform.machine() not in {"arm64", "x86_64"}:
        raise Blocked("自动更新仅支持 Apple Silicon 或 Intel Mac 原生版本。")
    arch = "darwin-arm64" if platform.machine() == "arm64" else "darwin-x64"
    with tempfile.TemporaryDirectory(prefix="surge-cc-release-") as temporary:
        target = Path(temporary) / "latest"
        _fetch(RELEASES + "/latest", config, target, 128)
        version = target.read_text().strip()
        if not VERSION.fullmatch(version):
            raise Blocked("官方版本响应无法识别，未生成更新计划。")
        _fetch(RELEASES + "/" + version + "/manifest.json", config, target, 65536)
        try:
            manifest = json.loads(target.read_bytes())
            item = manifest["platforms"][arch]
            valid = (manifest["version"] == version and item["binary"] == "claude"
                     and isinstance(item["checksum"], str) and re.fullmatch(r"[a-f0-9]{64}", item["checksum"])
                     and type(item["size"]) is int and 0 < item["size"] <= MAX_BINARY)
        except (ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            raise Blocked("官方版本清单不完整，未生成更新计划。")
        return {"version": version, "platform": arch, "sha256": item["checksum"], "size": item["size"]}


def _entry(key, title, state, detail, action=None):
    value = {"id": key, "title": title, "status": state, "detail": detail}
    if action:
        value["action"] = action
    return value


def status(config_path: Path, *, state_dir=None):
    """Local inspection only; no network, native execution, or login data read."""
    entries = []
    try:
        config_path, folder, directory = _folders(config_path, state_dir)
        data = _registration(config_path, folder)
        current = terminal.status(state_dir=folder)
        entries.append(_entry("terminal", "Claude Code 终端接管", "pass" if current["ok"] else "fail",
                              current["summary"], None if current["ok"] else "repair-terminal"))
        entries.append(_entry("native-version", "已登记 Claude Code", "info", data["native_version"]))
        supported = Path(data["original_path"]).parent == _versions()
        entries.append(_entry("native-update", "Claude Code 官方更新", "info" if supported else "warn",
                              "检查官方最新版本，校验下载和签名后更新；保留账号与原始程序。" if supported else "此安装由其他工具管理，自动维护暂不支持。",
                              "update-claude" if supported else None))
        summary = "终端接管正常；可检查官方更新。" if current["ok"] else "发现可检查的终端维护问题。"
        value = {"schema": 1, "ok": current["ok"], "summary": summary, "entries": entries, "checked_at": now()}
        previous = directory / "last-result.json"
        if previous.exists():
            try:
                _, body = terminal._update_snapshot(previous)
                last = json.loads(body)
                if (last.get("schema") == 1 and last.get("ok") is True
                        and last.get("operation") in OPERATIONS
                        and isinstance(last.get("version"), str)
                        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+ \(Claude Code\)", last["version"])):
                    value["last_result"] = {"ok": True, "version": last["version"],
                                            "summary": "上次 Claude Code 维护已完成。"}
            except (OSError, ValueError, TypeError, AttributeError, Blocked):
                pass  # Advisory history cannot turn a valid launcher into a failure.
        return value
    except (OSError, ValueError, TypeError, KeyError, Blocked) as error:
        detail = str(error) if isinstance(error, Blocked) else "无法完整读取终端维护记录；请在配置向导检查安装。"
        return {"schema": 1, "ok": False, "summary": "终端维护需要处理。",
                "entries": [_entry("terminal", "Claude Code 终端接管", "fail", detail)], "checked_at": now()}


def _scope(config, target: Path):
    # Never silently expand the Surge process scope during binary maintenance.
    values = config.get("cli_process_paths", [])
    if str(target) not in values and str(target.parent) + "/" not in values:
        raise Blocked("新版本不在现有 CLI 旁路保护范围内；请先在配置向导设置官方 versions 目录保护，再更新。")


def plan(config_path: Path, operation="repair-terminal", *, state_dir=None):
    if operation not in OPERATIONS:
        raise Blocked("未知的 Claude Code 维护操作。")
    try:
        config_path, folder, directory = _folders(config_path, state_dir)
        config = load_config(config_path)
        data = _registration(config_path, folder)
        baseline = _state(config_path, folder, data)
        if operation == "repair-terminal":
            candidate = _verify_native(_candidate(data))
            target = Path(candidate["path"])
            release = None
            detail = "验证 Apple 信任链、Anthropic 发布者与原生版本；重新登记当前程序，并保持命令受控。"
        else:
            _native_path(Path(data["original_path"]))
            release = _release(config)
            old_version = tuple(map(int, data["native_version"].split(" ")[0].split(".")))
            if tuple(map(int, release["version"].split("."))) < old_version:
                raise Blocked("官方最新版本低于当前登记版本，维护中心不会自动降级。")
            target = _native_path(_versions() / release["version"])
            candidate = _verify_native(target) if target.exists() else None
            if candidate and candidate["sha256"] != release["sha256"]:
                raise Blocked("已有同名版本与官方清单校验值不同，未覆盖。")
            detail = "下载官方 " + release["version"] + "，核对 SHA256 和 Apple 发布者签名；原版本保留以便恢复。"
        _scope(config, target)
        if _state(config_path, folder, _registration(config_path, folder)) != baseline:
            raise Blocked("检查期间终端设置已变化，请重新生成维护计划。")
        actions = [{"id": operation, "title": "修复 Claude Code 接管" if operation == "repair-terminal" else "更新 Claude Code",
                    "detail": detail},
                   {"id": "maintenance-gate", "title": "保护维护过程", "detail": "有受控会话时停止维护；关闭新启动入口，验证后再原子提交。"},
                   {"id": "preserve", "title": "保留账号和网络设置", "detail": "不更改 A/B 登录、浏览器资料、个人 Chrome 或 Surge 代理配置。"}]
        intent = {"schema": 1, "operation": operation, "created": time.time(), "nonce": uuid.uuid4().hex,
                  "config_path": str(config_path), "state_dir": str(folder), "baseline": baseline,
                  "candidate": candidate, "target": str(target), "release": release, "actions": actions}
        identifier = hashlib.sha256(_json(intent)).hexdigest()
        terminal._private_dir(directory, create=True)
        plans = directory / "plans"
        terminal._private_dir(plans, create=True)
        terminal._write_private(plans / (identifier + ".json"), _json(intent))
        return {"schema": 1, "ok": True, "plan_id": identifier, "operation": operation, "actions": actions,
                "summary": "维护计划已生成，执行前会再次核对。", "target_version": target.name}
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, Blocked) as error:
        raise error if isinstance(error, Blocked) else Blocked("无法生成 Claude Code 维护计划，未改动原始入口。") from None


def _leases(stack, config_path):
    stack.enter_context(workspaces.account_lock(config_path, exclusive=True))
    root = config_path.parent / "workspaces"
    terminal._plain_path(root)
    if root.exists():
        for path in sorted(root.iterdir()):
            if path.is_symlink() or not path.is_dir():
                raise Blocked("工作区目录存在未知条目，未开始维护。")
            workspaces.name_ok(path.name)
            try:
                stack.enter_context(workspaces._lock(path, exclusive=True))
                assert_no_stop_failures(path)
            except Blocked:
                raise Blocked("仍有受控浏览器或 Claude Code 会话，请保存并关闭后重试维护；不会强行结束工作。") from None


def _replace_entries(entries):
    """Atomic per-file exchange, fail closed between manifest/link commits.

    Each displaced entry is retained until the transaction is validated. Rollback
    restores only our own replacement and never overwrites concurrent changes.
    """
    for entry in entries:
        target = entry["target"]
        if not _same(target, entry["old"]):
            raise Blocked("维护期间入口已变化，已停止并保留原文件。")
        if entry["old"]["kind"] == "missing":
            # link is an atomic no-clobber install. It never follows target.
            os.link(entry["staging"], target, follow_symlinks=False)
            entry["installed"] = True
            entry["new"] = _snapshot(target)
        else:
            terminal._exchange(entry["staging"], target)
            entry["swapped"] = True
            if not _same(entry["staging"], entry["old"]):
                raise Blocked("维护期间入口已变化，已停止并保留冲突文件。")
        if not _same(target, entry["new"]):
            raise Blocked("维护期间新记录发生变化，已停止。")


def _rollback(entries):
    for entry in reversed(entries):
        if not _same(entry["target"], entry["new"]):
            continue
        if entry.get("swapped"):
            displaced = _snapshot(entry["staging"])
            terminal._exchange(entry["staging"], entry["target"])
            if _same(entry["staging"], entry["new"]):
                entry["swapped"] = False
            elif _same(entry["target"], displaced):
                terminal._exchange(entry["staging"], entry["target"])
        elif entry.get("installed"):
            entry["target"].unlink()
            entry["installed"] = False


def _stage(target, content, old, *, link=False, mode=0o600):
    fd, name = tempfile.mkstemp(prefix=".surge-cc-maintenance-", dir=target.parent)
    staging = Path(name)
    if link:
        os.close(fd)
        staging.unlink()
        staging.symlink_to(content)
    else:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    return {"target": target, "staging": staging, "old": old, "new": _snapshot(staging), "swapped": False}


def _commit(config_path, folder, data, verified, baseline):
    marker = folder / "maintenance-active.json"
    terminal._write_private(marker, _json({"schema": 1, "operation": "native-registration", "created_at": now()}))
    barrier = _snapshot(marker)
    updated = dict(data, original_path=verified["path"], original_link=verified["path"],
                   original_stat=terminal._identity(Path(verified["path"])), native_version=verified["version"])
    updated["shim_sha256"] = terminal._digest(terminal._shim(updated))
    entries = []
    committed = False
    try:
        command = Path(data["command_path"])
        entries.append(_stage(command, terminal._shim(updated), baseline["command"], mode=0o700))
        entries.append(_stage(folder / "original-link", updated["original_link"], baseline["backup"], link=True))
        entries.append(_stage(folder / "manifest.json", _json(updated) + b"\n", baseline["manifest"]))
        _replace_entries(entries)
        if terminal._read_registration(folder) != updated or _hash_file(Path(verified["path"])) != {k: verified[k] for k in ("identity", "sha256")}:
            raise Blocked("提交后版本核验不一致，未恢复启动。")
        terminal._verify_active(updated)
        if not _same(marker, barrier):
            raise Blocked("维护屏障发生变化，未恢复启动。")
        marker.unlink()
        committed = True
    finally:
        if not committed:
            try:
                _rollback(entries)
            except (OSError, ValueError, Blocked):
                pass
            # Keep the barrier if rollback is incomplete or was already pending.
            # A new repair plan can recover intact-but-stale registration later.
            if baseline["barrier"]["kind"] == "missing" and all(_same(e["target"], e["old"]) for e in entries) and _same(marker, barrier):
                marker.unlink()
        for entry in entries:
            expected = entry["old"] if committed and entry["old"]["kind"] != "missing" else entry["new"]
            if _same(entry["staging"], expected):
                entry["staging"].unlink()


def apply(config_path: Path, plan_id: str, *, state_dir=None):
    """Apply exactly the reviewed plan; never stop an existing user session."""
    try:
        if not isinstance(plan_id, str) or not re.fullmatch(r"[a-f0-9]{64}", plan_id):
            raise Blocked("维护计划编号无效，请重新检查。")
        config_path, folder, directory = _folders(config_path, state_dir)
        plan_path = directory / "plans" / (plan_id + ".json")
        _, raw = terminal._update_snapshot(plan_path)
        intent = json.loads(raw)
        if hashlib.sha256(_json(intent)).hexdigest() != plan_id or intent.get("schema") != 1 or intent.get("operation") not in OPERATIONS:
            raise Blocked("维护计划记录不一致，请重新检查。")
        if intent["config_path"] != str(config_path) or intent["state_dir"] != str(folder) or not 0 <= time.time() - intent["created"] <= PLAN_TTL:
            raise Blocked("维护计划已过期或不属于当前配置，请重新检查。")
        with ExitStack() as stack:
            _leases(stack, config_path)
            stack.enter_context(terminal._lock(folder))
            data = _registration(config_path, folder)
            if _state(config_path, folder, data) != intent["baseline"]:
                raise Blocked("原始程序、配置或入口已变化，请重新生成维护计划。")
            config = load_config(config_path)
            target = _native_path(Path(intent["target"]))
            _scope(config, target)
            release = intent["release"]
            expected_state = dict(intent["baseline"])
            if release and not target.exists():
                # Download outside the versions directory so partial files can
                # never match its process scope or a later version selection.
                temporary = stack.enter_context(tempfile.TemporaryDirectory(prefix="download-", dir=directory))
                download = Path(temporary) / "claude"
                _fetch(RELEASES + "/" + release["version"] + "/" + release["platform"] + "/claude", config, download, release["size"])
                download.chmod(0o700)
                if download.stat().st_size != release["size"] or _hash_file(download)["sha256"] != release["sha256"]:
                    raise Blocked("下载文件与官方 SHA256/大小不符，未执行或安装。")
                # First publish the complete bytes without clobber, then verify
                # Apple's publisher before ever executing --version.
                fd, stage_name = tempfile.mkstemp(prefix=".surge-cc-download-", dir=target.parent)
                staged = Path(stage_name)
                try:
                    with os.fdopen(fd, "wb") as output, download.open("rb") as source:
                        os.fchmod(output.fileno(), 0o700)
                        for chunk in iter(lambda: source.read(1024 * 1024), b""):
                            output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                    # Verify signature before exposing a filename accepted by
                    # the versions-directory selection path.
                    if sys.platform != "darwin":
                        raise Blocked("自动更新仅支持 macOS。")
                    signature = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "-R=" + PUBLISHER_REQUIREMENT, str(staged)],
                                               capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
                    if signature.returncode:
                        raise Blocked("下载的 Claude 未通过 Anthropic 发布者签名验证，未安装。")
                    os.link(staged, target)
                    if str(target) == data["original_path"] and intent["baseline"]["original"] == {"kind": "missing"}:
                        expected_state["original"] = _hash_file(target)
                finally:
                    staged.unlink(missing_ok=True)
            verified = _verify_native(target)
            if release and (verified["sha256"] != release["sha256"] or target.stat().st_size != release["size"]):
                raise Blocked("官方版本校验值发生变化，未重新登记。")
            if intent["candidate"] and verified != intent["candidate"]:
                raise Blocked("预览后的原生程序已变化，请重新生成维护计划。")
            if _state(config_path, folder, _registration(config_path, folder)) != expected_state:
                raise Blocked("维护期间原始配置发生变化，未重新登记。")
            _commit(config_path, folder, data, verified, intent["baseline"])
            result = {"schema": 1, "ok": True, "operation": intent["operation"], "version": verified["version"],
                      "summary": "Claude Code 维护完成；终端接管已验证，账号登录和代理设置保持原样。", "checked_at": now()}
            try:
                terminal._write_private(directory / "last-result.json", _json(result))
                plan_path.unlink()
            except OSError:
                # The registration already committed successfully; a history
                # write must not misreport it as a failed/rolled-back update.
                result["history_saved"] = False
            return result
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, Blocked) as error:
        raise error if isinstance(error, Blocked) else Blocked("Claude Code 维护未完成；已保留受控入口和恢复记录，请重新检查维护状态。") from None

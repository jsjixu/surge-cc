"""Activate an account's Claude route without changing Surge's global mode."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from . import repair, containment
from .core import (Blocked, Surge, SURGE_CLI, global_mode_allowed, profile_sections,
                   split_fields, validate_topology, run_checks)

ROUTE_KEYS = ("group", "policy", "expected_ip", "proxy_url", "hosts")


def proposal(original: str, old: dict, target: dict) -> str:
    # Replace only Claude domain routes belonging to these account groups.
    # Other domain/process rules, node credentials and proxy groups are retained.
    hosts = set(old["hosts"]) | set(target["hosts"])
    groups = {old["group"], target["group"]}
    output, section = [], ""
    for line in original.splitlines(keepends=True):
        value = line.strip()
        if value.startswith("[") and value.endswith("]"):
            section = value[1:-1].lower()
        if section == "rule" and not value.startswith(("#", ";", "//")):
            fields = split_fields(value)
            if (len(fields) == 3 and fields[0] == "DOMAIN-SUFFIX"
                    and fields[1] in hosts and fields[2] in groups):
                continue
        if value == "# Surge CC: fixed Claude routes":
            continue
        output.append(line)
    return repair.patch_profile("".join(output), target, True, True)


def activate(config_path: Path, old: dict, target: dict, *, surge=None,
             runner=subprocess.run, check=run_checks):
    """Return an undo closure. Caller commits its account pointer last."""
    if all(old.get(key) == target.get(key) for key in ROUTE_KEYS):
        return lambda: None
    surge = surge or Surge()
    status = surge.status()
    effective_before = surge.profile()
    mode = status.get("mode")
    if mode not in {"rule", "proxy"}:
        raise Blocked("Surge 当前不是规则或全局代理模式，未切换工作区线路。")
    path = Path(target.get("profile_path", ""))
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or status.get("profile-path") != str(path)
            or old.get("profile_path") != str(path)):
        raise Blocked("请先配置当前本地 Surge 配置路径，再切换独立线路。")
    original = path.read_text()
    if original.lstrip().startswith("#!MANAGED-CONFIG"):
        raise Blocked("订阅配置不能由工作区切换直接改写，请先使用本地配置。")
    proposed = proposal(original, old, target)
    try:
        previous_selection = surge.group(target["group"]).get("selected")
    except Blocked:
        previous_selection = None
    fd, candidate = tempfile.mkstemp(prefix=".surge-cc-account-check-", suffix=".conf", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(proposed)
        validation = runner([str(SURGE_CLI), "--check", candidate], capture_output=True, timeout=20)
        if validation.returncode:
            raise Blocked("目标工作区线路配置语法检查失败，未切换。")
    finally:
        os.unlink(candidate)
    latest = surge.status()
    if (path.read_text() != original or surge.profile() != effective_before
            or any(latest.get(k) != status.get(k) for k in ("mode", "profile-path"))):
        raise Blocked("准备切换时 Surge 状态已变化，未改写线路。")
    backup = config_path.parent / "repair-backups"
    if backup.is_symlink() or any(p.is_symlink() for p in backup.parents):
        raise Blocked("线路备份目录异常，未切换。")
    backup.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(backup / ("account-" + uuid.uuid4().hex + ".conf"),
                 os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(original)
    wrote = False

    def undo():
        if wrote:
            if path.read_text() != proposed:
                raise Blocked("线路被其他程序更改，无法自动覆盖回滚；原配置备份已保留。")
            repair.replace_file(path, original)
            if surge.status().get("profile-path") != str(path):
                raise Blocked("当前 Surge 配置已切换；已恢复原文件，请检查生效配置。")
            surge.call("reload")
        if previous_selection:
            surge.call("policy-group", "set", target["group"], previous_selection)

    try:
        if proposed != original:
            repair.replace_file(path, proposed)
            wrote = True
            surge.call("reload")
        for attempt in range(30):
            current = surge.status()
            if current.get("profile-path") != str(path) or current.get("mode") != mode:
                raise Blocked("切换期间 Surge 模式或配置发生变化，已停止切换。")
            try:
                validate_topology(surge.profile(), surge.group(target["group"]), target)
                break
            except Blocked:
                if attempt == 29:
                    raise
                time.sleep(0.1)
        surge.pin(target)
        if mode == "rule" and target.get("browser_path"):
            containment.validate_scope(target, surge)
        report = check(target, surge=surge)
        if not report.get("ok") and not global_mode_allowed(report):
            raise Blocked("目标工作区线路未通过检查，已取消切换。")
    except Exception:
        try:
            undo()
        except Exception:
            raise Blocked("工作区切换未完成，线路回滚未能完整确认；账号未切换，备份已保留。") from None
        raise Blocked("目标工作区线路未就绪，已恢复原线路，账号未切换。") from None
    return undo

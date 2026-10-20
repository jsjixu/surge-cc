"""Reviewable, narrowly scoped repairs. Plans are bound to the observed state."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import uuid

from . import containment
from .core import Blocked, SURGE_CLI, Surge, browser_executable, default_claude, definition, profile_sections, route_is_fixed, split_fields, validate_topology


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def patch_profile(text: str, config: dict, fix_group: bool, fix_rules: bool) -> str:
    """Retain all unrelated lines. Never overwrite a node's credentials."""
    sections = profile_sections(text)
    definition(sections, "proxy", config["policy"])
    lines = text.splitlines(keepends=True)
    current = ""
    group_replaced = False
    rule_inserted = False
    output = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if current == "proxy group" and fix_group and not group_replaced:
                output.append(f'{config["group"]} = select, "{config["policy"]}", include-all-proxies=0\n')
                group_replaced = True
            current = stripped[1:-1].strip().lower()
            output.append(line)
            if current == "rule" and fix_rules:
                if rule_inserted:
                    raise Blocked("配置存在多个 Rule 段，需要先人工整理。")
                output.extend(["# Surge CC: fixed Claude routes\n"] +
                              [f'DOMAIN-SUFFIX,{host},"{config["group"]}"\n' for host in config["hosts"]])
                rule_inserted = True
            continue
        if (current == "proxy group" and fix_group and "=" in line and
                line.split("=", 1)[0].strip().strip('"') == config["group"]):
            if group_replaced:
                raise Blocked("配置存在重复 Claude 组，不能自动覆盖。")
            output.append(f'{config["group"]} = select, "{config["policy"]}", include-all-proxies=0\n')
            group_replaced = True
        else:
            output.append(line)
    if fix_group and not group_replaced:
        if current != "proxy group":
            output.append("\n[Proxy Group]\n")
        output.append(f'{config["group"]} = select, "{config["policy"]}", include-all-proxies=0\n')
    if fix_rules and not rule_inserted:
        output.append("\n[Rule]\n")
        output.extend([f'DOMAIN-SUFFIX,{host},"{config["group"]}"\n' for host in config["hosts"]])
    proposed = "".join(output)
    # Domain repairs must never displace the dedicated listener and process
    # rejection rules. Keep one owner responsible for their order and syntax.
    return containment.patch_profile(proposed, config) if config.get("browser_path") else proposed


def plan(config: dict, surge: Surge | None = None) -> dict:
    surge = surge or Surge()
    status = surge.status()
    if not isinstance(status.get("mode"), str) or status["mode"] not in {"rule", "direct", "proxy"}:
        raise Blocked("无法确认当前出站模式，不能生成可回滚的修复计划。")
    path = config.get("profile_path")
    if not path or status.get("profile-path") != path:
        raise Blocked("自动修复要求明确指定当前本地 Surge 配置文件。")
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise Blocked("自动修复仅支持普通本地配置文件。")
    try:
        original = source.read_text()
    except OSError:
        raise Blocked("无法读取指定配置，未生成修复计划。") from None
    if original.lstrip().startswith("#!MANAGED-CONFIG"):
        raise Blocked("这是托管订阅配置，请在来源或模块中修复，避免更新时覆盖。")
    group = surge.group(config["group"])
    if not isinstance(group.get("selected"), str) or not group["selected"].strip():
        raise Blocked("无法确认当前策略组选择，不能生成可回滚的修复计划。")
    effective = surge.profile()
    try:
        validate_topology(effective, group, config)
        fix_group = False
    except Blocked:
        fix_group = True
    fix_rules = any(not route_is_fixed(surge.route(host, config, process), config)
                    for host in config["hosts"]
                    for process in (str(default_claude()), str(browser_executable(config)), "/usr/bin/curl"))
    dedicated = bool(config.get("browser_path"))
    fix_scope = False
    features = status.get("features")
    enhanced = features.get("enhanced-mode") if isinstance(features, dict) else None
    if dedicated:
        fix_scope = containment.patch_profile(original, config) != original
        if not fix_scope:
            try:
                containment.validate_scope(config, surge)
            except Blocked:
                # A stale effective profile or module/temporary-rule override
                # must remain visible in the review. The post-apply validation
                # will reject anything this narrow repair cannot resolve.
                fix_scope = True
    actions = []
    if fix_group:
        actions.append({"id": "group", "title": "固定 Claude 策略组",
                        "detail": "只保留指定节点的手动选择组；其他节点定义和策略组保留。"})
    if fix_rules:
        actions.append({"id": "rules", "title": "补齐并置顶 Claude 规则",
                        "detail": (f"在专用入口与旁路拒绝规则之后加入 {len(config['hosts'])} 个受保护域名的固定路由。"
                                   if dedicated else
                                   f"在 Rule 段开头加入 {len(config['hosts'])} 个受保护域名的固定路由。")})
    if fix_scope:
        actions.append({"id": "scope", "title": "恢复专用入口与旁路保护",
                        "detail": "保留原有监听入口，补齐独立本机入口；前两条规则固定入口节点并拒绝专用浏览器旁路，应用后重新核验。"})
    if dedicated and enhanced is not True:
        actions.append({"id": "enhanced-required", "title": "需要先手动开启增强模式",
                        "detail": "增强模式未确认开启，当前计划不能应用；本工具不会自动切换这个全局开关。"})
    if fix_group or fix_rules or fix_scope:
        actions.append({"id": "reload", "title": "备份、校验并重载配置",
                        "detail": "保存原文件备份后重载。Surge 可能短暂重连；加载失败时恢复原文件。"})
    if status.get("mode") != "rule":
        actions.append({"id": "mode", "title": "切换为规则模式",
                        "detail": "出站模式改为 rule，所有请求按你现有的分流规则处理。"})
    if fix_group or group.get("selected") != config["policy"]:
        actions.append({"id": "select", "title": "选择指定节点", "detail": "仅更改 Claude 策略组的当前选择。"})
    proposed = patch_profile(original, config, fix_group, fix_rules) if fix_group or fix_rules or dedicated else original
    state = {"source": digest(original), "effective": digest(effective), "mode": status.get("mode"),
             "group": group, "config": config, "proposed": digest(proposed), "actions": actions}
    if dedicated:
        state["enhanced"] = enhanced
    identifier = digest(json.dumps(state, sort_keys=True, ensure_ascii=False))
    return {"plan_id": identifier, "actions": actions,
            "_original": original, "_proposed": proposed, "_path": source,
            "_mode": status.get("mode"), "_selected": group.get("selected")}


def public_plan(value: dict) -> dict:
    return {k: v for k, v in value.items() if not k.startswith("_")}


def replace_file(path: Path, text: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".surge-cc-repair-", suffix=".conf", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            os.fchmod(handle.fileno(), stat.S_IMODE(path.stat().st_mode))
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _wait_scope_ready(config: dict, surge: Surge, proposed: str) -> None:
    """Wait for reload convergence; never change global feature switches."""
    expected = [split_fields(line) for line in profile_sections(proposed).get("rule", [])[:2]]
    consecutive = 0
    for attempt in range(20):
        status = surge.status()
        if status.get("profile-path") != config["profile_path"]:
            raise Blocked("重载期间当前配置已切换，停止后续操作。")
        features = status.get("features")
        ready = (status.get("mode") == "rule" and isinstance(features, dict)
                 and features.get("enhanced-mode") is True)
        if ready:
            actual = [split_fields(line) for line in profile_sections(surge.profile()).get("rule", [])[:2]]
            ready = actual == expected
        consecutive = consecutive + 1 if ready else 0
        if consecutive >= 3:
            return
        if attempt < 19:
            time.sleep(0.25)
    raise Blocked("重载后专用范围保护未恢复就绪，停止并回滚本次修复。")


def apply(config: dict, config_path: Path, plan_id: str, surge: Surge | None = None,
          runner=subprocess.run) -> dict:
    surge = surge or Surge()
    current = plan(config, surge)
    if not plan_id or current["plan_id"] != plan_id:
        raise Blocked("修复计划已变化，请重新预览并确认。")
    if any(item["id"] == "enhanced-required" for item in current["actions"]):
        raise Blocked("请先在 Surge 中手动开启增强模式，再重新预览修复；配置尚未修改。")
    modified = current["_original"] != current["_proposed"]
    backup = None
    if modified:
        folder = config_path.parent / "repair-backups"
        if folder.is_symlink() or any(p.is_symlink() for p in folder.parents if p.exists()):
            raise Blocked("备份目录不能通过符号链接访问，原文件未修改。")
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        backup = folder / (uuid.uuid4().hex + ".conf")
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(current["_original"])
        # Validate a private same-directory candidate so relative references still work.
        fd, candidate = tempfile.mkstemp(prefix=".surge-cc-check-", suffix=".conf", dir=current["_path"].parent)
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(current["_proposed"])
            validation = runner([str(SURGE_CLI), "--check", candidate], capture_output=True, timeout=20)
            if validation.returncode:
                raise Blocked("Surge 配置语法验证失败，原文件未修改。")
        finally:
            os.unlink(candidate)
    # Validation may take seconds. Re-evaluate the full observed state before
    # the first mutation, not just the on-disk file hash.
    if plan(config, surge)["plan_id"] != plan_id:
        raise Blocked("确认后 Surge 状态或配置发生变化，请重新预览。")
    def still_active():
        if surge.status().get("profile-path") != str(current["_path"]):
            raise Blocked("修复期间当前配置已切换，停止后续操作。")
    changed_mode = False
    changed_selection = False
    wrote_file = False
    try:
        if modified:
            still_active()
            replace_file(current["_path"], current["_proposed"])
            wrote_file = True
        if any(item["id"] == "reload" for item in current["actions"]):
            still_active()
            surge.call("reload")
        if any(item["id"] == "mode" for item in current["actions"]):
            still_active()
            changed_mode = True
            surge.call("mode", "set", "rule")
        if any(item["id"] == "select" for item in current["actions"]):
            still_active()
            surge.pin(config)
            changed_selection = True
        still_active()
        if config.get("browser_path"):
            if any(item["id"] == "reload" for item in current["actions"]):
                _wait_scope_ready(config, surge, current["_proposed"])
            containment.validate_scope(config, surge)
    except (Blocked, OSError):
        rollback_complete = True
        if wrote_file:
            try:
                if current["_path"].read_text() == current["_proposed"]:
                    replace_file(current["_path"], current["_original"])
                    if surge.status().get("profile-path") == str(current["_path"]):
                        surge.call("reload")
                else:
                    rollback_complete = False
            except (Blocked, OSError):
                rollback_complete = False
        try:
            if surge.status().get("profile-path") == str(current["_path"]):
                selected_now = surge.group(config["group"]).get("selected")
                if (current["_selected"] != config["policy"] and selected_now == config["policy"]
                        and (changed_selection or any(a["id"] == "select" for a in current["actions"]))):
                    surge.call("policy-group", "set", config["group"], current["_selected"])
                if changed_mode and surge.status().get("mode") == "rule":
                    surge.call("mode", "set", current["_mode"])
        except (Blocked, OSError):
            rollback_complete = False
        raise Blocked("修复未完成，已恢复本次可确认的改动，请重新检查。" if rollback_complete
                      else "修复未完成，部分状态无法确认已恢复；原配置备份已保留，请检查 Surge。") from None
    return {"actions": current["actions"], "backup_created": backup is not None,
            "summary": "已应用确认的修复，请重新执行完整检查。" if current["actions"] else "Claude 策略组、域名规则和出站模式无需修复；其他隐私项目请查看完整检查。"}

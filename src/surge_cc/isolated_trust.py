"""Opt-in directory trust for already validated isolated project launches.

This module grants no filesystem or network access. The launcher must validate
the registered project and any linked Orca worktree before calling ``prepare``.
The private marker is outside every child HOME. Only a missing trust boolean in
the current HOME is seeded; accounts, sessions and settings are never copied.
"""
from __future__ import annotations

from pathlib import Path
import re

from .core import Blocked
from . import isolated_preferences as preferences


MARKER = "trust.json"
MAX_MARKER = 16384
_ID = re.compile(r"[a-z][a-z0-9-]{0,39}\Z")
_ERROR = "隔离项目信任配置无效、正在变化或权限不安全，已停止自动信任。"


def _allowlist(runtime, base: Path):
    data, state = preferences._read(runtime, MARKER, private=True,
                                    limit=MAX_MARKER)
    if state is None:
        return None, None
    if (type(data.get("schema")) is not int or data["schema"] != 1
            or type(data.get("enabled")) is not bool):
        raise ValueError("invalid trust schema")
    if data["enabled"] is False:
        if set(data) != {"schema", "enabled"}:
            raise ValueError("invalid disabled trust marker")
        return None, state
    if set(data) != {"schema", "enabled", "projects"} or not isinstance(data["projects"], list):
        raise ValueError("invalid trust allowlist")
    entries = {}
    for item in data["projects"]:
        if (not isinstance(item, dict) or set(item) != {"id", "path"}
                or not isinstance(item["id"], str) or _ID.fullmatch(item["id"]) is None
                or not isinstance(item["path"], str) or item["id"] in entries):
            raise ValueError("invalid trust entry")
        expected = base / "projects" / item["id"]
        # Exact strings disallow alternate spellings, wildcard roots and '..'.
        # Resolve only after the allowlisted structural path has been checked.
        if item["path"] != str(expected) or expected.resolve() != expected:
            raise ValueError("noncanonical trust root")
        entries[item["id"]] = expected
    return entries, state


def prepare(project) -> bool:
    """Seed only missing native directory trust for an explicitly listed root.

    Native Claude Code 2.1.296 keys linked-worktree trust by the main repository
    root. Each worktree still uses its own HOME and config. An existing explicit
    false is a user decision and is not overridden. Returns whether the current
    HOME's config changed. Call only after final worktree validation.
    """
    try:
        with preferences._scope(project) as (runtime, current):
            base = Path(project.base).absolute()
            entries, marker_state = _allowlist(runtime, base)
            if entries is None:
                return False
            if (not isinstance(project.name, str) or _ID.fullmatch(project.name) is None
                    or Path(project.registered_root) != base / "projects" / project.name
                    or Path(project.registered_root).resolve() != Path(project.registered_root)):
                raise ValueError("invalid current registered root")
            if entries.get(project.name) != project.registered_root:
                return False
            config, state = preferences._read(current, preferences.CONFIG, private=True)
            projects = config.get("projects", {})
            if not isinstance(projects, dict):
                raise ValueError("invalid native project map")
            key = str(project.registered_root)
            entry = projects.get(key, {})
            if not isinstance(entry, dict):
                raise ValueError("invalid native project entry")
            if "hasTrustDialogAccepted" in entry:
                if type(entry["hasTrustDialogAccepted"]) is not bool:
                    raise ValueError("invalid native trust flag")
                return False
            updated_entry = dict(entry, hasTrustDialogAccepted=True)
            updated_projects = dict(projects)
            updated_projects[key] = updated_entry
            updated_config = dict(config, projects=updated_projects)
            # Recheck the authorization marker before making a private atomic
            # change. _write independently rejects concurrent native updates.
            preferences._unchanged(runtime, MARKER, marker_state)
            preferences._write(current, preferences.CONFIG, updated_config, state)
            return True
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise Blocked(_ERROR) from None

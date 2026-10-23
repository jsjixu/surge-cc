"""Migrate one known obsolete rule set in already-validated isolated copies.

The original template denied all of ~/orca, which includes the current Orca
worktree. Seatbelt already denies every unrelated directory. Never remove a
standalone user deny rule, or change the operating-system sandbox here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from .core import Blocked


def template(host_home: Path) -> list[str]:
    roots = ("Documents/Claude", "orca", ".claude", ".config",
             "Library/Application Support/Orca", "Library/Logs")
    return [f"{tool}(/{host_home / root}/**)" for tool in ("Read", "Edit") for root in roots]


def repair(project, *, host_home: Path | None = None) -> dict | None:
    """Called only after the launcher validates the registered project/HOME."""
    from .development import _read_settings
    path = project.root / ".claude/settings.json"
    value = _read_settings(path, (project.root,))
    permissions = value.get("permissions")
    if not isinstance(permissions, dict):
        return None
    rules = permissions.get("deny")
    home = Path.home() if host_home is None else Path(host_home)
    expected = template(home)
    if not isinstance(rules, list) or not all(rule in rules for rule in expected):
        return None
    obsolete = {f"{tool}(/{home / 'orca'}/**)" for tool in ("Read", "Edit")}
    try:
        # Reject aliases/hardlinks before both backup and replacement. Do not
        # migrate settings.local.json or arbitrary partial/custom deny lists.
        if path.resolve(strict=True) != path or project.home.resolve(strict=True) != project.home:
            raise ValueError("noncanonical scope")
        original = path.lstat()
        if original.st_uid != os.getuid() or original.st_nlink != 1 or not stat.S_ISREG(original.st_mode):
            raise ValueError("unsafe settings")
        raw = path.read_bytes()
        if json.loads(raw) != value:
            raise ValueError("settings changed")
        backup_dir = project.home / ".surge-cc-settings-backups"
        if os.path.lexists(backup_dir):
            info = backup_dir.lstat()
            if (backup_dir.resolve() != backup_dir or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.getuid() or info.st_mode & 0o077):
                raise ValueError("unsafe backup directory")
        else:
            backup_dir.mkdir(mode=0o700)
        fd, backup_name = tempfile.mkstemp(prefix="legacy-orca-deny-", suffix=".json", dir=backup_dir)
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        updated = dict(value)
        updated["permissions"] = dict(permissions, deny=[rule for rule in rules if rule not in obsolete])
        body = (json.dumps(updated, ensure_ascii=False, indent=2) + "\n").encode()
        fd, staging = tempfile.mkstemp(prefix=".surge-cc-settings-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                os.fchmod(output.fileno(), stat.S_IMODE(original.st_mode) & 0o755)
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
            current = path.lstat()
            identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_nlink)
            if path.resolve(strict=True) != path or identity(current) != identity(original) or path.read_bytes() != raw:
                raise ValueError("concurrent settings change")
            os.replace(staging, path)
        finally:
            if os.path.lexists(staging):
                os.unlink(staging)
        return {"path": str(path), "backup": backup_name, "removed": sorted(obsolete),
                "before_sha256": hashlib.sha256(raw).hexdigest(),
                "after_sha256": hashlib.sha256(body).hexdigest()}
    except (OSError, ValueError, TypeError):
        raise Blocked("旧版 Orca 权限规则迁移未完成；请检查设置及私有备份，不会取消文件隔离。") from None

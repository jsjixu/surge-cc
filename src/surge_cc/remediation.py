"""Attach one allowlisted UI action without replacing the original diagnostic.

These are navigation/preview actions, never commands or implicit repairs. In
particular an observed exit mismatch must never update the expected IP.
"""
from . import terminal


ACTIONS = frozenset({"recover-browser", "repair-terminal", "open-surge", "configure-route",
                     "repair-route", "open-app-management", "recheck"})
_TERMINAL_COMMANDS = {"check", "checkdetail", "status", "launch", "terminal", "maintenance", "orca"}
_TERMINAL_PHRASES = ("原始 Claude 程序已变化", "终端集成", "Claude 命令入口", "Claude 入口属于 Surge CC",
                     "终端接管记录", "Claude Code 维护尚未完成")


def _failed_rows(report):
    rows = report.get("checks")
    if not isinstance(rows, (list, tuple)):
        return [], set()
    rows = [item for item in rows if isinstance(item, dict) and item.get("required", True) is not False
            and item.get("status") in ("fail", "unknown")]
    return rows, {item["id"] for item in rows if isinstance(item.get("id"), str)}


def _terminal_observation():
    # This enrichment is advisory. It must never hide the original route,
    # permission, auth or browser error because its own read/stat/query failed.
    try:
        value = terminal.status()
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def attach(report, *, command="check", error=None):
    if not isinstance(report, dict) or report.get("ok") is True or report.get("paused") is True:
        return report
    rows, failed = _failed_rows(report)
    if report.get("recovery_action") in ("recover-browser", "repair-browser-locks"):
        action = "recover-browser"
    elif isinstance(error, PermissionError):
        action = "open-app-management"
    elif "surge" in failed or "mode" in failed or "proxy" in failed:
        action = "open-surge"
    elif failed & {"exit", "geoip_country", "geoip_asn"}:
        action = "configure-route"
    elif failed & {"definition", "group", "route", "stable", "browser_containment"}:
        action = "repair-route"
    else:
        details = [item.get("detail", "") for item in rows]
        if isinstance(error, Exception):
            try:
                details.append(str(error))
            except Exception:
                pass
        related = (command == "terminal" or bool(failed & {"terminal", "terminal_metadata", "native-version"})
                   or any(phrase in detail for detail in details if isinstance(detail, str)
                          for phrase in _TERMINAL_PHRASES))
        # Only use a global terminal observation when no primary diagnostic
        # explains the failure. An unrelated broken CLI must not hijack a DNS,
        # project-isolation, browser or account-specific error's action.
        observed = _terminal_observation() if command in _TERMINAL_COMMANDS and not failed and error is None else {}
        if related or observed.get("ok") is False:
            action = "repair-terminal"
        elif command == "configure" or report.get("settings") == {}:
            action = "configure-route"
        else:
            action = "recheck"
    report["remediation_action"] = action
    return report

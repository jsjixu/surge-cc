"""Synthetic, local-only probe executed inside the production Seatbelt policy.

Never read credential contents. Existing external paths are opened/listed only
to prove denial; output contains booleans, not filenames or file contents.
"""
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import uuid


def main():
    spec = json.loads(os.environ.pop("SURGE_CC_ISOLATION_PROBE"))
    root, home = Path(spec["root"]), Path(os.environ["HOME"])
    checks = []

    def record(name, ok):
        checks.append({"test": name, "pass": bool(ok)})

    def denied(path, directory=False):
        try:
            if directory:
                os.listdir(path)
            else:
                fd = os.open(path, os.O_RDONLY)
                os.close(fd)
            return False
        except OSError as error:
            return error.errno in (errno.EPERM, errno.EACCES)

    canary = root / (".surge-cc-test-" + uuid.uuid4().hex)
    home_canary = home / ("test-" + uuid.uuid4().hex)
    link = root / (".surge-cc-link-" + uuid.uuid4().hex)
    hardlink = root / (".surge-cc-hardlink-" + uuid.uuid4().hex)
    try:
        context = root / "PROJECT_CONTEXT.md"
        if context.exists():
            record("project_context_read", bool(context.read_text()))
        canary.write_text("synthetic-project-canary")
        record("project_write_read", canary.read_text() == "synthetic-project-canary")
        home_canary.write_text("synthetic-home-canary")
        record("isolated_home_write_read", home_canary.read_text() == "synthetic-home-canary")
        for index, item in enumerate(spec["denied"]):
            record("external_path_denied_" + str(index), denied(item["path"], item["directory"]))
        outside = spec["outside_canary"]
        record("outside_canary_denied", denied(outside))
        record("data_volume_alias_denied", denied("/System/Volumes/Data" + outside))
        link.symlink_to(outside)
        record("symlink_escape_denied", denied(link))
        try:
            os.link(outside, hardlink)
            record("hardlink_escape_denied", False)
        except OSError as error:
            record("hardlink_escape_denied", error.errno in (errno.EPERM, errno.EACCES))
        shell = subprocess.run(["/bin/sh", "-c", '/bin/cat "$1" && /bin/cat "$2" >/dev/null',
                                "probe", str(canary), outside],
                               capture_output=True, timeout=10, close_fds=True)
        record("shell_child_read_denied", shell.returncode == 1 and
               shell.stdout == b"synthetic-project-canary" and b"Operation not permitted" in shell.stderr)
        child_source = '''import errno,os,sys
assert open(sys.argv[1]).read() == "synthetic-project-canary"
try:
    fd=os.open(sys.argv[2],os.O_RDONLY)
    os.close(fd)
except OSError as e:
    sys.exit(41 if e.errno in (errno.EPERM,errno.EACCES) else 42)
sys.exit(43)
'''
        grandchild = subprocess.run([sys.executable, "-c",
            "import subprocess,sys;sys.exit(subprocess.run([sys.executable,'-c',sys.argv[1],sys.argv[2],sys.argv[3]]).returncode)",
            child_source, str(canary), outside], capture_output=True, timeout=10, close_fds=True)
        record("grandchild_read_denied", grandchild.returncode == 41)
        unexpected = [k for k in os.environ if k.startswith(("ANTHROPIC_", "AWS_", "GOOGLE_", "ORCA_", "DYLD_"))
                      or k in {"NODE_OPTIONS", "PYTHONPATH", "SSH_AUTH_SOCK", "GH_TOKEN", "GITHUB_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"}]
        record("inherited_credentials_and_injection_absent", not unexpected)
        record("fresh_home_config", Path(os.environ["CLAUDE_CONFIG_DIR"]) == home / ".claude")
        # A deliberately inheritable FD is opened by the trusted parent. The
        # actual launcher must close it before exec. 0/1/2 remain user channels.
        try:
            os.fstat(spec["outside_fd"])
            record("extra_descriptor_closed", False)
        except OSError as error:
            record("extra_descriptor_closed", error.errno == errno.EBADF)
        for name, address in (("surge_only_port_allowed", ("127.0.0.1", 62919)),
                              ("other_proxy_port_denied", ("127.0.0.1", 6152)),
                              ("arbitrary_localhost_denied", ("127.0.0.1", 9)),
                              ("direct_public_network_denied", ("1.1.1.1", 443))):
            with socket.socket() as connection:
                connection.settimeout(2)
                try:
                    connection.connect(address)
                    record(name, address[1] == 62919)
                except OSError as error:
                    record(name, address[1] != 62919 and error.errno in (errno.EPERM, errno.EACCES))
        record("native_binary_readable", os.access(spec["native"], os.R_OK))
        if spec.get("git"):
            # No writes to the user's index, no hooks/fsmonitor/external diff,
            # no credentials or network. Never emit repository contents.
            git_env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0",
                           GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="")
            prefix = ["/usr/bin/git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]
            for label, args in (("git_status", ["status", "--porcelain=v1"]),
                                ("git_diff", ["diff", "--no-ext-diff", "--no-textconv", "--stat"]),
                                ("git_history", ["log", "-1", "--format=%H"])):
                result = subprocess.run(prefix + args, cwd=root, env=git_env,
                                        capture_output=True, timeout=20, close_fds=True)
                record(label, result.returncode == 0)
            common = Path(spec["git"]["common_dir"])
            shared_link = root / (".surge-cc-shared-link-" + uuid.uuid4().hex)
            try:
                os.link(common / "config", shared_link)
                shared_link.unlink()
                record("shared_git_hardlink_escape_denied", False)
            except OSError as error:
                record("shared_git_hardlink_escape_denied", error.errno in (errno.EPERM, errno.EACCES))
            # O_WRONLY without O_TRUNC checks permission without changing data.
            try:
                fd = os.open(common / "config", os.O_WRONLY | os.O_NOFOLLOW)
                os.close(fd)
                record("shared_git_config_write_denied", False)
            except OSError as error:
                record("shared_git_config_write_denied", error.errno in (errno.EPERM, errno.EACCES))
            for directory in ("objects", "refs"):
                candidate = common / directory / ("surge-cc-probe-" + uuid.uuid4().hex)
                try:
                    fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    os.close(fd)
                    candidate.unlink()
                    record("shared_git_" + directory + "_write_denied", False)
                except OSError as error:
                    record("shared_git_" + directory + "_write_denied", error.errno in (errno.EPERM, errno.EACCES))
        help_run = subprocess.run([spec["native"], *spec["native_help_args"]], capture_output=True, text=True,
                                  timeout=30, close_fds=True)
        record("native_claude_help", help_run.returncode == 0 and "Usage: claude" in help_run.stdout)
    finally:
        for path in (canary, home_canary, link, hardlink):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    result = {"schema": 1, "project": spec["project"], "ok": all(c["pass"] for c in checks),
              "checks": checks, "model_called": False, "login_performed": False}
    print(json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

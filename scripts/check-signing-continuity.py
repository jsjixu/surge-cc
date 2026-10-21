#!/usr/bin/env python3
"""Read-only preflight for code-signing identity continuity between two apps.

This does not query, grant, reset or verify TCC/privacy permissions. macOS makes
the authorization decision. In particular, migration from an ad-hoc build is
not reported as permission-preserving, even when its bundle identifier matches.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


CODESIGN = "/usr/bin/codesign"
LIMITATION = (
    "Only code-signing continuity is checked. This does not verify or guarantee "
    "retention of TCC/privacy permissions; macOS decides authorization."
)


class Incompatible(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _codesign(arguments, failure_code, failure_message):
    """Never invoke a shell or disclose arbitrary tool output in the report."""
    try:
        completed = subprocess.run(
            [CODESIGN, *arguments], stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=30, check=False,
        )
    except FileNotFoundError:
        raise Incompatible("tool_unavailable", "The codesign tool is unavailable.")
    except subprocess.TimeoutExpired:
        raise Incompatible("tool_timeout", "A codesign check timed out; continuity is unverified.")
    except (OSError, UnicodeError):
        raise Incompatible("tool_failed", "The codesign tool could not complete the check.")
    if completed.returncode != 0:
        raise Incompatible(failure_code, failure_message)
    # `-r-` normally emits requirements to stdout and display metadata to
    # stderr. Accept either stream, while _one_value rejects duplicate fields.
    return completed.stderr + "\n" + completed.stdout


def _one_value(output, pattern, label):
    matches = re.findall(pattern, output, flags=re.MULTILINE)
    if len(matches) != 1 or not matches[0].strip():
        raise Incompatible("signature_metadata_invalid", "Missing or ambiguous signing " + label + ".")
    return matches[0].strip()


def _identity(path, side):
    _codesign(["--verify", "--strict", str(path)],
              side + "_signature_invalid", "The " + side + " app failed strict signature verification.")
    output = _codesign(["-d", "--verbose=4", "-r-", str(path)],
                       side + "_signature_unreadable", "The " + side + " app signing identity could not be read.")
    identifier = _one_value(output, r"^Identifier=(.*)$", "identifier")
    # Standard ad-hoc signatures identify themselves either explicitly or in
    # CodeDirectory flags. A missing certificate signature is not a stable ID.
    ad_hoc = bool(re.search(r"^Signature=adhoc\s*$", output, re.MULTILINE | re.IGNORECASE)
                  or re.search(r"^CodeDirectory .*\([^\n)]*\badhoc\b[^\n)]*\)", output,
                               re.MULTILINE | re.IGNORECASE))
    certificate_signature = bool(re.search(r"^Signature size=[1-9][0-9]*\s*$", output, re.MULTILINE)
                                 and re.search(r"^Authority=\S.*$", output, re.MULTILINE))
    if not ad_hoc and not certificate_signature:
        raise Incompatible("signature_metadata_invalid", "The " + side + " app has no verifiable certificate-signature metadata.")
    # Ad-hoc code may expose only a commented, implicit cdhash requirement.
    # It is categorically incompatible, without having to parse that comment.
    requirement = "" if ad_hoc else _one_value(output, r"^designated => (.*)$", "designated requirement")
    return {"identifier": identifier, "ad_hoc": ad_hoc, "requirement": requirement}


def check(old_app, new_app):
    report = {"schema": 1, "status": "not_compatible", "compatible": False,
              "reason_code": "unverified", "summary": "Signing continuity has not been verified.",
              "limitation": LIMITATION}
    try:
        # Absolute argument values cannot be interpreted as codesign options.
        # Resolving paths only reads filesystem metadata; app files are untouched.
        old_path = Path(old_app).expanduser().resolve(strict=True)
        new_path = Path(new_app).expanduser().resolve(strict=True)
        if not old_path.is_dir() or not new_path.is_dir():
            raise Incompatible("invalid_app_path", "Both inputs must be existing app bundle directories.")
        old = _identity(old_path, "old")
        new = _identity(new_path, "new")
        report["old"] = {key: old[key] for key in ("identifier", "ad_hoc")}
        report["new"] = {key: new[key] for key in ("identifier", "ad_hoc")}
        if old["identifier"] != new["identifier"]:
            raise Incompatible("identifier_mismatch", "The app signing identifiers differ.")
        if old["ad_hoc"] or new["ad_hoc"]:
            raise Incompatible("ad_hoc_identity", "An ad-hoc signature cannot establish identity continuity across updates; first migration may require authorization again.")
        _codesign(["--verify", "--strict", "-R", "=" + old["requirement"], str(new_path)],
                  "new_rejects_old_requirement", "The new app does not satisfy the old app designated requirement.")
        _codesign(["--verify", "--strict", "-R", "=" + new["requirement"], str(old_path)],
                  "old_rejects_new_requirement", "The old app does not satisfy the new app designated requirement.")
        report.update(status="verified", compatible=True, reason_code="mutual_requirements_verified",
                      summary="Both valid signatures satisfy each other's designated requirement.")
    except Incompatible as error:
        report.update(reason_code=error.code, summary=str(error))
    except (OSError, RuntimeError, ValueError):
        report.update(reason_code="invalid_app_path", summary="An app bundle path is missing or cannot be inspected.")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old_app", help="Currently installed app bundle")
    parser.add_argument("new_app", help="Newly built app bundle, before installation")
    parser.add_argument("--json", action="store_true", help="Write a structured report")
    options = parser.parse_args(argv)
    report = check(options.old_app, options.new_app)
    if options.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(report["status"] + ": " + report["summary"])
        print(report["limitation"])
    return 0 if report["compatible"] else 2


if __name__ == "__main__":
    sys.exit(main())

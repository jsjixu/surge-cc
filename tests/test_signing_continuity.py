"""Signing preflight tests never sign an app or access a real keychain/TCC."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check-signing-continuity.py"
SPEC = importlib.util.spec_from_file_location("check_signing_continuity", SCRIPT)
continuity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(continuity)


def metadata(identifier="local.surgecc.app", requirement=None, ad_hoc=False,
             digest="a" * 40):
    requirement = requirement or 'identifier "local.surgecc.app" and anchor apple generic and certificate leaf[subject.OU] = "TESTTEAM12"'
    return "\n".join([
        "Executable=/fixture with spaces/Surge CC.app/Contents/MacOS/SurgeCC",
        "Identifier=" + identifier,
        "CodeDirectory v=20500 size=420 flags=" + ("0x2(adhoc)" if ad_hoc else "0x0(none)"),
        "CDHash=" + digest,
        "Signature=adhoc" if ad_hoc else "Signature size=9024\nAuthority=Developer ID Application: Test Fixture (TESTTEAM12)",
        "TeamIdentifier=not set" if ad_hoc else "TeamIdentifier=TESTTEAM12",
        "designated => " + requirement,
        "",
    ])


class SigningContinuityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="signing check ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.old = self.root / "Old Surge CC.app"
        self.new = self.root / "New Surge CC.app"
        self.old.mkdir()
        self.new.mkdir()
        (self.old / "do not modify").write_text("old contents")
        (self.new / "do not modify").write_text("new contents")
        self.output = {str(self.old): metadata(digest="a" * 40),
                       str(self.new): metadata(digest="b" * 40)}
        self.calls = []
        self.fail_on = None
        self.requirements_on_stdout = True

        def run(arguments, **kwargs):
            self.assertIsInstance(arguments, list)
            self.assertEqual(arguments[0], "/usr/bin/codesign")
            self.assertNotIn("shell", kwargs)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertTrue(kwargs["capture_output"])
            self.assertTrue(kwargs["text"])
            self.assertFalse(kwargs["check"])
            self.assertEqual(kwargs["timeout"], 30)
            self.assertFalse(any(flag in arguments for flag in ("--sign", "--remove-signature")))
            self.calls.append(arguments)
            fail = self.fail_on and self.fail_on(arguments)
            result = self.output.get(arguments[-1], "") if "-d" in arguments else ""
            stdout = ""
            if self.requirements_on_stdout:
                lines = result.splitlines()
                stdout = "\n".join(line for line in lines if line.startswith("designated => "))
                result = "\n".join(line for line in lines if not line.startswith("designated => "))
            return subprocess.CompletedProcess(arguments, 1 if fail else 0, stdout=stdout, stderr=result)

        self.process = patch.object(continuity.subprocess, "run", side_effect=run)
        self.mock_run = self.process.start()
        self.addCleanup(self.process.stop)

    def verify(self):
        return continuity.check(self.old, self.new)

    def test_certificate_requirement_continuity_allows_changed_code_hash(self):
        result = self.verify()
        self.assertTrue(result["compatible"])
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["reason_code"], "mutual_requirements_verified")
        self.assertEqual(len(self.calls), 6)
        self.assertEqual(self.calls[0][1:3], ["--verify", "--strict"])
        self.assertEqual(self.calls[2][1:3], ["--verify", "--strict"])
        self.assertIn("-r-", self.calls[1])
        self.assertIn("-r-", self.calls[3])
        self.assertEqual(self.calls[4][-1], str(self.new))
        self.assertEqual(self.calls[5][-1], str(self.old))
        self.assertEqual(self.calls[4][3], "-R")
        self.assertTrue(self.calls[4][4].startswith('=identifier "'))
        self.assertNotIn("Authority", json.dumps(result))
        self.assertIn("does not verify or guarantee", result["limitation"])
        self.assertIn("macOS decides", result["limitation"])
        self.assertEqual((self.old / "do not modify").read_text(), "old contents")
        self.assertEqual((self.new / "do not modify").read_text(), "new contents")

    def test_each_requirement_is_used_on_opposite_app_as_one_argument(self):
        old_dr = 'identifier "local.surgecc.app" and certificate leaf = H"0123"'
        new_dr = 'identifier "local.surgecc.app" and certificate leaf = H"4567"'
        self.output[str(self.old)] = metadata(requirement=old_dr)
        self.output[str(self.new)] = metadata(requirement=new_dr)
        self.assertTrue(self.verify()["compatible"])
        self.assertEqual(self.calls[4], [continuity.CODESIGN, "--verify", "--strict", "-R", "=" + old_dr, str(self.new)])
        self.assertEqual(self.calls[5], [continuity.CODESIGN, "--verify", "--strict", "-R", "=" + new_dr, str(self.old)])

    def test_requirements_in_stderr_are_also_supported(self):
        self.requirements_on_stdout = False
        self.assertTrue(self.verify()["compatible"])

    def test_ad_hoc_to_certificate_migration_is_explicitly_incompatible(self):
        self.output[str(self.old)] = metadata(ad_hoc=True, requirement='cdhash H"' + "a" * 40 + '"')
        result = self.verify()
        self.assertFalse(result["compatible"])
        self.assertEqual(result["reason_code"], "ad_hoc_identity")
        self.assertIn("first migration", result["summary"])
        self.assertFalse(any("-R" in call for call in self.calls))

    def test_new_ad_hoc_signature_is_rejected(self):
        self.output[str(self.new)] = metadata(ad_hoc=True)
        self.assertEqual(self.verify()["reason_code"], "ad_hoc_identity")

    def test_both_ad_hoc_different_or_identical_hashes_are_never_continuity(self):
        for digest in ("a" * 40, "b" * 40):
            with self.subTest(digest=digest):
                self.output[str(self.old)] = metadata(ad_hoc=True, digest="a" * 40)
                self.output[str(self.new)] = metadata(ad_hoc=True, digest=digest)
                self.assertEqual(self.verify()["reason_code"], "ad_hoc_identity")

    def test_ad_hoc_code_directory_flag_alone_is_rejected(self):
        self.output[str(self.old)] = metadata(ad_hoc=True).replace("Signature=adhoc\n", "")
        self.assertEqual(self.verify()["reason_code"], "ad_hoc_identity")

    def test_ad_hoc_implicit_requirement_still_reports_migration(self):
        self.output[str(self.old)] = metadata(ad_hoc=True).replace("designated => ", "# designated => ")
        self.assertEqual(self.verify()["reason_code"], "ad_hoc_identity")

    def test_same_team_but_different_identifier_is_rejected(self):
        self.output[str(self.new)] = metadata(identifier="local.other.app")
        self.assertEqual(self.verify()["reason_code"], "identifier_mismatch")
        self.assertFalse(any("-R" in call for call in self.calls))

    def test_strict_verification_failure_stops_without_continuity_claim(self):
        for side in ("old", "new"):
            with self.subTest(side=side):
                path = str(getattr(self, side))
                self.fail_on = lambda args: "--verify" in args and args[-1] == path
                self.assertEqual(self.verify()["reason_code"], side + "_signature_invalid")

    def test_signature_display_failure_is_rejected(self):
        self.fail_on = lambda args: "-d" in args and args[-1] == str(self.new)
        self.assertEqual(self.verify()["reason_code"], "new_signature_unreadable")

    def test_missing_ambiguous_or_unsigned_metadata_is_rejected(self):
        original = self.output[str(self.old)]
        for invalid in ("", "code object is not signed at all\n",
                        original.replace("Identifier=", "MissingIdentifier="),
                        original + "Identifier=local.other.app\n",
                        original.replace("designated => ", "missing => "),
                        original + "designated => true\n",
                        original.replace("Signature size=9024", "Signature size=0"),
                        original.replace("Authority=", "MissingAuthority=")):
            with self.subTest(metadata=invalid):
                self.output[str(self.old)] = invalid
                result = self.verify()
                self.assertFalse(result["compatible"])
                self.assertEqual(result["reason_code"], "signature_metadata_invalid")

    def test_same_identifier_different_cdhash_requirement_must_be_compatible_both_ways(self):
        self.output[str(self.old)] = metadata(requirement='cdhash H"' + "a" * 40 + '"')
        self.output[str(self.new)] = metadata(requirement='cdhash H"' + "b" * 40 + '"')
        for target, reason in ((self.new, "new_rejects_old_requirement"),
                               (self.old, "old_rejects_new_requirement")):
            with self.subTest(target=target):
                self.fail_on = lambda args: "-R" in args and args[-1] == str(target)
                result = self.verify()
                self.assertFalse(result["compatible"])
                self.assertEqual(result["reason_code"], reason)

    def test_missing_tool_timeout_and_system_failure_are_closed(self):
        for error, reason in ((FileNotFoundError(), "tool_unavailable"),
                              (subprocess.TimeoutExpired("codesign", 30), "tool_timeout"),
                              (PermissionError(), "tool_failed")):
            with self.subTest(error=error):
                self.mock_run.side_effect = error
                result = self.verify()
                self.assertFalse(result["compatible"])
                self.assertEqual(result["reason_code"], reason)

    def test_invalid_paths_are_rejected_without_tool_calls(self):
        for invalid in (self.root / "missing.app", self.old / "do not modify"):
            with self.subTest(path=invalid):
                self.assertEqual(continuity.check(self.old, invalid)["reason_code"], "invalid_app_path")
        self.mock_run.assert_not_called()

    def test_json_cli_exit_status_matches_verification_without_claiming_tcc(self):
        for failure in (False, True):
            with self.subTest(failure=failure):
                self.fail_on = lambda args: failure
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    exit_code = continuity.main([str(self.old), str(self.new), "--json"])
                report = json.loads(output.getvalue())
                self.assertEqual(exit_code, 2 if failure else 0)
                self.assertEqual(report["compatible"], not failure)
                self.assertIn("TCC/privacy", report["limitation"])

    def test_text_cli_also_states_scope(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(continuity.main([str(self.old), str(self.new)]), 0)
        self.assertTrue(output.getvalue().startswith("verified: "))
        self.assertIn("macOS decides authorization", output.getvalue())


if __name__ == "__main__":
    unittest.main()

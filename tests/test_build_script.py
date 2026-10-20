"""Build publication checks use temporary files and stub toolchains only."""
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == "darwin", "macOS exclusive rename is required")
class BuildOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.project = self.root / "fixture"
        for directory in ("scripts", "app/assets", "src/surge_cc"):
            (self.project / directory).mkdir(parents=True)
        source = Path(__file__).resolve().parents[1] / "scripts/build-app.sh"
        self.script = self.project / "scripts/build-app.sh"
        shutil.copy2(source, self.script)
        (self.project / "scripts/surge-cc").write_text("# fixture; never executed\n")
        (self.project / "src/surge_cc/__init__.py").write_text("")
        (self.project / "app/main.swift").write_text("// fixture; never compiled\n")
        (self.project / "app/assets/SurgeCCIcon.icns").write_bytes(b"fixture icon")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "calls.jsonl"
        stub = f"""#!{sys.executable}
import json
import os
from pathlib import Path
import sys
tool = Path(sys.argv[0]).name
with open(os.environ["BUILD_TEST_LOG"], "a") as log:
    log.write(json.dumps([tool, *sys.argv[1:]]) + "\\n")
if tool == "swiftc":
    out = Path(sys.argv[sys.argv.index("-o") + 1])
    out.write_bytes(b"fixture executable; never launched")
    if os.environ.get("BUILD_TEST_FAIL"):
        sys.exit(9)
if tool == "codesign" and "--verify" in sys.argv:
    destination = os.environ.get("BUILD_TEST_RACE")
    if destination:
        path = Path(destination)
        outside = os.environ.get("BUILD_TEST_RACE_LINK")
        if outside:
            path.symlink_to(outside, target_is_directory=True)
        else:
            path.mkdir()
            (path / "keep.txt").write_text("concurrent owner")
"""
        for name in ("swiftc", "plutil", "codesign"):
            tool = self.bin / name
            tool.write_text(stub)
            tool.chmod(0o755)
        self.dist = self.project / "dist"
        self.env = dict(os.environ)
        self.env.pop("SURGE_CC_APP_NAME", None)
        self.env.pop("SURGE_CC_DIST_DIR", None)
        self.env.update(PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        BUILD_TEST_LOG=str(self.log))

    def build(self, **environment):
        return subprocess.run(["/bin/bash", str(self.script)], text=True,
                              capture_output=True, env=dict(self.env, **environment))

    def assert_no_staging(self):
        self.assertEqual(list(self.dist.glob(".surge-cc-build.*")), [])

    def test_versioned_output_preserves_existing_default_app(self):
        existing = self.dist / "Surge CC.app"
        existing.mkdir(parents=True)
        (existing / "keep.txt").write_text("running version")
        result = self.build(SURGE_CC_APP_NAME="Surge CC 0.2.2.app")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((existing / "keep.txt").read_text(), "running version")
        self.assertEqual(list(existing.iterdir()), [existing / "keep.txt"])
        output = self.dist / "Surge CC 0.2.2.app"
        info = plistlib.loads((output / "Contents/Info.plist").read_bytes())
        self.assertEqual(info["CFBundleShortVersionString"], "0.2.3")
        self.assertEqual(info["CFBundleVersion"], "5")
        self.assertTrue((output / "Contents/MacOS/SurgeCC").is_file())
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([call[0] for call in calls],
                         ["swiftc", "plutil", "codesign", "codesign"])
        for flag in ("-file-prefix-map", "-debug-prefix-map"):
            self.assertEqual(calls[0][calls[0].index(flag) + 1], str(self.project) + "=/SurgeCC")
        self.assertIn("app/main.swift", calls[0])
        self.assertNotIn(str(self.project / "app/main.swift"), calls[0])
        self.assert_no_staging()

    def test_existing_directory_is_rejected_before_toolchain_runs(self):
        existing = self.dist / "Surge CC.app"
        existing.mkdir(parents=True)
        (existing / "keep.txt").write_text("keep")
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to replace", result.stderr)
        self.assertFalse(self.log.exists())
        self.assertEqual((existing / "keep.txt").read_text(), "keep")
        self.assert_no_staging()

    def test_existing_dangling_symlink_is_rejected(self):
        self.dist.mkdir()
        output = self.dist / "Surge CC.app"
        output.symlink_to(self.root / "missing")
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(output.is_symlink())
        self.assertFalse(self.log.exists())
        self.assert_no_staging()

    def test_unsafe_or_empty_app_names_are_rejected(self):
        for name in ("", "../Escape.app", "/tmp/Escape.app", ".hidden.app",
                     "bad\nname.app", "bad$name.app", "no-extension",
                     "a" * 117 + ".app"):
            with self.subTest(name=name):
                result = self.build(SURGE_CC_APP_NAME=name)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must be a basename", result.stderr)
                self.assertFalse(self.log.exists())
        self.assertFalse(self.dist.exists())

    def test_destination_created_during_build_is_not_overwritten_or_nested(self):
        output = self.dist / "Surge CC.app"
        result = self.build(BUILD_TEST_RACE=str(output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Output was not published", result.stderr)
        self.assertEqual((output / "keep.txt").read_text(), "concurrent owner")
        self.assertEqual(list(output.iterdir()), [output / "keep.txt"])
        self.assert_no_staging()

    def test_symlink_created_during_build_is_not_followed(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("unrelated")
        output = self.dist / "Surge CC.app"
        result = self.build(BUILD_TEST_RACE=str(output),
                            BUILD_TEST_RACE_LINK=str(outside))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(output.is_symlink())
        self.assertEqual(list(outside.iterdir()), [outside / "keep.txt"])
        self.assertEqual((outside / "keep.txt").read_text(), "unrelated")
        self.assert_no_staging()

    def test_failed_compilation_only_removes_its_temporary_stage(self):
        shared_old_stage = self.project / "build/Surge CC.app"
        shared_old_stage.mkdir(parents=True)
        (shared_old_stage / "keep.txt").write_text("old build")
        result = self.build(BUILD_TEST_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.dist / "Surge CC.app").exists())
        self.assertEqual((shared_old_stage / "keep.txt").read_text(), "old build")
        self.assert_no_staging()

    def test_each_build_uses_a_different_private_stage(self):
        first = self.build(SURGE_CC_APP_NAME="First.app")
        second = self.build(SURGE_CC_APP_NAME="Second.app")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        compiles = [call for call in calls if call[0] == "swiftc"]
        stages = [Path(call[call.index("-o") + 1]).parents[3] for call in compiles]
        self.assertNotEqual(stages[0], stages[1])
        self.assertTrue(all(stage.parent == self.dist for stage in stages))
        self.assert_no_staging()


if __name__ == "__main__":
    unittest.main()

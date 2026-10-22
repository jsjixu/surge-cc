"""Synthetic PNG imports only: no clipboard, actual user screenshots or network."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import types
import subprocess
import unittest
from unittest.mock import patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import pasted_images as images
from surge_cc.core import Blocked

NAME = "orca-paste-1792665408955-d83d74aa-82d3-48bb-ae09-557ecbd35da3.png"


def chunk(kind, payload=b""):
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff)


def png(width=1, height=1):
    return (images._SIGNATURE + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\0\xff\0\0\xff")) + chunk(b"IEND"))


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "home"
        self.source = self.root / "source"
        self.home.mkdir(mode=0o700)
        self.source.mkdir(mode=0o700)
        self.path = self.source / NAME
        self.path.write_bytes(png())
        self.path.chmod(0o600)
        self.raw = os.fsencode(self.path)
        self.importer = images.ImageImporter(self.home, self.source)
        self.addCleanup(self.importer.close)

    def imported(self):
        return Path(os.fsdecode(self.importer.import_path(self.raw)))

    def assertBlocked(self, action):
        with self.assertRaises(Blocked) as caught:
            action()
        self.assertEqual(str(caught.exception), images._ERROR)
        self.assertNotIn(str(self.path), str(caught.exception))

    def test_import_is_private_scoped_unchanged_and_persists_after_close(self):
        result = self.imported()
        self.assertEqual(result.parent.parent, self.home)
        self.assertEqual(result.read_bytes(), png())
        self.assertEqual(self.path.read_bytes(), png())
        self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(result.parent.stat().st_mode), 0o700)
        self.importer.close()
        self.assertEqual(result.read_bytes(), png())

    def test_constructor_and_matcher_allow_not_yet_created_home(self):
        new_home = self.root / "fresh"
        with images.ImageImporter(new_home, self.source) as importer:
            with patch.object(images.os, "stat", side_effect=AssertionError("matcher must not stat")):
                self.assertTrue(importer.matches_path(self.raw))
            self.assertFalse(new_home.exists())
            new_home.mkdir(mode=0o700)
            result = Path(os.fsdecode(importer.import_path(self.raw)))
            self.assertEqual(result.read_bytes(), png())

    def test_missing_home_blocks_without_creating_it(self):
        new_home = self.root / "missing"
        with images.ImageImporter(new_home, self.source) as importer:
            self.assertBlocked(lambda: importer.import_path(self.raw))
        self.assertFalse(new_home.exists())

    def test_default_temp_uses_os_confstr_and_not_environment(self):
        with patch.dict(os.environ, {"TMPDIR": "/not/the/source"}):
            with patch.object(images.os, "confstr", return_value=str(self.source)) as confstr:
                with images.ImageImporter(self.home) as importer:
                    self.assertTrue(importer.matches_path(self.raw))
                confstr.assert_called_once_with("CS_DARWIN_USER_TEMP_DIR")

    def test_python39_confstr_falls_back_to_fixed_getconf_without_environment(self):
        result = types.SimpleNamespace(stdout=os.fsencode(self.source) + b"\n")
        with patch.object(images.os, "confstr", side_effect=ValueError("unknown name")):
            with patch.object(images.subprocess, "run", return_value=result) as run:
                with images.ImageImporter(self.home) as importer:
                    self.assertTrue(importer.matches_path(self.raw))
                positional, options = run.call_args
                self.assertEqual(positional[0], ["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"])
                self.assertEqual(options["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                self.assertEqual(options["timeout"], 3)
                self.assertEqual(options["stdin"], subprocess.DEVNULL)

    def test_getconf_errors_or_unbounded_output_block_without_environment_fallback(self):
        failures = [subprocess.TimeoutExpired("getconf", 3), OSError("failed"),
                    types.SimpleNamespace(stdout=b"x" * 4097),
                    types.SimpleNamespace(stdout=b"/tmp\n/elsewhere\n"),
                    types.SimpleNamespace(stdout=b""), types.SimpleNamespace(stdout=b"relative\n")]
        with patch.dict(os.environ, {"TMPDIR": str(self.source)}):
            for failure in failures:
                with self.subTest(failure=repr(failure)):
                    with patch.object(images.os, "confstr", side_effect=ValueError("unknown name")):
                        options = ({"side_effect": failure} if isinstance(failure, BaseException)
                                   else {"return_value": failure})
                        with patch.object(images.subprocess, "run", **options):
                            self.assertBlocked(lambda: images.ImageImporter(self.home))

    def test_var_alias_of_private_var_source_is_accepted(self):
        if not str(self.source).startswith("/private/var/"):
            self.skipTest("macOS private/var temp alias unavailable")
        alias = self.raw[len(b"/private"):]
        self.assertTrue(self.importer.matches_path(alias))
        self.assertEqual(Path(os.fsdecode(self.importer.import_path(alias))).read_bytes(), png())

    def test_matcher_rejects_unexpected_paths_without_creating_files(self):
        invalid = [b"'" + self.raw + b"'", b'"' + self.raw + b'"', b" " + self.raw,
                   self.raw + b"\n", self.raw + b"\0", self.raw + b"/more",
                   self.raw.replace(b"orca-paste-", b"different-"), self.raw + b".jpg",
                   os.fsencode(self.source / "nested" / NAME),
                   os.fsencode(self.source / ".." / "source" / NAME),
                   os.fsencode(self.root / NAME), self.raw.decode(), None]
        for payload in invalid:
            with self.subTest(payload=repr(payload)):
                self.assertFalse(self.importer.matches_path(payload))
                self.assertBlocked(lambda: self.importer.import_path(payload))
        self.assertEqual(list(self.home.iterdir()), [])

    def test_missing_source_blocks(self):
        self.path.unlink()
        self.assertBlocked(self.imported)

    def test_source_symlink_blocks(self):
        target = self.source / "actual.png"
        self.path.rename(target)
        self.path.symlink_to(target)
        self.assertBlocked(self.imported)

    def test_source_hardlink_blocks(self):
        os.link(self.path, self.source / "another.png")
        self.assertBlocked(self.imported)

    def test_source_directory_and_fifo_block_without_hanging(self):
        self.path.unlink()
        self.path.mkdir()
        self.assertBlocked(self.imported)
        self.path.rmdir()
        os.mkfifo(self.path)
        self.assertBlocked(self.imported)

    def test_source_writable_by_others_blocks(self):
        for mode in (0o620, 0o602, 0o666):
            with self.subTest(mode=mode):
                self.path.chmod(mode)
                self.assertBlocked(self.imported)

    def test_source_owner_mismatch_blocks(self):
        real_fstat = images.os.fstat
        def fake(fd):
            result = real_fstat(fd)
            if stat.S_ISREG(result.st_mode):
                values = list(result)
                values[4] = os.getuid() + 100
                return os.stat_result(values)
            return result
        with patch.object(images.os, "fstat", side_effect=fake):
            self.assertBlocked(self.imported)

    def test_empty_and_oversized_source_block(self):
        self.path.write_bytes(b"")
        self.assertBlocked(self.imported)
        with self.path.open("wb") as file:
            file.truncate(images.MAX_IMAGE + 1)
        self.assertBlocked(self.imported)

    def test_source_root_replaced_after_constructor_blocks(self):
        self.source.rename(self.root / "old-source")
        self.source.mkdir(mode=0o700)
        (self.source / NAME).write_bytes(png())
        self.assertBlocked(self.imported)

    def test_source_ancestor_symlink_is_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.source, target_is_directory=True)
        self.assertBlocked(lambda: images.ImageImporter(self.home, alias))

    def test_source_root_permission_change_blocks(self):
        self.source.chmod(0o777)
        self.assertBlocked(self.imported)

    def test_source_replacement_during_read_blocks(self):
        real_read = images.os.read
        changed = False
        def mutate(fd, size):
            nonlocal changed
            data = real_read(fd, size)
            if data and not changed:
                changed = True
                self.path.rename(self.source / "original.png")
                self.path.write_bytes(png())
            return data
        with patch.object(images.os, "read", side_effect=mutate):
            self.assertBlocked(self.imported)
        self.assertEqual(list(self.home.iterdir()), [])

    def test_source_content_change_during_read_blocks(self):
        real_read = images.os.read
        changed = False
        def mutate(fd, size):
            nonlocal changed
            data = real_read(fd, size)
            if data and not changed:
                changed = True
                self.path.write_bytes(png(2, 1))
            return data
        with patch.object(images.os, "read", side_effect=mutate):
            self.assertBlocked(self.imported)

    def test_home_symlink_and_writable_permissions_block(self):
        actual = self.root / "actual-home"
        self.home.rename(actual)
        self.home.symlink_to(actual, target_is_directory=True)
        self.assertBlocked(self.imported)
        self.home.unlink()
        actual.rename(self.home)
        self.home.chmod(0o777)
        self.assertBlocked(self.imported)

    def test_home_replacement_between_imports_blocks(self):
        self.imported()
        self.home.rename(self.root / "old-home")
        self.home.mkdir(mode=0o700)
        self.assertBlocked(self.imported)

    def test_destination_folder_symlink_swap_blocks(self):
        result = self.imported()
        folder = result.parent
        folder.rename(self.home / "old-folder")
        folder.symlink_to(self.source, target_is_directory=True)
        self.assertBlocked(self.imported)
        self.assertEqual(set(p.name for p in self.source.iterdir()), {NAME})

    def test_destination_folder_permission_change_blocks(self):
        result = self.imported()
        result.parent.chmod(0o755)
        self.assertBlocked(self.imported)

    def test_destination_existing_filename_symlink_or_hardlink_blocks(self):
        first = self.imported()
        fixed = "a" * 32
        collision = first.parent / ("image-" + fixed + ".png")
        collision.symlink_to(self.path)
        with patch.object(images.secrets, "token_hex", return_value=fixed):
            self.assertBlocked(self.imported)
        collision.unlink()
        os.link(self.path, collision)
        with patch.object(images.secrets, "token_hex", return_value=fixed):
            self.assertBlocked(self.imported)
        self.assertEqual(self.path.read_bytes(), png())

    def test_destination_replaced_after_write_blocks_and_does_not_delete_replacement(self):
        real_fsync = images.os.fsync
        replacement = None
        def mutate(fd):
            nonlocal replacement
            real_fsync(fd)
            folder = self.home / self.importer._folder_name
            target = next(folder.glob("image-*.png"))
            target.rename(folder / "written.png")
            target.symlink_to(self.path)
            replacement = target
        with patch.object(images.os, "fsync", side_effect=mutate):
            self.assertBlocked(self.imported)
        self.assertTrue(replacement.is_symlink())
        self.assertEqual(self.path.read_bytes(), png())

    def test_destination_content_mutation_during_write_blocks(self):
        real_fsync = images.os.fsync
        def mutate(fd):
            real_fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b"not PNG!")
        with patch.object(images.os, "fsync", side_effect=mutate):
            self.assertBlocked(self.imported)
        self.assertEqual(list((self.home / self.importer._folder_name).iterdir()), [])

    def test_two_importers_and_concurrent_imports_never_overwrite(self):
        with images.ImageImporter(self.home, self.source) as second:
            with ThreadPoolExecutor(max_workers=4) as pool:
                paths = list(pool.map(lambda _: self.imported(), range(8)))
            extra = Path(os.fsdecode(second.import_path(self.raw)))
        self.assertEqual(len(set(paths)), 8)
        self.assertNotEqual(paths[0].parent, extra.parent)
        self.assertTrue(all(p.read_bytes() == png() for p in [*paths, extra]))

    def test_closed_importer_blocks(self):
        self.importer.close()
        self.assertBlocked(self.imported)

    def test_invalid_pngs_are_not_copied(self):
        valid = png()
        header = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
        invalid = [b"secret text", valid + b"trailer", valid[:-1],
                   valid[:20] + bytes([valid[20] ^ 1]) + valid[21:],
                   images._SIGNATURE + chunk(b"IEND"),
                   images._SIGNATURE + header + chunk(b"IEND"),
                   images._SIGNATURE + header + header + chunk(b"IDAT", b"x") + chunk(b"IEND"),
                   images._SIGNATURE + header + chunk(b"FAKE") + chunk(b"IDAT", b"x") + chunk(b"IEND"),
                   images._SIGNATURE + header + chunk(b"IDAT", b"x") + chunk(b"tEXt", b"abc") + chunk(b"IDAT", b"x") + chunk(b"IEND"),
                   png(0, 1), png(images.MAX_DIMENSION + 1, 1), png(20000, 20000)]
        for data in invalid:
            with self.subTest(length=len(data)):
                self.path.write_bytes(data)
                self.assertBlocked(self.imported)
        self.assertEqual(list(self.home.iterdir()), [])

    def test_png_chunk_budget_is_bounded(self):
        data = png()
        with patch.object(images, "MAX_CHUNKS", 2):
            self.assertBlocked(self.imported)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from context_sast.apk_loader import ApkLoader
from context_sast.apk_loader.loader import ApkIntegrityError


class ApkLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.apk = Path(self._temp.name) / "sample.apk"
        self.apk.write_bytes(b"original" * 4096)
        self.loader = ApkLoader()

    def test_load_records_digest_and_size(self) -> None:
        loaded = self.loader.load(self.apk)
        self.assertEqual(loaded.sha256, hashlib.sha256(self.apk.read_bytes()).hexdigest())
        self.assertEqual(loaded.size_bytes, self.apk.stat().st_size)

    def test_verify_accepts_an_untouched_file(self) -> None:
        loaded = self.loader.load(self.apk)
        self.loader.verify_unchanged(loaded)

    def test_verify_rejects_content_swapped_at_the_same_size(self) -> None:
        loaded = self.loader.load(self.apk)
        self.apk.write_bytes(b"swapped!" * 4096)
        with self.assertRaises(ApkIntegrityError):
            self.loader.verify_unchanged(loaded)

    def test_verify_rejects_a_file_removed_mid_scan(self) -> None:
        loaded = self.loader.load(self.apk)
        self.apk.unlink()
        with self.assertRaises(ApkIntegrityError):
            self.loader.verify_unchanged(loaded)

    def test_load_rejects_a_non_apk_suffix(self) -> None:
        other = Path(self._temp.name) / "sample.zip"
        other.write_bytes(b"x")
        with self.assertRaises(ValueError):
            self.loader.load(other)


if __name__ == "__main__":
    unittest.main()

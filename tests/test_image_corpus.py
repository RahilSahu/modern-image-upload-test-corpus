import csv
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from image_corpus import MARKER, SAMPLES, build_corpus

FORMATS = ["heic", "heif", "avif", "jxl", "webp"]
FORBIDDEN = [b"system(", b"exec(", b"/bin/sh", b"cmd.exe", b"$_GET", b"shellcode", b"\\x90\\x90"]


class SampleStructureTests(unittest.TestCase):
    def test_webp_is_a_real_riff(self):
        data = SAMPLES["webp"]
        self.assertEqual(data[0:4], b"RIFF")
        self.assertEqual(data[8:12], b"WEBP")
        riff_size = struct.unpack("<I", data[4:8])[0]
        self.assertEqual(riff_size, len(data) - 8)

    def test_isobmff_brands(self):
        for ext, brand in (("heic", b"heic"), ("heif", b"mif1"), ("avif", b"avif")):
            data = SAMPLES[ext]
            self.assertEqual(data[4:8], b"ftyp")
            self.assertEqual(data[8:12], brand)

    def test_jxl_signature(self):
        self.assertEqual(SAMPLES["jxl"][0:2], b"\xff\x0a")


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)
        self.manifest = build_corpus(self.out, size_mb=0.05)

    def tearDown(self):
        self.tmp.cleanup()

    def test_manifest_covers_all_formats_and_variants(self):
        self.assertEqual(len(self.manifest), len(FORMATS) * 8)
        with open(self.out / "manifest.csv", newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), len(self.manifest))
        for fmt in FORMATS:
            self.assertTrue(any(r["format"] == fmt for r in rows))

    def test_all_manifest_files_exist(self):
        for row in self.manifest:
            self.assertTrue((self.out / row["filename"]).is_file(), row["filename"])

    def test_metadata_variants_carry_the_marker(self):
        for fmt in FORMATS:
            data = (self.out / f"metadata_marker.{fmt}").read_bytes()
            self.assertIn(MARKER.encode(), data)

    def test_corrupt_length_claims_huge_size(self):
        data = (self.out / "corrupt_length.heic").read_bytes()
        claimed = struct.unpack(">I", data[0:4])[0]
        self.assertEqual(claimed, 500_000_000)
        self.assertLess(len(data), 1000)

    def test_truncated_is_shorter(self):
        for fmt in FORMATS:
            truncated = (self.out / f"truncated.{fmt}").read_bytes()
            self.assertLess(len(truncated), len(SAMPLES[fmt]))

    def test_mismatch_files_are_really_png(self):
        data = (self.out / "mismatch_png_as.heic").read_bytes()
        self.assertTrue(data.startswith(b"\x89PNG"))

    def test_no_forbidden_content_anywhere(self):
        for path in self.out.iterdir():
            if path.is_file():
                content = path.read_bytes()
                for needle in FORBIDDEN:
                    self.assertNotIn(needle, content, f"{needle} found in {path.name}")


if __name__ == "__main__":
    unittest.main()

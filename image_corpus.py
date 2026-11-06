#!/usr/bin/env python3
"""Modern image format upload test corpus generator.

New image formats (HEIC, HEIF, AVIF, JPEG XL, WebP) reach production
upload handlers long before the handlers, and the image libraries
behind them, are ready. Files in these formats are parsed by complex
native libraries (libheif, libavif, libjxl, libwebp), and the
recurring production failures are boring but serious: the upload
crashes the worker, the parser hangs or eats memory, the file is
misidentified and served with the wrong content type, or metadata and
trailing data sail straight through a validator that only checked the
extension.

This tool generates a corpus of HARMLESS test files for those cases:

- Minimal sample files for heic, heif, avif, jxl and webp
- Metadata marker variants (a fixed test string in a metadata box or
  EXIF chunk): does the pipeline strip or pass metadata through?
- Trailing data variants: bytes after the image proper, the classic
  polyglot and content sniffing test
- Header polyglot variants: image header followed by an HTML marker,
  to catch handlers that sniff content as HTML
- Truncated files: the parser must fail cleanly, never crash a worker
- Corrupt length variants: a box or chunk size field claims far more
  data than the file holds, which a safe parser must reject by bounds
  checking, not by reading until it dies
- Cross-format mismatches: real bytes of one format wearing another
  format's extension
- Padded large variants: size limit behaviour

Every payload is a marker, a structural inconsistency, or a clean
sample. There are deliberately NO code execution payloads, no
shellcode, and no crafted memory corruption triggers: the correct
defence against parser vulnerabilities is patched libraries,
sandboxed decoding and re-encoding, and this corpus tests whether a
pipeline survives bad files, which is the part you can verify from
outside. Marker used everywhere: IMAGE_CORPUS_TEST_MARKER.

Zero dependencies: Python 3.9+ standard library only.
"""

from __future__ import annotations

import argparse
import base64
import csv
import struct
import sys
from pathlib import Path

MARKER = "IMAGE_CORPUS_TEST_MARKER"

# A well-known minimal valid 1x1 lossless WebP.
WEBP_1X1 = base64.b64decode(
    "UklGRiIAAABXRUJQVlA4IBYAAAAwAQCdASoBAAEADsD+JaQAA3AAAAAA"
)


def box(box_type: bytes, payload: bytes) -> bytes:
    """One ISOBMFF box: size, type, payload."""
    return struct.pack(">I", len(payload) + 8) + box_type + payload


def isobmff_sample(major_brand: bytes, compatible: list[bytes]) -> bytes:
    """A minimal header-valid ISOBMFF sample for HEIF family formats.

    ftyp with the right brands, a free box, and an empty mdat. Enough
    for upload handlers and sniffers to identify and route the format,
    and for parser front doors to accept or reject the structure.
    """
    ftyp = box(b"ftyp", major_brand + struct.pack(">I", 0) + b"".join(compatible))
    free = box(b"free", b"")
    mdat = box(b"mdat", b"")
    return ftyp + free + mdat


def jxl_sample() -> bytes:
    """Minimal JPEG XL codestream signature plus header bytes."""
    # Codestream signature 0xFF0A, followed by a minimal image header
    # (small image, default codestream fields). Header-valid sample.
    return bytes([0xFF, 0x0A, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00])


SAMPLES: dict[str, bytes] = {
    "heic": isobmff_sample(b"heic", [b"heic", b"mif1", b"msf1"]),
    "heif": isobmff_sample(b"mif1", [b"mif1", b"heif"]),
    "avif": isobmff_sample(b"avif", [b"avif", b"avis", b"mif1"]),
    "jxl": jxl_sample(),
    "webp": WEBP_1X1,
}

# A real PNG header and start, used for cross-format mismatch files.
PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg=="
)


def webp_with_exif_marker() -> bytes:
    """Insert an EXIF chunk carrying the marker into the WebP RIFF."""
    body = WEBP_1X1[12:]  # everything after 'WEBP'
    exif_payload = b"II*\x00\x08\x00\x00\x00\x00\x00\x00\x00" + MARKER.encode()
    if len(exif_payload) % 2:
        exif_payload += b"\x00"
    exif_chunk = b"EXIF" + struct.pack("<I", len(exif_payload)) + exif_payload
    new_body = body + exif_chunk
    return b"RIFF" + struct.pack("<I", len(new_body) + 4) + b"WEBP" + new_body


def with_metadata_marker(ext: str, data: bytes) -> bytes:
    if ext == "webp":
        return webp_with_exif_marker()
    if ext == "jxl":
        # JPEG XL container: signature box + an Exif box with the marker.
        sig_box = struct.pack(">I", 12) + b"JXL " + bytes([0x0D, 0x0A, 0x87, 0x0A])
        exif_box = box(b"Exif", b"\x00\x00\x00\x00" + MARKER.encode())
        return sig_box + exif_box + data
    # ISOBMFF family: append a udta (user data) box with the marker.
    return data + box(b"udta", MARKER.encode())


def corrupt_length(ext: str, data: bytes) -> bytes:
    """Make the first length field claim far more than the file holds."""
    data = bytearray(data)
    if ext == "webp":
        # RIFF size at offset 4 claims 500 MB.
        data[4:8] = struct.pack("<I", 500_000_000)
    elif ext == "jxl":
        # Append a box whose size is absurd for the container form.
        return bytes(data) + struct.pack(">I", 0xFFFFFFF0) + b"jxll"
    else:
        # First box (ftyp) size claims 500 MB.
        data[0:4] = struct.pack(">I", 500_000_000)
    return bytes(data)


def padded_large(ext: str, data: bytes, size_mb: float) -> bytes:
    target = int(size_mb * 1024 * 1024)
    if len(data) >= target:
        return data
    padding_needed = target - len(data)
    if ext in ("heic", "heif", "avif"):
        # A proper free box of padding keeps the structure parseable.
        if padding_needed >= 8:
            return data + box(b"free", b"\x00" * (padding_needed - 8))
    return data + b"\x00" * padding_needed


def build_corpus(output_dir: Path, size_mb: float = 2.0) -> list[dict]:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []

    def add(filename: str, data: bytes, fmt: str, technique: str, expected: str) -> None:
        (output_dir / filename).write_bytes(data)
        manifest.append({"filename": filename, "format": fmt,
                         "technique": technique, "expected_secure_behavior": expected})

    for ext, sample in SAMPLES.items():
        add(f"sample.{ext}", sample, ext, "Minimal sample file",
            "Accept if the format is supported, identify it from its bytes (not the extension), and re-encode or store it safely.")
        add(f"metadata_marker.{ext}", with_metadata_marker(ext, sample), ext,
            "Test marker embedded in metadata (EXIF chunk, udta or Exif box)",
            "Strip or sanitise metadata on upload, or make a deliberate documented decision to keep it. Markers and private EXIF data must not pass through by accident.")
        add(f"trailing_data.{ext}", sample + b"\n" + MARKER.encode(), ext,
            "Marker bytes appended after the image data",
            "Reject, truncate safely, or re-encode. Trailing data is the classic polyglot hiding place and must not reach browsers as sniffable content.")
        add(f"header_polyglot.{ext}", sample[:16] + b"<html><body>" + MARKER.encode() + b"</body></html>", ext,
            "Image header followed by an HTML marker",
            "Never serve uploads in a way that lets a browser sniff them as HTML. Serve with the correct image content type, nosniff, or as an attachment from a separate domain.")
        add(f"truncated.{ext}", sample[: max(4, len(sample) // 3)], ext,
            "File cut off mid-structure",
            "Reject with a clean error. The parser must not crash the worker, hang, or produce a partial image.")
        add(f"corrupt_length.{ext}", corrupt_length(ext, sample), ext,
            "Length field claims about 500 MB in a file of a few dozen bytes",
            "Reject by bounds checking before allocating or reading. A parser that trusts length fields is one malformed file away from memory exhaustion.")
        add(f"large_padded.{ext}", padded_large(ext, sample, size_mb), ext,
            f"Valid header padded to about {size_mb} MB",
            "Enforce the documented size limit and reject oversized uploads cleanly, without storing partial files.")
        other = "png" if ext != "png" else "webp"
        add(f"mismatch_png_as.{ext}", PNG_BYTES, ext,
            "Real PNG bytes wearing a different format's extension",
            "Identify files from magic bytes and full structure, never from the extension alone. Reject or treat as what it actually is.")

    with open(output_dir / "manifest.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["filename", "format", "technique", "expected_secure_behavior"])
        writer.writeheader()
        writer.writerows(manifest)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a harmless test corpus for modern image format uploads (HEIC, HEIF, AVIF, JXL, WebP).")
    parser.add_argument("-o", "--output-dir", default="image-test-corpus")
    parser.add_argument("--size-mb", type=float, default=2.0,
                        help="Target size for the large padded variants (default 2)")
    args = parser.parse_args(argv)

    manifest = build_corpus(Path(args.output_dir), size_mb=args.size_mb)
    print(f"Generated {len(manifest)} test files plus manifest.csv in {args.output_dir}:")
    for row in manifest:
        print(f"  {row['filename']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Modern Image Upload Test Corpus

Test files for the image formats your upload handler was not ready
for: **HEIC, HEIF, AVIF, JPEG XL (JXL) and WebP**.

These formats are decoded by complex native libraries (libheif,
libavif, libjxl, libwebp) inside upload pipelines. The production
failures that follow are predictable: a malformed file crashes the
worker, a length field makes the parser try to allocate half a
gigabyte, metadata sails through unstripped, a "photo" gets served
back as sniffable HTML. This tool generates a harmless corpus that
tests every one of those behaviours, for all five formats, in one run.

## What it generates

40 files plus a `manifest.csv` (8 variants per format):

| Variant | What it tests |
| --- | --- |
| `sample.<ext>` | A minimal format-correct sample (the WebP is a real decodable 1x1 image, the ISOBMFF samples carry the correct ftyp brands) |
| `metadata_marker.<ext>` | A fixed test marker in an EXIF chunk, udta box or Exif box: is metadata stripped, kept by decision, or passed through by accident? |
| `trailing_data.<ext>` | Marker bytes after the image proper: the polyglot hiding place |
| `header_polyglot.<ext>` | Image header followed by an HTML marker: content sniffing and serving checks |
| `truncated.<ext>` | File cut mid-structure: the parser must fail cleanly, never crash a worker |
| `corrupt_length.<ext>` | A box, chunk or RIFF length field claiming about 500 MB in a tiny file: bounds checking, not blind trust |
| `large_padded.<ext>` | A structurally fine file padded to size: upload size limits |
| `mismatch_png_as.<ext>` | Real PNG bytes wearing another format's extension: magic byte validation |

The manifest states, for every file, what a secure upload pipeline
should do with it, so the corpus doubles as an acceptance test for
your handler.

## Usage

```bash
python3 image_corpus.py -o image-test-corpus
python3 image_corpus.py -o image-test-corpus --size-mb 5
```

## What this tool deliberately does not do

There are no code execution payloads, no shellcode, and no crafted
memory corruption triggers in this corpus, and there never will be.
Exploiting parser bugs is a different activity from testing whether
your pipeline survives bad files. The defences that actually work
against image parser vulnerabilities are:

- Keep libheif, libavif, libjxl and libwebp patched, they have all
  had serious CVEs and will have more
- Decode uploads in a sandbox or a separate low-privilege worker
- Re-encode every accepted image and serve only the re-encoded copy
- Validate structure and size limits before the parser ever runs

This corpus verifies the last two, and tells you quickly whether the
first two are saving you when a bad file arrives.

## Requirements

Python 3.9 or newer. No packages to install.

## Tests

10 offline unit tests validate the sample structures (RIFF sizes,
ftyp brands, JXL signature), the manifest, and that no generated file
contains executable payload content:

```bash
python3 -m unittest discover -s tests
```

## Responsible use

Only upload these files to systems you own or are authorised to test.

## License

MIT, see LICENSE.

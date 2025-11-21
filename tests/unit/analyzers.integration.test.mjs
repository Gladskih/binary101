"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectBinaryType, parseForUi } from "../../analyzers/index.js";
import { DOMParser as XmlDomParser } from "xmldom";
import {
  createElfFile,
  createFb2File,
  createGifFile,
  createJpegFile,
  createMp3File,
  createPdfFile,
  createPngFile,
  createPngWithIhdr,
  createPeFile,
  createSevenZipFile,
  createTarFile,
  createWebpFile,
  createZipFile
} from "../fixtures/sample-files.mjs";
import { MockFile } from "../helpers/mock-file.mjs";

const textEncoder = new TextEncoder();
class TestDomParser extends XmlDomParser {
  parseFromString(text, type) {
    const doc = super.parseFromString(text, type);
    if (!doc.querySelector) {
      doc.querySelector = selector => {
        const tagName = selector.replace(/[^a-zA-Z0-9:-]/g, "");
        const matches = doc.getElementsByTagName(tagName);
        return matches && matches.length ? matches[0] : null;
      };
    }
    return doc;
  }
}

global.DOMParser = TestDomParser;

const assertParsed = async (file, expectedAnalyzer, checks = () => {}) => {
  const { analyzer, parsed } = await parseForUi(file);
  assert.strictEqual(analyzer, expectedAnalyzer);
  assert.ok(parsed, `Expected parsed data for ${expectedAnalyzer}`);
  checks(parsed);
};

test("detectBinaryType recognizes common binary formats", async () => {
  const detections = await Promise.all([
    detectBinaryType(createPngWithIhdr()),
    detectBinaryType(createGifFile()),
    detectBinaryType(createJpegFile()),
    detectBinaryType(createWebpFile()),
    detectBinaryType(createPdfFile()),
    detectBinaryType(createTarFile()),
    detectBinaryType(createSevenZipFile()),
    detectBinaryType(new MockFile(textEncoder.encode("plain text sample"), "note.txt", "text/plain"))
  ]);

  assert.match(detections[0], /^PNG image/);
  assert.match(detections[1], /^GIF image/);
  assert.match(detections[2], /^JPEG image/);
  assert.match(detections[3], /^WebP image/);
  assert.match(detections[4], /^PDF document/);
  assert.match(detections[5], /tar archive/i);
  assert.match(detections[6], /^7z archive v0\.4/);
  assert.strictEqual(detections[7], "Text file");
});

test("parseForUi parses and reports PNG layout", async () => {
  await assertParsed(createPngFile(), "png", png => {
    assert.strictEqual(png.ihdr.width, 1);
    assert.strictEqual(png.ihdr.height, 1);
    assert.ok(Array.isArray(png.chunks));
  });
});

test("parseForUi parses PE headers and sections", async () => {
  await assertParsed(createPeFile(), "pe", pe => {
    assert.strictEqual(pe.coff.NumberOfSections, 1);
    assert.ok(pe.sections);
    assert.ok(pe.coverage);
  });
});

test("parseForUi parses GIF frames and trailer", async () => {
  await assertParsed(createGifFile(), "gif", gif => {
    assert.ok(gif.hasTrailer);
    assert.ok(Array.isArray(gif.frames));
    assert.strictEqual(gif.frames.length >= 0, true);
  });
});

test("parseForUi parses JPEG metadata", async () => {
  await assertParsed(createJpegFile(), "jpeg", jpeg => {
    assert.ok(Array.isArray(jpeg.segments));
    assert.ok(jpeg.segmentCount >= 1);
  });
});

test("parseForUi parses WebP chunks", async () => {
  await assertParsed(createWebpFile(), "webp", webp => {
    assert.ok(Array.isArray(webp.chunks));
  });
});

test("parseForUi parses FB2 XML", async () => {
  await assertParsed(createFb2File(), "fb2", fb2 => {
    assert.ok(fb2.title);
    assert.ok(fb2.bodyCount >= 0);
  });
});

test("parseForUi parses PDF cross-reference data", async () => {
  await assertParsed(createPdfFile(), "pdf", pdf => {
    assert.ok(pdf.header);
    assert.ok(pdf.xref);
    assert.ok(Array.isArray(pdf.issues));
  });
});

test("parseForUi parses MP3 frames and summary", async () => {
  await assertParsed(createMp3File(), "mp3", mp3 => {
    assert.strictEqual(mp3.isMp3, true);
    assert.ok(mp3.mpeg.firstFrame);
    assert.ok(mp3.summary);
  });
});

test("parseForUi parses TAR headers", async () => {
  await assertParsed(createTarFile(), "tar", tar => {
    assert.strictEqual(tar.isTar, true);
    assert.ok(Array.isArray(tar.entries));
    assert.ok(tar.entries[0]);
  });
});

test("parseForUi parses ZIP EOCD", async () => {
  await assertParsed(createZipFile(), "zip", zip => {
    assert.ok(zip.eocd);
    assert.ok(zip.centralDirectory);
  });
});

test("parseForUi parses ELF header and sections", async () => {
  await assertParsed(createElfFile(), "elf", elf => {
    assert.strictEqual(elf.ident.className, "ELF64");
    assert.ok(Array.isArray(elf.sections));
  });
});

test("parseForUi parses 7z start header even when next header is unknown", async () => {
  await assertParsed(createSevenZipFile(), "sevenZip", sevenZip => {
    assert.strictEqual(sevenZip.is7z, true);
    assert.ok(Array.isArray(sevenZip.issues));
    assert.ok(sevenZip.nextHeader);
  });
});

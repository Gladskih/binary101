"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectBinaryType, parseForUi } from "../../analyzers/index.js";
import { DOMParser as XmlDomParser } from "@xmldom/xmldom";
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
  createZipFile,
  createRar4File,
  createRar5File,
  createDosMzExe,
  createLnkFile
} from "../fixtures/sample-files.js";
import { MockFile } from "../helpers/mock-file.js";

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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const assertParsed = async (file: MockFile, expectedAnalyzer: string, checks: (parsed: any) => void = () => {}) => {
  const { analyzer, parsed } = await parseForUi(file);
  assert.strictEqual(analyzer, expectedAnalyzer);
  assert.ok(parsed, `Expected parsed data for ${expectedAnalyzer}`);
  checks(parsed);
};

void test("detectBinaryType recognizes common binary formats", async () => {
  const detections = await Promise.all([
    detectBinaryType(createPngWithIhdr()),
    detectBinaryType(createGifFile()),
    detectBinaryType(createJpegFile()),
    detectBinaryType(createWebpFile()),
    detectBinaryType(createPdfFile()),
    detectBinaryType(createTarFile()),
    detectBinaryType(createSevenZipFile()),
    detectBinaryType(createRar5File()),
    detectBinaryType(createLnkFile()),
    detectBinaryType(new MockFile(textEncoder.encode("plain text sample"), "note.txt", "text/plain"))
  ]);

  assert.match(detections[0], /^PNG image/);
  assert.match(detections[1], /^GIF image/);
  assert.match(detections[2], /^JPEG image/);
  assert.match(detections[3], /^WebP image/);
  assert.match(detections[4], /^PDF document/);
  assert.match(detections[5], /tar archive/i);
  assert.match(detections[6], /^7z archive v0\.4/);
  assert.match(detections[7], /^RAR archive/);
  assert.strictEqual(detections[8], "Windows shortcut (.lnk)");
  assert.strictEqual(detections[9], "Text file");
});

void test("detectBinaryType distinguishes DOS MZ executables from PE", async () => {
  const mzFile = createDosMzExe();
  const detection = await detectBinaryType(mzFile);
  assert.strictEqual(detection, "MS-DOS MZ executable");
  const parsed = await parseForUi(mzFile);
  assert.strictEqual(parsed.analyzer, "mz");
  assert.ok(parsed.parsed);
  assert.strictEqual(parsed.parsed.header.e_magic, "MZ");
  assert.ok(Array.isArray(parsed.parsed.stubStrings));
  assert.ok(parsed.parsed.stubStrings.length >= 1);
});

void test("parseForUi parses and reports PNG layout", async () => {
  await assertParsed(createPngFile(), "png", png => {
    assert.strictEqual(png.ihdr.width, 1);
    assert.strictEqual(png.ihdr.height, 1);
    assert.ok(Array.isArray(png.chunks));
  });
});

void test("parseForUi parses PE headers and sections", async () => {
  await assertParsed(createPeFile(), "pe", pe => {
    assert.strictEqual(pe.coff.NumberOfSections, 1);
    assert.ok(pe.sections);
    assert.ok(pe.coverage);
  });
});

void test("parseForUi parses GIF frames and trailer", async () => {
  await assertParsed(createGifFile(), "gif", gif => {
    assert.ok(gif.hasTrailer);
    assert.ok(Array.isArray(gif.frames));
    assert.strictEqual(gif.frames.length >= 0, true);
  });
});

void test("parseForUi parses JPEG metadata", async () => {
  await assertParsed(createJpegFile(), "jpeg", jpeg => {
    assert.ok(Array.isArray(jpeg.segments));
    assert.ok(jpeg.segmentCount >= 1);
  });
});

void test("parseForUi parses WebP chunks", async () => {
  await assertParsed(createWebpFile(), "webp", webp => {
    assert.ok(Array.isArray(webp.chunks));
  });
});

void test("parseForUi parses FB2 XML", async () => {
  await assertParsed(createFb2File(), "fb2", fb2 => {
    assert.ok(fb2.title);
    assert.ok(fb2.bodyCount >= 0);
  });
});

void test("parseForUi parses PDF cross-reference data", async () => {
  await assertParsed(createPdfFile(), "pdf", pdf => {
    assert.ok(pdf.header);
    assert.ok(pdf.xref);
    assert.ok(Array.isArray(pdf.issues));
  });
});

void test("parseForUi parses Windows shortcuts", async () => {
  await assertParsed(createLnkFile(), "lnk", lnk => {
    assert.strictEqual(lnk.linkInfo.localBasePath, "C:\\Program Files\\Example");
    assert.strictEqual(lnk.stringData.relativePath, ".\\Example\\app.exe");
    assert.ok(Array.isArray(lnk.extraData.blocks));
    const propertyStore = lnk.extraData.blocks.find(block => block.signature === 0xa0000009);
    assert.ok(propertyStore?.parsed?.storages?.length);
  });
});

void test("parseForUi parses MP3 frames and summary", async () => {
  await assertParsed(createMp3File(), "mp3", mp3 => {
    assert.strictEqual(mp3.isMp3, true);
    assert.ok(mp3.mpeg.firstFrame);
    assert.ok(mp3.summary);
  });
});

void test("parseForUi parses TAR headers", async () => {
  await assertParsed(createTarFile(), "tar", tar => {
    assert.strictEqual(tar.isTar, true);
    assert.ok(Array.isArray(tar.entries));
    assert.ok(tar.entries[0]);
  });
});

void test("parseForUi parses RAR v4 and v5 headers", async () => {
  await assertParsed(createRar4File(), "rar", rar => {
    assert.strictEqual(rar.version, 4);
    assert.ok(rar.entries.length >= 1);
  });
  await assertParsed(createRar5File(), "rar", rar => {
    assert.strictEqual(rar.version, 5);
    assert.ok(rar.entries.length >= 1);
  });
});

void test("parseForUi parses ZIP EOCD", async () => {
  await assertParsed(createZipFile(), "zip", zip => {
    assert.ok(zip.eocd);
    assert.ok(zip.centralDirectory);
  });
});

void test("parseForUi parses ELF header and sections", async () => {
  await assertParsed(createElfFile(), "elf", elf => {
    assert.strictEqual(elf.ident.className, "ELF64");
    assert.ok(Array.isArray(elf.sections));
  });
});

void test("parseForUi parses 7z start header even when next header is unknown", async () => {
  await assertParsed(createSevenZipFile(), "sevenZip", sevenZip => {
    assert.strictEqual(sevenZip.is7z, true);
    assert.ok(Array.isArray(sevenZip.issues));
    assert.ok(sevenZip.nextHeader);
  });
});

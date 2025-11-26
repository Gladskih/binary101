"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectBinaryType } from "../../analyzers/index.js";
import { MockFile } from "../helpers/mock-file.js";
import { createMp3File } from "../fixtures/sample-files.js";

const fromAscii = text => new Uint8Array(Buffer.from(text, "ascii"));

void test("detectBinaryType refines ZIP-based document labels", async () => {
  const zipSignature = [0x50, 0x4b, 0x03, 0x04];
  const docxPayload = "[Content_Types].xml word/document.xml";
  const bytes = new Uint8Array(zipSignature.length + docxPayload.length);
  bytes.set(zipSignature, 0);
  bytes.set(fromAscii(docxPayload), zipSignature.length);
  const label = await detectBinaryType(new MockFile(bytes, "docx-like.zip", "application/zip"));
  assert.strictEqual(label, "Microsoft Word document (DOCX)");

  const apkPayload = "[Content_Types].xml META-INF/MANIFEST.MF AndroidManifest.xml classes.dex";
  const apkBytes = new Uint8Array(zipSignature.length + apkPayload.length);
  apkBytes.set(zipSignature, 0);
  apkBytes.set(fromAscii(apkPayload), zipSignature.length);
  const apkLabel = await detectBinaryType(new MockFile(apkBytes, "sample.apk", "application/zip"));
  assert.strictEqual(apkLabel, "Android application package (APK)");
});

void test("detectBinaryType refines Compound File formats", async () => {
  const compoundMagic = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
  const workbook = "Workbook";
  const bytes = new Uint8Array(compoundMagic.length + workbook.length);
  bytes.set(compoundMagic, 0);
  bytes.set(fromAscii(workbook), compoundMagic.length);
  const label = await detectBinaryType(new MockFile(bytes, "sample.xls", "application/octet-stream"));
  assert.strictEqual(label, "Microsoft Excel binary workbook (XLS)");
});

void test("detectBinaryType reports EOCD-only ZIPs and PDF versions", async () => {
  const eocd = new Uint8Array(32).fill(0);
  eocd.set([0x50, 0x4b, 0x05, 0x06], eocd.length - 22);
  const zipLabel = await detectBinaryType(new MockFile(eocd, "eocd.zip", "application/zip"));
  assert.strictEqual(zipLabel, "ZIP archive");

  const pdfBytes = Buffer.from("%PDF-1.5\n", "ascii");
  const pdfLabel = await detectBinaryType(new MockFile(new Uint8Array(pdfBytes), "v15.pdf", "application/pdf"));
  assert.strictEqual(pdfLabel, "PDF document (v1.5)");
});

void test("detectBinaryType refines additional ZIP-based formats", async () => {
  const zipSignature = [0x50, 0x4b, 0x03, 0x04];
  const cases = [
    { marker: "[Content_Types].xml xl/workbook.xml", expected: "Microsoft Excel workbook (XLSX)" },
    { marker: "[Content_Types].xml ppt/presentation.xml", expected: "Microsoft PowerPoint presentation (PPTX)" },
    { marker: "application/vnd.oasis.opendocument.text", expected: "OpenDocument text document (ODT)" },
    { marker: "application/vnd.oasis.opendocument.spreadsheet", expected: "OpenDocument spreadsheet (ODS)" },
    { marker: "application/vnd.oasis.opendocument.presentation", expected: "OpenDocument presentation (ODP)" },
    { marker: "application/epub+zip", expected: "EPUB e-book" },
    { marker: "extension.vsixmanifest", expected: "Visual Studio extension package (VSIX)" },
    { marker: "META-INF/MANIFEST.MF", expected: "Java archive (JAR/WAR/EAR/JMOD)" },
    { marker: "FixedDocumentSequence.fdseq", expected: "XPS document" },
    { marker: "example.fb2 inside archive", expected: "FictionBook e-book inside ZIP (FB2)" }
  ];

  for (const { marker, expected } of cases) {
    const bytes = new Uint8Array(zipSignature.length + marker.length);
    bytes.set(zipSignature, 0);
    bytes.set(fromAscii(marker), zipSignature.length);
    const label = await detectBinaryType(new MockFile(bytes, "zip-derived.bin", "application/zip"));
    assert.strictEqual(label, expected);
  }
});

void test("detectBinaryType refines compound formats beyond Excel", async () => {
  const magic = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
  const fixtures = [
    { suffix: "PowerPoint Document", expected: "Microsoft PowerPoint binary document (PPT)" },
    { suffix: "WordDocument", expected: "Microsoft Word binary document (DOC)" },
    { suffix: "MSISummaryInformation", expected: "Windows Installer package (MSI)" }
  ];

  for (const fixture of fixtures) {
    const bytes = new Uint8Array(magic.length + fixture.suffix.length);
    bytes.set(magic, 0);
    bytes.set(fromAscii(fixture.suffix), magic.length);
    const label = await detectBinaryType(new MockFile(bytes, "compound.bin", "application/octet-stream"));
    assert.strictEqual(label, fixture.expected);
  }
});

void test("detectBinaryType recognises ELF and Mach-O executables", async () => {
  const elf = new Uint8Array(0x20).fill(0);
  elf.set([0x7f, 0x45, 0x4c, 0x46], 0);
  elf[4] = 2; // 64-bit
  elf[5] = 1; // little endian
  const elfView = new DataView(elf.buffer);
  elfView.setUint16(0x10, 2, true); // executable
  elfView.setUint16(0x12, 0x3e, true); // x86-64
  const elfLabel = await detectBinaryType(new MockFile(elf, "elf.bin", "application/octet-stream"));
  assert.strictEqual(elfLabel, "ELF 64-bit LSB executable, x86-64");

  const macho64 = new Uint8Array([0xfe, 0xed, 0xfa, 0xcf]);
  const machoLabel = await detectBinaryType(new MockFile(macho64, "macho", "application/octet-stream"));
  assert.strictEqual(machoLabel, "Mach-O 64-bit");
});

void test("detectBinaryType recognises MP3 streams even when frames are not at offset 0", async () => {
  const base = createMp3File();
  const prefixed = new Uint8Array(base.data.length + 16);
  prefixed.set(base.data, 16);
  const file = new MockFile(prefixed, "prefixed.mp3", "audio/mpeg");
  const label = await detectBinaryType(file);
  assert.strictEqual(label, "MPEG Version 1, Layer III, 128 kbps, 44100 Hz, Stereo");
});

void test("detectBinaryType reports MP3 for minimal single-frame files", async () => {
  const full = createMp3File();
  const singleFrame = full.data.slice(0, full.data.length / 2);
  const label = await detectBinaryType(new MockFile(singleFrame, "single-frame.mp3", "audio/mpeg"));
  assert.strictEqual(label, "MPEG Version 1, Layer III, 128 kbps, 44100 Hz, Stereo");
});

void test("detectBinaryType rejects MP3 label when second frame is invalid", async () => {
  const full = createMp3File();
  const firstFrameLength = full.data.length / 2;
  const damaged = new Uint8Array(firstFrameLength + 16);
  damaged.set(full.data.slice(0, firstFrameLength), 0);
  // Add some junk after the first frame to force a bad second header
  damaged.fill(0, firstFrameLength);
  const label = await detectBinaryType(new MockFile(damaged, "damaged.mp3", "audio/mpeg"));
  assert.strictEqual(label, "Unknown binary type");
});

void test("detectBinaryType recognises animated cursors (ANI)", async () => {
  const bytes = new Uint8Array([
    0x52, 0x49, 0x46, 0x46, // "RIFF"
    0x24, 0x00, 0x00, 0x00, // size placeholder
    0x41, 0x43, 0x4f, 0x4e  // "ACON"
  ]);
  const label = await detectBinaryType(new MockFile(bytes, "aero_busy.ani", "application/octet-stream"));
  assert.strictEqual(label, "Windows animated cursor (ANI)");
});

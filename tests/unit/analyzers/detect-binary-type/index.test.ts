"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectBinaryType } from "../../../../analyzers/index.js";
import { IMAGE_FILE_MACHINE_I386 } from "../../../../analyzers/coff/machine.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createMp3File } from "../../../fixtures/audio-sample-files.js";
import { createMp4File } from "../../../fixtures/mp4-fixtures.js";
import { createMinimalJavaClassBytes } from "../../../fixtures/java-class-fixtures.js";
import { createTruncatedFatMachOBytes } from "../../../fixtures/macho-fixtures.js";
import { createWebmFile } from "../../../fixtures/webm-base-fixtures.js";
import { createFlacFile } from "../../../fixtures/flac-fixtures.js";
import {
  createSqliteFile,
  createSqliteWalIndexSharedMemoryFile
} from "../../../fixtures/sqlite-fixtures.js";
import { createSampleAsfFile } from "../../../fixtures/asf-fixtures.js";
import { createMachOFile, createMachOUniversalFile } from "../../../fixtures/macho-fixtures.js";
import { createPeFile, createPePlusFile, createPeRomFile } from "../../../fixtures/sample-files-pe.js";
import { createZipFile } from "../../../fixtures/zip-fixtures.js";
import { createSliceTrackingFile } from "../../../helpers/slice-tracking-file.js";

const fromAscii = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "ascii"));

const fromUtf16Le = (text: string): Uint8Array => {
  const bytes = new Uint8Array(2 + text.length * 2);
  bytes[0] = 0xff;
  bytes[1] = 0xfe;
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < text.length; index += 1) {
    view.setUint16(2 + index * 2, text.charCodeAt(index), true);
  }
  return bytes;
};

const createTerminfoEntry = (nameList: string): Uint8Array => {
  const names = fromAscii(`${nameList}\0`);
  const booleanCount = 1;
  const numberCount = 1;
  const stringCount = 1;
  const stringTableSize = 4;
  const afterBooleans = 12 + names.length + booleanCount;
  const numbersOffset = afterBooleans + (afterBooleans % 2);
  const bytes = new Uint8Array(numbersOffset + numberCount * 2 + stringCount * 2 + stringTableSize);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x011a, true);
  view.setUint16(2, names.length, true);
  view.setUint16(4, booleanCount, true);
  view.setUint16(6, numberCount, true);
  view.setUint16(8, stringCount, true);
  view.setUint16(10, stringTableSize, true);
  bytes.set(names, 12);
  return bytes;
};

const createMinimalPeLabelProbe = (machine: number, optionalHeaderMagic = 0x10b): MockFile => {
  const peHeaderOffset = 0x40;
  const coffHeaderSize = 20;
  const optionalHeaderSize = 0xe0;
  const bytes = new Uint8Array(peHeaderOffset + 4 + coffHeaderSize + optionalHeaderSize).fill(0);
  const view = new DataView(bytes.buffer);
  bytes[0] = 0x4d;
  bytes[1] = 0x5a;
  view.setUint32(0x3c, peHeaderOffset, true);
  bytes.set([0x50, 0x45, 0x00, 0x00], peHeaderOffset);
  view.setUint16(peHeaderOffset + 4, machine, true);
  view.setUint16(peHeaderOffset + 4 + 16, optionalHeaderSize, true);
  view.setUint16(peHeaderOffset + 4 + 18, 0x0002, true);
  view.setUint16(peHeaderOffset + 4 + coffHeaderSize, optionalHeaderMagic, true);
  return new MockFile(bytes, `machine-${machine.toString(16)}.exe`);
};

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

  const macho64 = new Uint8Array([0xcf, 0xfa, 0xed, 0xfe]);
  const machoLabel = await detectBinaryType(new MockFile(macho64, "macho", "application/octet-stream"));
  assert.strictEqual(machoLabel, "Mach-O 64-bit");
});

void test("detectBinaryType recognises real Mach-O fixtures", async () => {
  const thinLabel = await detectBinaryType(createMachOFile());
  assert.strictEqual(thinLabel, "Mach-O 64-bit");

  const fatLabel = await detectBinaryType(createMachOUniversalFile());
  assert.strictEqual(fatLabel, "Mach-O universal (Fat)");
});

void test("detectBinaryType keeps truncated fat wrappers visible", async () => {
  const label = await detectBinaryType(new MockFile(createTruncatedFatMachOBytes()));
  assert.strictEqual(label, "Mach-O universal (Fat, truncated)");
});

void test("detectBinaryType does not route Java class files through Mach-O detection", async () => {
  const javaClass = new MockFile(createMinimalJavaClassBytes());
  const label = await detectBinaryType(javaClass);
  assert.strictEqual(label, "Java class file");
});

void test("detectBinaryType recognises MP3 streams even when frames are not at offset 0", async () => {
  const base = createMp3File();
  const prefixed = new Uint8Array(base.data.length + 16);
  prefixed.set(base.data, 16);
  const file = new MockFile(prefixed, "prefixed.mp3", "audio/mpeg");
  const label = await detectBinaryType(file);
  assert.strictEqual(label, "MPEG audio stream (MP3/AAC)");
});

void test("detectBinaryType reports Matroska/WebM by container signature", async () => {
  const label = await detectBinaryType(createWebmFile());
  assert.strictEqual(label, "Matroska/WebM container");
});

void test("detectBinaryType reports MP4 by ISO-BMFF signature", async () => {
  const label = await detectBinaryType(createMp4File());
  assert.strictEqual(label, "MP4/QuickTime container (ISO-BMFF)");
});

void test("detectBinaryType reports ASF by GUID without parsing streams", async () => {
  const label = await detectBinaryType(createSampleAsfFile());
  assert.strictEqual(label, "ASF container (WMA/WMV)");
});

void test("detectBinaryType reports MP3 for minimal single-frame files", async () => {
  const full = createMp3File();
  const singleFrame = full.data.slice(0, full.data.length / 2);
  const label = await detectBinaryType(new MockFile(singleFrame, "single-frame.mp3", "audio/mpeg"));
  assert.strictEqual(label, "MPEG audio stream (MP3/AAC)");
});

void test("detectBinaryType reports FLAC by stream marker without metadata parsing", async () => {
  const label = await detectBinaryType(createFlacFile());
  assert.strictEqual(label, "FLAC audio");
});

void test("detectBinaryType does not mislabel MPEG Program Stream as MP3", async () => {
  const bytes = new Uint8Array(64).fill(0);
  // MPEG PS pack start code 0x000001ba
  bytes[0] = 0x00;
  bytes[1] = 0x00;
  bytes[2] = 0x01;
  bytes[3] = 0xba;
  const label = await detectBinaryType(new MockFile(bytes, "sample.mpg", "video/mpeg"));
  assert.strictEqual(label, "MPEG Program Stream (MPG)");
});

void test("detectBinaryType rejects damaged single-frame MPEG-like streams", async () => {
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

void test("detectBinaryType reports large cursor files from ICO/CUR headers", async () => {
  const cursor = new Uint8Array(22);
  const view = new DataView(cursor.buffer);
  view.setUint16(0, 0, true);
  view.setUint16(2, 2, true);
  view.setUint16(4, 1, true);
  cursor[6] = 128;
  cursor[7] = 128;
  view.setUint16(10, 25, true);
  view.setUint32(14, 128 * 1024, true);
  view.setUint32(18, 22, true);
  const label = await detectBinaryType(new MockFile(cursor, "large.cur"));

  assert.strictEqual(label, "ICO/CUR icon image");
});

void test("detectBinaryType reports compiled terminfo entries", async () => {
  const label = await detectBinaryType(
    new MockFile(createTerminfoEntry("vt100|DEC VT100"), "vt100")
  );

  assert.strictEqual(label, 'Compiled terminfo entry "vt100" (terminal capability database)');
});

void test("detectBinaryType reports Windows INF setup scripts", async () => {
  const inf = [
    "; sample INF",
    "[Version]",
    'Signature="$Windows NT$"',
    "Class=System"
  ].join("\r\n");
  const label = await detectBinaryType(new MockFile(fromUtf16Le(inf), "sample.inf"));

  assert.strictEqual(label, "Windows setup information file (INF, driver/install directives)");
});

void test("detectBinaryType reports GNU gettext message catalogs", async () => {
  const label = await detectBinaryType(
    new MockFile(new Uint8Array([0xde, 0x12, 0x04, 0x95]), "messages.mo")
  );

  assert.strictEqual(label, "GNU gettext message catalog (MO translations)");
});

void test("detectBinaryType reports TrueType/OpenType sfnt fonts", async () => {
  const label = await detectBinaryType(
    new MockFile(new Uint8Array([0x00, 0x01, 0x00, 0x00]), "font.ttf")
  );

  assert.strictEqual(label, "TrueType/OpenType font (sfnt glyph outlines)");
});

void test("detectBinaryType reports WOFF2 web fonts", async () => {
  const label = await detectBinaryType(
    new MockFile(new Uint8Array([0x77, 0x4f, 0x46, 0x32]), "font.woff2")
  );

  assert.strictEqual(label, "Web Open Font Format 2 font (WOFF2 compressed web font)");
});

void test("detectBinaryType reports WOFF web fonts", async () => {
  const label = await detectBinaryType(
    new MockFile(new Uint8Array([0x77, 0x4f, 0x46, 0x46]), "font.woff")
  );

  assert.strictEqual(label, "Web Open Font Format font (WOFF compressed web font)");
});

void test("detectBinaryType reports CPython bytecode cache files", async () => {
  const bytes = new Uint8Array(16);
  bytes[0] = 0xcb;
  bytes[1] = 0x0d;
  bytes[2] = 0x0d;
  bytes[3] = 0x0a;
  const label = await detectBinaryType(new MockFile(bytes, "module.cpython-312.pyc"));

  assert.strictEqual(label, "Python bytecode cache (PYC compiled module)");
});

void test("detectBinaryType reports SQLite by signature without page parsing", async () => {
  const label = await detectBinaryType(createSqliteFile());
  assert.strictEqual(label, "SQLite 3.x database");
});

void test("detectBinaryType reports SQLite WAL-index shared-memory files", async () => {
  const label = await detectBinaryType(createSqliteWalIndexSharedMemoryFile());
  assert.strictEqual(label, "SQLite WAL-index shared-memory file");
});

void test("detectBinaryType avoids full media parsing during signature detection", async () => {
  const sample = createMp4File();
  const tracked = createSliceTrackingFile(sample.data, sample.size, sample.name);

  const label = await detectBinaryType(tracked.file);

  assert.equal(label, "MP4/QuickTime container (ISO-BMFF)");
  assert.deepEqual(tracked.requests, [sample.size]);
});

void test("detectBinaryType reports PE32, PE32+, and ROM labels without full parsing", async () => {
  const pe32Label = await detectBinaryType(createPeFile());
  assert.strictEqual(pe32Label, "PE32 executable for x86 (I386)");

  const pe64Label = await detectBinaryType(createPePlusFile());
  assert.strictEqual(pe64Label, "PE32+ executable for x86-64 (AMD64)");

  const peRomLabel = await detectBinaryType(createPeRomFile());
  assert.strictEqual(peRomLabel, "PE ROM image for MIPS R4000");
});

void test("detectBinaryType prefers PE headers over embedded ZIP EOCD signatures", async () => {
  const pe = createMinimalPeLabelProbe(IMAGE_FILE_MACHINE_I386);
  const zip = createZipFile();
  const bytes = new Uint8Array(pe.data.length + zip.data.length);
  bytes.set(pe.data);
  bytes.set(zip.data, pe.data.length);

  const label = await detectBinaryType(new MockFile(bytes, "pe-with-eocd.dll"));

  assert.strictEqual(label, "PE32 executable for x86 (I386)");
});

void test("detectBinaryType uses the official Microsoft machine names for PE labels", async () => {
  const cases = [
    // Microsoft PE format, "Machine Types": 0x0168 = IMAGE_FILE_MACHINE_R10000.
    { machine: 0x0168, expected: "PE32 executable for MIPS R10000" },
    // Microsoft PE format, "Machine Types": 0x01C2 = IMAGE_FILE_MACHINE_THUMB.
    { machine: 0x01c2, expected: "PE32 executable for Thumb" },
    // Microsoft PE format, "Machine Types": 0x6264 = IMAGE_FILE_MACHINE_LOONGARCH64.
    { machine: 0x6264, expected: "PE32 executable for LoongArch 64-bit" }
  ];

  for (const { machine, expected } of cases) {
    const label = await detectBinaryType(createMinimalPeLabelProbe(machine));
    assert.strictEqual(label, expected);
  }
});

void test("detectBinaryType labels .NET ReadyToRun OS-overridden PE machines", async () => {
  // .NET ReadyToRun: IMAGE_FILE_MACHINE_AMD64 XOR Linux override 0x7B79.
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/pedecoder.h
  const label = await detectBinaryType(createMinimalPeLabelProbe(0xfd1d, 0x20b));
  assert.strictEqual(label, "PE32+ executable for x86-64 (AMD64) ReadyToRun for Linux");
});

void test("detectBinaryType labels ROM optional headers as PE ROM images", async () => {
  // Microsoft PE/COFF: 0x107 identifies IMAGE_ROM_OPTIONAL_HEADER.
  const label = await detectBinaryType(createMinimalPeLabelProbe(0x0166, 0x107));
  assert.strictEqual(label, "PE ROM image for MIPS R4000");
});

void test("detectBinaryType tolerates truncated optional headers for PE labels", async () => {
  const peHeaderOffset = 0x40;
  const bytes = new Uint8Array(peHeaderOffset + 4).fill(0);
  bytes[0] = 0x4d;
  bytes[1] = 0x5a;
  const view = new DataView(bytes.buffer);
  view.setUint32(0x3c, peHeaderOffset, true);
  bytes.set([0x50, 0x45, 0x00, 0x00], peHeaderOffset);
  const label = await detectBinaryType(new MockFile(bytes, "tiny.exe"));
  assert.strictEqual(label, "PE executable (truncated COFF header)");
});

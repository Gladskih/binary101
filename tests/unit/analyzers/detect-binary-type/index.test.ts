"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectBinaryType } from "../../../../analyzers/index.js";
import { IMAGE_FILE_MACHINE_I386 } from "../../../../analyzers/coff/machine.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createPeFile, createPePlusFile, createPeRomFile } from "../../../fixtures/sample-files-pe.js";
import { createZipFile } from "../../../fixtures/zip-fixtures.js";

const fromAscii = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "ascii"));

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

void test("detectBinaryType distinguishes empty files from unknown data", async () => {
  const emptyLabel = await detectBinaryType(new MockFile(new Uint8Array(), "empty.bin"));
  const unknownLabel = await detectBinaryType(
    new MockFile(new Uint8Array([0x00, 0x01, 0x02, 0x03]), "unknown.bin")
  );

  assert.strictEqual(emptyLabel, "Empty file");
  assert.strictEqual(unknownLabel, "Unknown binary type");
});

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

void test("detectBinaryType reports Windows Imaging Format archives", async () => {
  const label = await detectBinaryType(new MockFile(fromAscii("MSWIM\0\0\0"), "sample.ppkg"));

  assert.strictEqual(label, "Windows Imaging Format archive (WIM/PPKG deployment image)");
});

void test("detectBinaryType reports Chrome CRX extension packages", async () => {
  const bytes = new Uint8Array(fromAscii("Cr24").length + 8);
  bytes.set(fromAscii("Cr24"));
  const view = new DataView(bytes.buffer);
  view.setUint32(4, 3, true);
  view.setUint32(8, 4, true);
  const label = await detectBinaryType(new MockFile(bytes, "extension.crx"));

  assert.strictEqual(label, "Chrome extension package (CRX signed ZIP)");
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

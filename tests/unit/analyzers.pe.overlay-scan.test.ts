"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeOverlay } from "../../analyzers/pe/overlay.js";
import { scanPeOverlayRange } from "../../analyzers/pe/overlay-scan.js";
import { createBmpFile } from "../fixtures/bmp-fixtures.js";
import { createBareMidiSignatureBytes, createMinimalMidiFileBytes } from "../fixtures/midi-fixtures.js";
import { createPeWithSectionAndIat } from "../fixtures/sample-files-pe.js";
import { createSevenZipFile } from "../fixtures/rar-sevenzip-fixtures.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { MockFile } from "../helpers/mock-file.js";

// PKWARE APPNOTE, "Local file header": local headers start with 0x04034b50.
// https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
const ZIP_LOCAL_FILE_HEADER_SIGNATURE = [0x50, 0x4b, 0x03, 0x04];

const createTrueOverlayFixture = (overlayPrefixBytes = Uint8Array.of()) => {
  const imagePrefixBytes = Uint8Array.of(0xaa, 0xbb, 0xcc, 0xdd);
  // ZIP local file headers are at least 30 bytes before variable filename/extra fields.
  const overlayBytes = new Uint8Array(30);
  overlayBytes.set(ZIP_LOCAL_FILE_HEADER_SIGNATURE);
  const overlayStart = imagePrefixBytes.byteLength;
  const detectedOffset = overlayStart + overlayPrefixBytes.byteLength;
  const overlayEnd = detectedOffset + overlayBytes.byteLength;
  const bytes = new Uint8Array(overlayEnd);
  bytes.set(imagePrefixBytes);
  bytes.set(overlayPrefixBytes, overlayStart);
  bytes.set(overlayBytes, detectedOffset);
  return { file: new MockFile(bytes, "carrier.exe"), overlayStart, detectedOffset };
};

const createOverlayInputs = (overlayPrefixBytes = Uint8Array.of()) => {
  const fixture = createTrueOverlayFixture(overlayPrefixBytes);
  return {
    fixture,
    inputs: {
      file: fixture.file,
      reader: fixture.file,
      optionalHeaderOffset: 0,
      optionalHeaderSize: 0,
      sectionCount: 0,
      declaredSizeOfHeaders: fixture.overlayStart,
      sections: [],
      dataDirs: [],
      pointerToSymbolTable: 0,
      numberOfSymbols: 0
    }
  };
};

const createOverlayInputsWithPayload = (payloadBytes: Uint8Array) => {
  const imagePrefixBytes = Uint8Array.of(0xaa, 0xbb, 0xcc, 0xdd);
  const overlayStart = imagePrefixBytes.byteLength;
  const overlayEnd = overlayStart + payloadBytes.byteLength;
  const bytes = new Uint8Array(overlayEnd);
  bytes.set(imagePrefixBytes);
  bytes.set(payloadBytes, overlayStart);
  const file = new MockFile(bytes, "carrier.exe");
  return {
    overlayEnd,
    overlayStart,
    inputs: {
      file,
      reader: file,
      optionalHeaderOffset: 0,
      optionalHeaderSize: 0,
      sectionCount: 0,
      declaredSizeOfHeaders: overlayStart,
      sections: [],
      dataDirs: [],
      pointerToSymbolTable: 0,
      numberOfSymbols: 0
    }
  };
};

type OverlayInputs = Parameters<typeof analyzePeOverlay>[0];

const getFirstOverlayRange = async (inputs: OverlayInputs) => {
  const analysis = expectDefined(await analyzePeOverlay(inputs));
  return expectDefined(analysis.ranges[0]);
};

const scanFirstOverlayRange = async (inputs: OverlayInputs) => {
  const range = await getFirstOverlayRange(inputs);
  return scanPeOverlayRange(inputs.file, inputs.reader, range);
};

const createIncidentalOverlayPrefix = (): Uint8Array =>
  Uint8Array.of(0x01, 0x02, 0x03);

const createIncidentalTrailingBytes = (): Uint8Array =>
  Uint8Array.of(0xfe, 0xed, 0xfa, 0xce);

const createMostlyAsciiTextPayload = (): Uint8Array => {
  const bytes = new Uint8Array(64);
  bytes.fill("A".charCodeAt(0));
  return bytes;
};

const createBareBmpSignaturePayload = (): Uint8Array => {
  const bytes = new Uint8Array(64);
  // Microsoft BITMAPFILEHEADER identifies BMP files with ASCII "BM" at bytes 0..1.
  // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader
  bytes[0] = 0x42;
  bytes[1] = 0x4d;
  return bytes;
};

const createEmbeddedPayloadWithTrailingBytes = (
  prefixBytes: Uint8Array,
  embeddedBytes: Uint8Array,
  trailingBytes: Uint8Array
): Uint8Array => {
  const payloadBytes = new Uint8Array(
    prefixBytes.byteLength + embeddedBytes.byteLength + trailingBytes.byteLength
  );
  payloadBytes.set(prefixBytes);
  payloadBytes.set(embeddedBytes, prefixBytes.byteLength);
  payloadBytes.set(trailingBytes, prefixBytes.byteLength + embeddedBytes.byteLength);
  return payloadBytes;
};

const createCabinetOverlayInputs = () => {
  const imagePrefixBytes = Uint8Array.of(0xaa, 0xbb, 0xcc, 0xdd);
  const overlayPrefixBytes = createIncidentalOverlayPrefix();
  // [MS-CAB] CFHEADER base size is 36 bytes; signature bytes spell "MSCF".
  const cabinetBytes = new Uint8Array(36);
  const cabinetView = new DataView(cabinetBytes.buffer);
  cabinetView.setUint32(0, 0x4d534346, false);
  cabinetView.setUint32(8, cabinetBytes.byteLength, true);
  const trailingBytes = createIncidentalTrailingBytes();
  const overlayStart = imagePrefixBytes.byteLength;
  const detectedOffset = overlayStart + overlayPrefixBytes.byteLength;
  const overlayEnd = detectedOffset + cabinetBytes.byteLength + trailingBytes.byteLength;
  const bytes = new Uint8Array(overlayEnd);
  bytes.set(imagePrefixBytes);
  bytes.set(overlayPrefixBytes, overlayStart);
  bytes.set(cabinetBytes, detectedOffset);
  bytes.set(trailingBytes, detectedOffset + cabinetBytes.byteLength);
  const file = new MockFile(bytes, "carrier.exe");
  return {
    cabinetEnd: detectedOffset + cabinetBytes.byteLength,
    detectedOffset,
    overlayEnd,
    inputs: {
      file,
      reader: file,
      optionalHeaderOffset: 0,
      optionalHeaderSize: 0,
      sectionCount: 0,
      declaredSizeOfHeaders: overlayStart,
      sections: [],
      dataDirs: [],
      pointerToSymbolTable: 0,
      numberOfSymbols: 0
    }
  };
};

void test("scanPeOverlayRange scans true overlay ranges for embedded payload signatures", async () => {
  const { fixture, inputs } = createOverlayInputs(Uint8Array.of(0, 0, 0));
  const range = await scanFirstOverlayRange(inputs);

  assert.equal(range.start, fixture.overlayStart);
  assert.equal(range.findings[0]?.start, fixture.detectedOffset);
  assert.match(range.findings[0]?.detectedType ?? "", /^ZIP archive/);
  assert.deepEqual(range.embeddedScan, { status: "complete", scannedBytes: range.size });
});

void test("scanPeOverlayRange does not report generic text overlay as an embedded file", async () => {
  const range = await scanFirstOverlayRange(createOverlayInputsWithPayload(createMostlyAsciiTextPayload()).inputs);

  assert.deepEqual(range.findings, []);
});

void test("scanPeOverlayRange rejects BMP matches without a validated bitmap header", async () => {
  const range = await scanFirstOverlayRange(createOverlayInputsWithPayload(createBareBmpSignaturePayload()).inputs);

  assert.deepEqual(range.findings, []);
});

void test("scanPeOverlayRange rejects MIDI matches without validated SMF chunks", async () => {
  const range = await scanFirstOverlayRange(createOverlayInputsWithPayload(createBareMidiSignatureBytes()).inputs);

  assert.deepEqual(range.findings, []);
});

void test("scanPeOverlayRange rejects short MPEG-TS sync coincidences", async () => {
  const tsLikeBytes = new Uint8Array(188 * 3).fill(0);
  tsLikeBytes[0] = 0x47;
  tsLikeBytes[188] = 0x47;
  tsLikeBytes[376] = 0x47;
  const range = await scanFirstOverlayRange(createOverlayInputsWithPayload(tsLikeBytes).inputs);

  assert.deepEqual(range.findings, []);
});

void test("scanPeOverlayRange rejects aborted scans", async () => {
  const { inputs } = createOverlayInputs();
  const range = await getFirstOverlayRange(inputs);
  const controller = new AbortController();
  controller.abort();

  await assert.rejects(
    () => scanPeOverlayRange(inputs.file, inputs.reader, range, { signal: controller.signal }),
    /PE overlay scan aborted/
  );
});

void test("scanPeOverlayRange bounds embedded BMP findings by the declared bfSize", async () => {
  const prefixBytes = createIncidentalOverlayPrefix();
  const bitmapBytes = createBmpFile().data;
  const payloadBytes = createEmbeddedPayloadWithTrailingBytes(
    prefixBytes,
    bitmapBytes,
    createIncidentalTrailingBytes()
  );
  const fixture = createOverlayInputsWithPayload(payloadBytes);
  const range = await scanFirstOverlayRange(fixture.inputs);
  const finding = expectDefined(range.findings[0]);

  assert.equal(range.end, fixture.overlayEnd);
  assert.equal(finding.start, fixture.overlayStart + prefixBytes.byteLength);
  assert.equal(finding.end, fixture.overlayStart + prefixBytes.byteLength + bitmapBytes.byteLength);
  assert.equal(finding.detectedType, "BMP bitmap image");
  assert.equal(finding.endDescription, "End comes from the BMP file header bfSize field.");
});

void test("scanPeOverlayRange bounds embedded MIDI findings by track chunk sizes", async () => {
  const prefixBytes = createIncidentalOverlayPrefix();
  const midiBytes = createMinimalMidiFileBytes();
  const payloadBytes = createEmbeddedPayloadWithTrailingBytes(
    prefixBytes,
    midiBytes,
    createIncidentalTrailingBytes()
  );
  const fixture = createOverlayInputsWithPayload(payloadBytes);
  const range = await scanFirstOverlayRange(fixture.inputs);
  const finding = expectDefined(range.findings[0]);

  assert.equal(range.end, fixture.overlayEnd);
  assert.equal(finding.start, fixture.overlayStart + prefixBytes.byteLength);
  assert.equal(finding.end, fixture.overlayStart + prefixBytes.byteLength + midiBytes.byteLength);
  assert.equal(finding.detectedType, "MIDI audio");
  assert.equal(finding.endDescription, "End comes from the Standard MIDI track chunk length fields.");
});

void test("scanPeOverlayRange bounds embedded 7z findings by signature header fields", async () => {
  const prefixBytes = createIncidentalOverlayPrefix();
  const sevenZipBytes = createSevenZipFile().data;
  const payloadBytes = createEmbeddedPayloadWithTrailingBytes(
    prefixBytes,
    sevenZipBytes,
    createIncidentalTrailingBytes()
  );
  const fixture = createOverlayInputsWithPayload(payloadBytes);
  const range = await scanFirstOverlayRange(fixture.inputs);
  const finding = expectDefined(range.findings[0]);

  assert.equal(range.end, fixture.overlayEnd);
  assert.equal(finding.start, fixture.overlayStart + prefixBytes.byteLength);
  assert.equal(finding.end, fixture.overlayStart + prefixBytes.byteLength + sevenZipBytes.byteLength);
  assert.equal(finding.detectedType, "7z archive");
  assert.equal(
    finding.endDescription,
    "End comes from the 7z SignatureHeader NextHeaderOffset and NextHeaderSize fields."
  );
});

void test("scanPeOverlayRange ignores stray embedded MZ bytes without an executable signature", async () => {
  // 96 bytes is enough to contain an MZ e_lfanew field at 0x3c, but this fixture leaves it invalid.
  const payloadBytes = new Uint8Array(96);
  payloadBytes[1] = 0x4d;
  payloadBytes[2] = 0x5a;
  const range = await scanFirstOverlayRange(createOverlayInputsWithPayload(payloadBytes).inputs);

  assert.deepEqual(range.findings, []);
});

void test("scanPeOverlayRange recognizes embedded PE only after validating e_lfanew signature", async () => {
  const prefixBytes = createIncidentalOverlayPrefix();
  const peBytes = createPeWithSectionAndIat();
  const payloadBytes = new Uint8Array(prefixBytes.byteLength + peBytes.byteLength);
  payloadBytes.set(prefixBytes);
  payloadBytes.set(peBytes, prefixBytes.byteLength);
  const fixture = createOverlayInputsWithPayload(payloadBytes);
  const range = await scanFirstOverlayRange(fixture.inputs);
  const finding = expectDefined(range.findings[0]);

  assert.equal(finding.start, fixture.overlayStart + prefixBytes.byteLength);
  assert.equal(finding.end, fixture.overlayEnd);
  assert.match(finding.detectedType, /^PE32 executable/);
});

void test("scanPeOverlayRange bounds embedded CAB findings by CFHEADER cbCabinet", async () => {
  const fixture = createCabinetOverlayInputs();
  const range = await scanFirstOverlayRange(fixture.inputs);
  const finding = expectDefined(range.findings[0]);

  assert.equal(range.end, fixture.overlayEnd);
  assert.equal(finding.start, fixture.detectedOffset);
  assert.equal(finding.end, fixture.cabinetEnd);
  assert.equal(finding.size, fixture.cabinetEnd - fixture.detectedOffset);
  assert.equal(finding.endDescription, "End comes from the CAB CFHEADER.cbCabinet size field.");
});

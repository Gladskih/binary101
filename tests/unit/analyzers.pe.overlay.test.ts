"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeOverlay, getUnexplainedOverlayRanges } from "../../analyzers/pe/overlay.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { createBmpFile } from "../fixtures/bmp-fixtures.js";
import { createPeWithSectionAndIat } from "../fixtures/sample-files-pe.js";

// PKWARE APPNOTE, "Local file header": local headers start with 0x04034b50.
// https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
const ZIP_LOCAL_FILE_HEADER_SIGNATURE = [0x50, 0x4b, 0x03, 0x04];

const createTrueOverlayFixture = (overlayPrefixBytes = Uint8Array.of()) => {
  const imagePrefixBytes = Uint8Array.of(0xaa, 0xbb, 0xcc, 0xdd);
  const overlayBytes = Uint8Array.of(...ZIP_LOCAL_FILE_HEADER_SIGNATURE);
  const overlayStart = imagePrefixBytes.byteLength;
  const detectedOffset = overlayStart + overlayPrefixBytes.byteLength;
  const overlayEnd = detectedOffset + overlayBytes.byteLength;
  const bytes = new Uint8Array(overlayEnd);
  bytes.set(imagePrefixBytes);
  bytes.set(overlayPrefixBytes, overlayStart);
  bytes.set(overlayBytes, detectedOffset);
  return { file: new MockFile(bytes, "carrier.exe"), overlayBytes, overlayStart, overlayEnd, detectedOffset };
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

void test("getUnexplainedOverlayRanges excludes certificate table bytes", () => {
  const { fixture, inputs } = createOverlayInputs();
  const ranges = getUnexplainedOverlayRanges({
    ...inputs,
    dataDirs: [{ name: "SECURITY", rva: fixture.overlayStart, size: fixture.overlayBytes.byteLength }]
  });

  assert.deepEqual(ranges, []);
});

void test("analyzePeOverlay recognizes true overlay bytes with existing binary detection", async () => {
  const { fixture, inputs } = createOverlayInputs();
  const analysis = expectDefined(await analyzePeOverlay(inputs));
  const range = expectDefined(analysis.ranges[0]);

  assert.equal(analysis.ranges.length, 1);
  assert.equal(range.start, fixture.overlayStart);
  assert.equal(range.end, fixture.overlayEnd);
  assert.equal(range.size, fixture.overlayEnd - fixture.overlayStart);
  assert.equal(range.findings[0]?.start, fixture.detectedOffset);
  assert.equal(range.findings[0]?.end, fixture.overlayEnd);
  assert.match(range.findings[0]?.detectedType ?? "", /^ZIP archive/);
});

void test("analyzePeOverlay scans inside true overlay ranges for embedded payload signatures", async () => {
  const { fixture, inputs } = createOverlayInputs(Uint8Array.of(0, 0, 0));
  const analysis = expectDefined(await analyzePeOverlay(inputs));
  const range = expectDefined(analysis.ranges[0]);

  assert.equal(range.start, fixture.overlayStart);
  assert.equal(range.findings[0]?.start, fixture.detectedOffset);
  assert.match(range.findings[0]?.detectedType ?? "", /^ZIP archive/);
});

void test("analyzePeOverlay does not report generic text overlay as an embedded file", async () => {
  const analysis = expectDefined(
    await analyzePeOverlay(createOverlayInputsWithPayload(createMostlyAsciiTextPayload()).inputs)
  );
  const range = expectDefined(analysis.ranges[0]);

  assert.deepEqual(range.findings, []);
});

void test("analyzePeOverlay rejects BMP matches without a validated bitmap header", async () => {
  const analysis = expectDefined(
    await analyzePeOverlay(createOverlayInputsWithPayload(createBareBmpSignaturePayload()).inputs)
  );
  const range = expectDefined(analysis.ranges[0]);

  assert.deepEqual(range.findings, []);
});

void test("analyzePeOverlay bounds embedded BMP findings by the declared bfSize", async () => {
  const prefixBytes = createIncidentalOverlayPrefix();
  const bitmapBytes = createBmpFile().data;
  const payloadBytes = createEmbeddedPayloadWithTrailingBytes(
    prefixBytes,
    bitmapBytes,
    createIncidentalTrailingBytes()
  );
  const fixture = createOverlayInputsWithPayload(payloadBytes);
  const analysis = expectDefined(await analyzePeOverlay(fixture.inputs));
  const range = expectDefined(analysis.ranges[0]);
  const finding = expectDefined(range.findings[0]);

  assert.equal(range.end, fixture.overlayEnd);
  assert.equal(finding.start, fixture.overlayStart + prefixBytes.byteLength);
  assert.equal(finding.end, fixture.overlayStart + prefixBytes.byteLength + bitmapBytes.byteLength);
  assert.equal(finding.detectedType, "BMP bitmap image");
  assert.equal(finding.endDescription, "End comes from the BMP file header bfSize field.");
});

void test("analyzePeOverlay ignores stray embedded MZ bytes without an executable signature", async () => {
  // 96 bytes is enough to contain an MZ e_lfanew field at 0x3c, but this fixture leaves it invalid.
  const payloadBytes = new Uint8Array(96);
  payloadBytes[1] = 0x4d;
  payloadBytes[2] = 0x5a;
  const analysis = expectDefined(await analyzePeOverlay(createOverlayInputsWithPayload(payloadBytes).inputs));
  const range = expectDefined(analysis.ranges[0]);

  assert.deepEqual(range.findings, []);
});

void test("analyzePeOverlay recognizes embedded PE only after validating e_lfanew signature", async () => {
  const prefixBytes = Uint8Array.of(0x01, 0x02, 0x03);
  const peBytes = createPeWithSectionAndIat();
  const payloadBytes = new Uint8Array(prefixBytes.byteLength + peBytes.byteLength);
  payloadBytes.set(prefixBytes);
  payloadBytes.set(peBytes, prefixBytes.byteLength);
  const fixture = createOverlayInputsWithPayload(payloadBytes);
  const analysis = expectDefined(await analyzePeOverlay(fixture.inputs));
  const range = expectDefined(analysis.ranges[0]);
  const finding = expectDefined(range.findings[0]);

  assert.equal(finding.start, fixture.overlayStart + prefixBytes.byteLength);
  assert.equal(finding.end, fixture.overlayEnd);
  assert.match(finding.detectedType, /^PE32 executable/);
});

void test("analyzePeOverlay bounds embedded CAB findings by CFHEADER cbCabinet", async () => {
  const fixture = createCabinetOverlayInputs();
  const analysis = expectDefined(await analyzePeOverlay(fixture.inputs));
  const range = expectDefined(analysis.ranges[0]);
  const finding = expectDefined(range.findings[0]);

  assert.equal(range.end, fixture.overlayEnd);
  assert.equal(finding.start, fixture.detectedOffset);
  assert.equal(finding.end, fixture.cabinetEnd);
  assert.equal(finding.size, fixture.cabinetEnd - fixture.detectedOffset);
  assert.equal(finding.endDescription, "End comes from the CAB CFHEADER.cbCabinet size field.");
});

void test("analyzePeOverlay returns null when no true overlay remains", async () => {
  const { fixture, inputs } = createOverlayInputs();
  assert.equal(
    await analyzePeOverlay({
      ...inputs,
      declaredSizeOfHeaders: fixture.file.size
    }),
    null
  );
});

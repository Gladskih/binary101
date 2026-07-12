"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  detectEmbeddedCandidateType,
  EMBEDDED_EXECUTABLE_LABEL,
  isEmbeddedCandidateStartByte,
  readEmbeddedBmpFileSize,
  readEmbeddedCabinetFileSize,
  readEmbeddedMidiFileSize,
  readEmbeddedSevenZipFileSize
} from "../../../../analyzers/pe/overlay-embedded.js";
import { createBmpFile } from "../../../fixtures/bmp-fixtures.js";
import { createBareMidiSignatureBytes, createMinimalMidiFileBytes } from "../../../fixtures/midi-fixtures.js";
import { createSevenZipFile } from "../../../fixtures/rar-sevenzip-fixtures.js";

const dataViewFrom = (bytes: ArrayLike<number>): DataView =>
  new DataView(Uint8Array.from(bytes).buffer);

const createBareBmpSignatureCandidate = (): DataView => {
  const bytes = new Uint8Array(64);
  // Microsoft BITMAPFILEHEADER identifies BMP files with ASCII "BM" at bytes 0..1.
  // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader
  bytes[0] = 0x42;
  bytes[1] = 0x4d;
  return new DataView(bytes.buffer);
};

void test("isEmbeddedCandidateStartByte gates expensive embedded probes", () => {
  assert.equal(isEmbeddedCandidateStartByte(0x50), true);
  assert.equal(isEmbeddedCandidateStartByte(0x47), false);
  assert.equal(isEmbeddedCandidateStartByte(0x00), false);
});

void test("detectEmbeddedCandidateType rejects bare MZ without e_lfanew signature", () => {
  const bytes = new Uint8Array(96);
  bytes[0] = 0x4d;
  bytes[1] = 0x5a;

  assert.equal(detectEmbeddedCandidateType(new DataView(bytes.buffer), bytes.byteLength), null);
});

void test("detectEmbeddedCandidateType accepts MZ only when e_lfanew points to PE signature", () => {
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x5a4d, true);
  view.setUint32(0x3c, 0x40, true);
  view.setUint32(0x40, 0x50450000, false);

  assert.equal(detectEmbeddedCandidateType(view, bytes.byteLength), EMBEDDED_EXECUTABLE_LABEL);
});

void test("detectEmbeddedCandidateType validates gzip method and reserved flags", () => {
  assert.equal(
    detectEmbeddedCandidateType(dataViewFrom([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0]), 10),
    "gzip compressed data"
  );
  assert.equal(
    detectEmbeddedCandidateType(dataViewFrom([0x1f, 0x8b, 0x09, 0x00, 0, 0, 0, 0, 0, 0]), 10),
    null
  );
  assert.equal(
    detectEmbeddedCandidateType(dataViewFrom([0x1f, 0x8b, 0x08, 0xe0, 0, 0, 0, 0, 0, 0]), 10),
    null
  );
});

void test("detectEmbeddedCandidateType accepts validated ZIP local headers", () => {
  const bytes = new Uint8Array(30);
  bytes.set([0x50, 0x4b, 0x03, 0x04]);

  assert.equal(detectEmbeddedCandidateType(new DataView(bytes.buffer), bytes.byteLength), "ZIP archive");
});

void test("detectEmbeddedCandidateType accepts CAB only with coherent cbCabinet", () => {
  const bytes = new Uint8Array(36);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x4d534346, false);
  view.setUint32(8, bytes.byteLength, true);

  assert.equal(readEmbeddedCabinetFileSize(view, bytes.byteLength), bytes.byteLength);
  assert.equal(detectEmbeddedCandidateType(view, bytes.byteLength), "Microsoft Cabinet archive (CAB)");
  view.setUint32(8, bytes.byteLength + 1, true);
  assert.equal(readEmbeddedCabinetFileSize(view, bytes.byteLength), null);
  assert.equal(detectEmbeddedCandidateType(view, bytes.byteLength), null);
});

void test("detectEmbeddedCandidateType accepts 7z only with bounded signature header fields", () => {
  const bytes = createSevenZipFile().data;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  assert.equal(readEmbeddedSevenZipFileSize(view, bytes.byteLength), bytes.byteLength);
  assert.equal(detectEmbeddedCandidateType(view, bytes.byteLength), "7z archive");
  assert.equal(detectEmbeddedCandidateType(dataViewFrom([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]), 6), null);
});

void test("detectEmbeddedCandidateType rejects a 7z start-header CRC mismatch", () => {
  const bytes = createSevenZipFile().data.slice();
  bytes[8] = (bytes[8] ?? 0) ^ 0xff;

  assert.equal(detectEmbeddedCandidateType(new DataView(bytes.buffer), bytes.byteLength), null);
});

void test("detectEmbeddedCandidateType rejects broad magic-only formats", () => {
  const tsBytes = new Uint8Array(188 * 5).fill(0);
  for (let offset = 0; offset < tsBytes.byteLength; offset += 188) {
    tsBytes[offset] = 0x47;
    tsBytes[offset + 3] = 0x10;
  }

  assert.equal(detectEmbeddedCandidateType(dataViewFrom([0x25, 0x50, 0x44, 0x46, 0x2d]), 5), null);
  assert.equal(detectEmbeddedCandidateType(new DataView(tsBytes.buffer), tsBytes.byteLength), null);
});

void test("detectEmbeddedCandidateType rejects bare BMP signatures without a coherent header", () => {
  const view = createBareBmpSignatureCandidate();

  assert.equal(detectEmbeddedCandidateType(view, view.byteLength), null);
  assert.equal(readEmbeddedBmpFileSize(view, view.byteLength), null);
});

void test("detectEmbeddedCandidateType accepts BMP after validating declared size and DIB fields", () => {
  const bytes = createBmpFile().data;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // createBmpFile encodes BITMAPFILEHEADER.bfSize as 0x3a, the complete fixture size.
  assert.equal(readEmbeddedBmpFileSize(view, bytes.byteLength), 58);
  assert.equal(detectEmbeddedCandidateType(view, bytes.byteLength), "BMP bitmap image");
});

void test("detectEmbeddedCandidateType rejects bare MIDI signatures without coherent chunks", () => {
  const bytes = createBareMidiSignatureBytes();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  assert.equal(detectEmbeddedCandidateType(view, view.byteLength), null);
  assert.equal(readEmbeddedMidiFileSize(view, view.byteLength), null);
});

void test("detectEmbeddedCandidateType accepts MIDI after validating header and track chunks", () => {
  const bytes = createMinimalMidiFileBytes();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  assert.equal(readEmbeddedMidiFileSize(view, view.byteLength), 26);
  assert.equal(detectEmbeddedCandidateType(view, view.byteLength), "MIDI audio");
});

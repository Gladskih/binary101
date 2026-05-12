"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeOverlay, getUnexplainedOverlayRanges } from "../../analyzers/pe/overlay.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

// PKWARE APPNOTE, "Local file header": local headers start with 0x04034b50.
// https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
const ZIP_LOCAL_FILE_HEADER_SIGNATURE = [0x50, 0x4b, 0x03, 0x04];

const createTrueOverlayFixture = () => {
  const imagePrefixBytes = Uint8Array.of(0xaa, 0xbb, 0xcc, 0xdd);
  const overlayBytes = Uint8Array.of(...ZIP_LOCAL_FILE_HEADER_SIGNATURE);
  const overlayStart = imagePrefixBytes.byteLength;
  const overlayEnd = overlayStart + overlayBytes.byteLength;
  const bytes = new Uint8Array(overlayEnd);
  bytes.set(imagePrefixBytes);
  bytes.set(overlayBytes, overlayStart);
  return { file: new MockFile(bytes, "carrier.exe"), overlayBytes, overlayStart, overlayEnd };
};

const createOverlayInputs = () => {
  const fixture = createTrueOverlayFixture();
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

void test("getUnexplainedOverlayRanges excludes certificate table bytes", () => {
  const { fixture, inputs } = createOverlayInputs();
  const ranges = getUnexplainedOverlayRanges({
    ...inputs,
    dataDirs: [{ name: "SECURITY", rva: fixture.overlayStart, size: fixture.overlayBytes.byteLength }]
  });

  assert.deepEqual(ranges, []);
});

void test("analyzePeOverlay lists true overlay bytes without scanning embedded signatures", async () => {
  const { fixture, inputs } = createOverlayInputs();
  const analysis = expectDefined(await analyzePeOverlay(inputs));
  const range = expectDefined(analysis.ranges[0]);

  assert.equal(analysis.ranges.length, 1);
  assert.equal(range.start, fixture.overlayStart);
  assert.equal(range.end, fixture.overlayEnd);
  assert.equal(range.size, fixture.overlayEnd - fixture.overlayStart);
  assert.deepEqual(range.findings, []);
  assert.equal(range.embeddedScan, undefined);
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

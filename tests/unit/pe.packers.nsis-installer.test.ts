"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { detectNsisInstaller } from "../../analyzers/pe/packers/nsis-installer.js";
import type { NsisInstallerDetectorInput } from "../../analyzers/pe/packers/types.js";
import { MockFile } from "../helpers/mock-file.js";

const OVERLAY_START = 0x20;
const OVERLAY_END = 0x80;
const FIRSTHEADER_BYTES = 28;
const NSIS_COMPRESSED_HEADER_BYTES = 10;
const NSIS_FOLLOWING_DATA_BYTES = 40;
const NSIS_BAD_FLAGS_WITH_RESERVED_BIT = 0x10;
const NSIS_TOO_SMALL_FOLLOWING_DATA_BYTES = FIRSTHEADER_BYTES - 1;
const NSIS_TOO_LARGE_COMPRESSED_HEADER_BYTES = NSIS_FOLLOWING_DATA_BYTES - FIRSTHEADER_BYTES + 1;
const NSIS_OVERSIZED_FOLLOWING_DATA_BYTES = 0x100;
const NSIS_TRUNCATED_SIGNATURE_BYTES = 12;
// firstheader field offsets follow NSIS fileform.h.
// https://github.com/kichik/nsis/blob/master/Source/exehead/fileform.h
const NSIS_FIRSTHEADER = {
  flags: 0,
  siginfo: 4,
  nsinst: 8,
  lengthOfHeader: 20,
  lengthOfAllFollowingData: 24
};

const createFirstHeader = (): Uint8Array => {
  const bytes = new Uint8Array(FIRSTHEADER_BYTES);
  const view = new DataView(bytes.buffer);
  // NSIS firstheader stores flags, FH_SIG, "NullsoftInst", length_of_header,
  // and length_of_all_following_data as 32-bit little-endian integers.
  // https://github.com/kichik/nsis/blob/master/Source/exehead/fileform.h
  view.setInt32(NSIS_FIRSTHEADER.flags, 0, true);
  view.setUint32(NSIS_FIRSTHEADER.siginfo, 0xdeadbeef, true);
  view.setUint32(NSIS_FIRSTHEADER.nsinst, 0x6c6c754e, true);
  view.setUint32(NSIS_FIRSTHEADER.nsinst + Int32Array.BYTES_PER_ELEMENT, 0x74666f73, true);
  view.setUint32(NSIS_FIRSTHEADER.nsinst + Int32Array.BYTES_PER_ELEMENT * 2, 0x74736e49, true);
  view.setInt32(NSIS_FIRSTHEADER.lengthOfHeader, NSIS_COMPRESSED_HEADER_BYTES, true);
  view.setInt32(NSIS_FIRSTHEADER.lengthOfAllFollowingData, NSIS_FOLLOWING_DATA_BYTES, true);
  return bytes;
};

const createInput = (firstHeader: Uint8Array, overlayEnd = OVERLAY_END) => {
  const bytes = new Uint8Array(overlayEnd);
  bytes.set(firstHeader, OVERLAY_START);
  return {
    reader: new MockFile(bytes, "nsis.exe"),
    overlay: {
      ranges: [{
        start: OVERLAY_START,
        end: overlayEnd,
        size: overlayEnd - OVERLAY_START,
        findings: []
      }]
    }
  } satisfies NsisInstallerDetectorInput;
};

void test("detectNsisInstaller reports a valid firstheader at a true overlay start", async () => {
  const result = await detectNsisInstaller(createInput(createFirstHeader()));

  assert.equal(result.warnings.length, 0);
  assert.equal(result.findings[0]?.id, "nsis-installer");
  assert.deepEqual(result.findings[0]?.details?.find(detail => detail.label === "Following data length"), {
    label: "Following data length",
    kind: "bytes",
    value: NSIS_FOLLOWING_DATA_BYTES
  });
});

void test("detectNsisInstaller ignores overlay starts without the NSIS signature", async () => {
  const result = await detectNsisInstaller(createInput(new Uint8Array(FIRSTHEADER_BYTES)));

  assert.deepEqual(result, { findings: [], warnings: [] });
});

void test("detectNsisInstaller warns about bad firstheader flags", async () => {
  const header = createFirstHeader();
  new DataView(header.buffer).setInt32(NSIS_FIRSTHEADER.flags, NSIS_BAD_FLAGS_WITH_RESERVED_BIT, true);

  const result = await detectNsisInstaller(createInput(header));

  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.warnings, ["NSIS firstheader has unsupported flag bits set."]);
});

void test("detectNsisInstaller warns about invalid firstheader lengths", async () => {
  const header = createFirstHeader();
  new DataView(header.buffer).setInt32(NSIS_FIRSTHEADER.lengthOfHeader, -1, true);

  const result = await detectNsisInstaller(createInput(header));

  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.warnings, ["NSIS firstheader length_of_header is not positive."]);
});

void test("detectNsisInstaller warns when following data is smaller than firstheader", async () => {
  const header = createFirstHeader();
  new DataView(header.buffer).setInt32(
    NSIS_FIRSTHEADER.lengthOfAllFollowingData,
    NSIS_TOO_SMALL_FOLLOWING_DATA_BYTES,
    true
  );

  const result = await detectNsisInstaller(createInput(header));

  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.warnings, [
    "NSIS firstheader length_of_all_following_data is smaller than firstheader."
  ]);
});

void test("detectNsisInstaller warns when compressed header exceeds following data", async () => {
  const header = createFirstHeader();
  new DataView(header.buffer).setInt32(
    NSIS_FIRSTHEADER.lengthOfHeader,
    NSIS_TOO_LARGE_COMPRESSED_HEADER_BYTES,
    true
  );

  const result = await detectNsisInstaller(createInput(header));

  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.warnings, ["NSIS firstheader length_of_header exceeds the following data span."]);
});

void test("detectNsisInstaller warns about data spans beyond the true overlay", async () => {
  const header = createFirstHeader();
  new DataView(header.buffer).setInt32(
    NSIS_FIRSTHEADER.lengthOfAllFollowingData,
    NSIS_OVERSIZED_FOLLOWING_DATA_BYTES,
    true
  );

  const result = await detectNsisInstaller(createInput(header));

  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.warnings, [
    "NSIS firstheader length_of_all_following_data extends past the true overlay range."
  ]);
});

void test("detectNsisInstaller warns about truncated signature-like firstheaders", async () => {
  const bytes = createFirstHeader().slice(0, NSIS_TRUNCATED_SIGNATURE_BYTES);

  const result = await detectNsisInstaller(createInput(bytes, OVERLAY_START + bytes.byteLength));

  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.warnings, ["NSIS firstheader is truncated by EOF."]);
});

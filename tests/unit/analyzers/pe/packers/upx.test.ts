"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { upxAdler32 } from "../../../../../analyzers/pe/packers/upx-adler32.js";
import { upxPackHeaderChecksum } from "../../../../../analyzers/pe/packers/upx-pack-header.js";
import { detectUpx } from "../../../../../analyzers/pe/packers/upx.js";
import type { UpxDetectorInput } from "../../../../../analyzers/pe/packers/types.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const SECTION_START = 0x100;
const HEADER_START = SECTION_START - 32;
const UNPACKED_BYTES = 24_955;
const UNPACKED_ADLER32 = 4_254_996_567;
const ORIGINAL_FILE_BYTES = 17_920;
const PACKED = Uint8Array.from(Buffer.from(
  "GgMAKqJYpQZrW5qaYo4ncMUJMo9sZrUxVukK6/uMHUfOOlCgtiYH5eVhnvPXUqcgSsrSXGW98E1E" +
  "75mGL0CRZW3NPdOoWONXUdUOMJ4JsAW31JubS8jsG2HJ/pqTqLtmuVM+UKA5ARlOsH3Ia5yu7pUt" +
  "I632uxdapEgcLCuCZMjnvsmF7u5Ge5OBNJq7fG6uEgJmdRs7o3RfucdplgaVretLwnH2TgDbhzLu" +
  "AGWBBW7rTkpcSzvjV8S0rNedZedKAD+F1PP144NwkM54edjWps4ksAA=",
  "base64"
));
const NRV_PACKED = Uint8Array.from(Buffer.from(
  "yf83/1WJ5VDHRfwAD7YFAAAQAIPEBF3DABIcQVUB6CRCUFUmVRKCoKhARlVUlI0CFR/yX34S" +
  "AFBFTAEDAIDKUmrgAALZYM32AQsBDgwCQhQQA3Z2s7MAQAsfBgAHLd9kSxdwJwOFhL1l7ygCBwb5" +
  "DxCyDGAMLnRlwr5h3Xh0BxeQswJ9szf75iAuZGF0YfIQB5B/ubAEq0DALnJlbG9jsykbbGBLRCdC" +
  "GwAAAHAEACQAAP8=",
  "base64"
));
const HEADER_FIELDS = {
  version: 4,
  format: 5,
  method: 6,
  level: 7,
  unpackedAdler: 8,
  packedAdler: 12,
  unpackedSize: 16,
  packedSize: 20,
  originalFileSize: 24,
  checksum: 31
};

const refreshHeaderChecksum = (bytes: Uint8Array): void => {
  bytes[HEADER_START + HEADER_FIELDS.checksum] = upxPackHeaderChecksum(
    bytes.subarray(HEADER_START, HEADER_START + HEADER_FIELDS.checksum)
  );
};

const createInput = (
  mutate?: (bytes: Uint8Array, view: DataView) => void,
  sectionSize = PACKED.byteLength
): UpxDetectorInput => {
  const bytes = new Uint8Array(SECTION_START + PACKED.byteLength + 1);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("UPX!"), HEADER_START);
  view.setUint8(HEADER_START + HEADER_FIELDS.version, 13);
  view.setUint8(HEADER_START + HEADER_FIELDS.format, 36);
  view.setUint8(HEADER_START + HEADER_FIELDS.method, 14);
  view.setUint8(HEADER_START + HEADER_FIELDS.level, 9);
  view.setUint32(HEADER_START + HEADER_FIELDS.unpackedAdler, UNPACKED_ADLER32, true);
  view.setUint32(HEADER_START + HEADER_FIELDS.packedAdler, upxAdler32(PACKED), true);
  view.setUint32(HEADER_START + HEADER_FIELDS.unpackedSize, UNPACKED_BYTES, true);
  view.setUint32(HEADER_START + HEADER_FIELDS.packedSize, PACKED.byteLength, true);
  view.setUint32(HEADER_START + HEADER_FIELDS.originalFileSize, ORIGINAL_FILE_BYTES, true);
  bytes.set(PACKED, SECTION_START);
  refreshHeaderChecksum(bytes);
  mutate?.(bytes, view);
  return {
    reader: new MockFile(bytes, "renamed-sections.exe"),
    sections: [{
      name: inlinePeSectionName(".x"),
      virtualSize: sectionSize,
      virtualAddress: 0x2000,
      sizeOfRawData: sectionSize,
      pointerToRawData: SECTION_START,
      characteristics: 0x60000020
    }],
    imagePointerBytes: 8
  };
};

void test("detectUpx verifies a PackHeader and LZMA stream without section names", async () => {
  const result = await detectUpx(createInput());

  assert.equal(result.warnings.length, 0);
  assert.equal(result.findings[0]?.id, "upx");
  assert.deepEqual(result.findings[0]?.details?.find(detail => detail.label === "Compression"), {
    label: "Compression",
    kind: "text",
    value: "LZMA"
  });
});

void test("detectUpx verifies the standard NRV PE method", async () => {
  const result = await detectUpx(createInput((bytes, view) => {
    bytes.set(NRV_PACKED, SECTION_START);
    view.setUint8(HEADER_START + HEADER_FIELDS.method, 2);
    view.setUint32(HEADER_START + HEADER_FIELDS.packedSize, NRV_PACKED.byteLength, true);
    view.setUint32(HEADER_START + HEADER_FIELDS.packedAdler, upxAdler32(NRV_PACKED), true);
    refreshHeaderChecksum(bytes);
  }));

  assert.equal(result.warnings.length, 0);
  assert.deepEqual(result.findings[0]?.details?.find(detail => detail.label === "Compression"), {
    label: "Compression",
    kind: "text",
    value: "NRV2B LE32"
  });
});

void test("detectUpx accepts legacy PackHeaders without a checksum field", async () => {
  const input = createInput((bytes, view) => {
    bytes.copyWithin(HEADER_START + 28, SECTION_START, SECTION_START + PACKED.byteLength);
    view.setUint8(HEADER_START + HEADER_FIELDS.version, 9);
  });
  input.sections[0]!.pointerToRawData = HEADER_START + 28;

  const result = await detectUpx(input);

  assert.equal(result.warnings.length, 0);
  assert.ok(result.findings[0]?.evidence.some(item => item.includes("no header checksum")));
});

void test("detectUpx deduplicates candidates from overlapping section ranges", async () => {
  const input = createInput();
  input.sections.push({ ...input.sections[0]! });

  const result = await detectUpx(input);

  assert.equal(result.findings.length, 1);
});

void test("detectUpx rejects PackHeader checksum mismatches", async () => {
  const result = await detectUpx(createInput(bytes => {
    bytes[HEADER_START + HEADER_FIELDS.checksum] =
      (bytes[HEADER_START + HEADER_FIELDS.checksum] ?? 0) ^ 1;
  }));

  assert.equal(result.findings.length, 0);
  assert.match(result.warnings[0] ?? "", /PackHeader checksum/);
});

void test("detectUpx rejects packed Adler-32 mismatches", async () => {
  const result = await detectUpx(createInput((bytes, view) => {
    view.setUint32(HEADER_START + HEADER_FIELDS.packedAdler, 0, true);
    refreshHeaderChecksum(bytes);
  }));

  assert.equal(result.findings.length, 0);
  assert.match(result.warnings[0] ?? "", /packed Adler-32/);
});

void test("detectUpx rejects short reads of otherwise bounded packed data", async () => {
  const input = createInput();
  const reader = input.reader;
  input.reader = {
    size: reader.size,
    read: (offset, size) => reader.read(offset, size),
    readBytes: async (offset, size) => (await reader.readBytes(offset, size)).subarray(0, size - 1)
  };

  const result = await detectUpx(input);

  assert.equal(result.findings.length, 0);
  assert.match(result.warnings[0] ?? "", /truncated/);
});

void test("detectUpx rejects unpacked Adler-32 mismatches", async () => {
  const result = await detectUpx(createInput((bytes, view) => {
    view.setUint32(HEADER_START + HEADER_FIELDS.unpackedAdler, 0, true);
    refreshHeaderChecksum(bytes);
  }));

  assert.equal(result.findings.length, 0);
  assert.match(result.warnings[0] ?? "", /unpacked Adler-32/);
});

void test("detectUpx rejects corrupt streams even when packed Adler-32 is updated", async () => {
  const result = await detectUpx(createInput((bytes, view) => {
    bytes[SECTION_START + 10] = (bytes[SECTION_START + 10] ?? 0) ^ 0xff;
    view.setUint32(
      HEADER_START + HEADER_FIELDS.packedAdler,
      upxAdler32(bytes.subarray(SECTION_START, SECTION_START + PACKED.byteLength)),
      true
    );
    refreshHeaderChecksum(bytes);
  }));

  assert.equal(result.findings.length, 0);
  assert.match(result.warnings[0] ?? "", /decompression|unpacked Adler-32/);
});

void test("detectUpx rejects packed ranges outside the section", async () => {
  const result = await detectUpx(createInput(undefined, PACKED.byteLength - 1));

  assert.equal(result.findings.length, 0);
  assert.match(result.warnings[0] ?? "", /outside its PE section/);
});

void test("detectUpx bounds browser allocations before decompression", async () => {
  const result = await detectUpx(createInput((bytes, view) => {
    view.setUint32(HEADER_START + HEADER_FIELDS.unpackedSize, 256 * 1024 * 1024 + 1, true);
    refreshHeaderChecksum(bytes);
  }));

  assert.equal(result.findings.length, 0);
  assert.match(result.warnings[0] ?? "", /browser limit/);
});

void test("detectUpx rejects LZMA streams with a checksummed trailing byte", async () => {
  const result = await detectUpx(createInput((bytes, view) => {
    view.setUint32(HEADER_START + HEADER_FIELDS.packedSize, PACKED.byteLength + 1, true);
    view.setUint32(
      HEADER_START + HEADER_FIELDS.packedAdler,
      upxAdler32(bytes.subarray(SECTION_START, SECTION_START + PACKED.byteLength + 1)),
      true
    );
    refreshHeaderChecksum(bytes);
  }, PACKED.byteLength + 1));

  assert.equal(result.findings.length, 0);
  assert.match(result.warnings[0] ?? "", /unconsumed input/);
});

void test("detectUpx ignores files with no PackHeader candidate", async () => {
  const input = createInput(bytes => bytes.fill(0, HEADER_START, SECTION_START));

  assert.deepEqual(await detectUpx(input), { findings: [], warnings: [] });
});

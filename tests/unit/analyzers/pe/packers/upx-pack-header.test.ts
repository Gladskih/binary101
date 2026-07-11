"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseUpxPackHeader,
  upxPackHeaderChecksum
} from "../../../../../analyzers/pe/packers/upx-pack-header.js";

const HEADER_BYTES = 32;
const OLD_HEADER_BYTES = 28;
const UPX_VERSION = 13;
const UPX_WIN64_FORMAT = 36;
const UPX_LZMA_METHOD = 14;
const UPX_LEVEL = 9;
const UNPACKED_BYTES = 0x3000;
const PACKED_BYTES = 0x1000;
const ORIGINAL_FILE_BYTES = 0x2800;
const HEADER_FIELDS = { version: 4, method: 6, level: 7 };

const createHeader = (): Uint8Array => {
  const bytes = new Uint8Array(HEADER_BYTES);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("UPX!"));
  view.setUint8(4, UPX_VERSION);
  view.setUint8(5, UPX_WIN64_FORMAT);
  view.setUint8(6, UPX_LZMA_METHOD);
  view.setUint8(7, UPX_LEVEL);
  view.setUint32(8, 0x11223344, true);
  view.setUint32(12, 0x55667788, true);
  view.setUint32(16, UNPACKED_BYTES, true);
  view.setUint32(20, PACKED_BYTES, true);
  view.setUint32(24, ORIGINAL_FILE_BYTES, true);
  view.setUint8(28, 0x49);
  view.setUint8(29, 8);
  view.setUint8(31, upxPackHeaderChecksum(bytes.subarray(0, HEADER_BYTES - 1)));
  return bytes;
};

void test("parseUpxPackHeader parses a checksummed modern PE header", () => {
  const result = parseUpxPackHeader(new DataView(createHeader().buffer), 0, 8);

  assert.ok(result && "header" in result);
  assert.equal(result.header.headerSize, HEADER_BYTES);
  assert.equal(result.header.method, UPX_LZMA_METHOD);
  assert.equal(result.header.unpackedSize, UNPACKED_BYTES);
  assert.equal(
    result.header.headerChecksum,
    upxPackHeaderChecksum(createHeader().subarray(0, HEADER_BYTES - 1))
  );
});

void test("parseUpxPackHeader rejects a checksum mismatch", () => {
  const bytes = createHeader();
  bytes[31] = (bytes[31] ?? 0) ^ 1;

  assert.deepEqual(parseUpxPackHeader(new DataView(bytes.buffer), 0, 8), {
    error: "UPX PackHeader checksum does not match."
  });
});

void test("parseUpxPackHeader accepts old headers without a checksum field", () => {
  const bytes = createHeader().slice(0, OLD_HEADER_BYTES);
  bytes[4] = 9;

  const result = parseUpxPackHeader(new DataView(bytes.buffer), 0, 8);

  assert.ok(result && "header" in result);
  assert.equal(result.header.headerSize, OLD_HEADER_BYTES);
  assert.equal(result.header.headerChecksum, null);
});

void test("parseUpxPackHeader ignores data without PackHeader magic", () => {
  const bytes = createHeader();
  bytes[0] = 0;

  assert.equal(parseUpxPackHeader(new DataView(bytes.buffer), 0, 8), null);
});

void test("parseUpxPackHeader rejects truncated headers", () => {
  const bytes = createHeader().slice(0, HEADER_BYTES - 1);

  assert.deepEqual(parseUpxPackHeader(new DataView(bytes.buffer), 0, 8), {
    error: "UPX PackHeader is truncated."
  });
});

void test("parseUpxPackHeader rejects PE formats for the wrong pointer width", () => {
  assert.deepEqual(parseUpxPackHeader(new DataView(createHeader().buffer), 0, 4), {
    error: "UPX PackHeader format does not match this PE image."
  });
});

void test("parseUpxPackHeader rejects invalid packed sizes", () => {
  const bytes = createHeader();
  new DataView(bytes.buffer).setUint32(20, UNPACKED_BYTES, true);
  bytes[31] = upxPackHeaderChecksum(bytes.subarray(0, HEADER_BYTES - 1));

  assert.deepEqual(parseUpxPackHeader(new DataView(bytes.buffer), 0, 8), {
    error: "UPX PackHeader packed size is not smaller than its unpacked size."
  });
});

void test("parseUpxPackHeader parses non-zero filter MRU fields", () => {
  const bytes = createHeader();
  bytes[30] = 7;
  bytes[31] = upxPackHeaderChecksum(bytes.subarray(0, HEADER_BYTES - 1));

  const result = parseUpxPackHeader(new DataView(bytes.buffer), 0, 8);

  assert.ok(result && "header" in result);
  assert.equal(result.header.filterMru, 8);
});

const invalidHeaderCases = [
  { field: HEADER_FIELDS.version, value: 0xff, error: /version/ },
  { field: HEADER_FIELDS.method, value: 13, error: /method/ },
  { field: HEADER_FIELDS.level, value: 0, error: /level/ }
] as const;

for (const invalid of invalidHeaderCases) {
  void test(`parseUpxPackHeader rejects invalid byte field ${invalid.field}`, () => {
    const bytes = createHeader();
    bytes[invalid.field] = invalid.value;
    bytes[HEADER_BYTES - 1] = upxPackHeaderChecksum(bytes.subarray(0, HEADER_BYTES - 1));

    const result = parseUpxPackHeader(new DataView(bytes.buffer), 0, 8);

    assert.ok(result && "error" in result);
    assert.match(result.error, invalid.error);
  });
}

void test("parseUpxPackHeader rejects too-small sizes", () => {
  const bytes = createHeader();
  new DataView(bytes.buffer).setUint32(20, 1, true);
  bytes[31] = upxPackHeaderChecksum(bytes.subarray(0, HEADER_BYTES - 1));

  assert.deepEqual(parseUpxPackHeader(new DataView(bytes.buffer), 0, 8), {
    error: "UPX PackHeader sizes are too small."
  });
});

void test("parseUpxPackHeader rejects invalid original file sizes", () => {
  const bytes = createHeader();
  new DataView(bytes.buffer).setUint32(24, 0, true);
  bytes[31] = upxPackHeaderChecksum(bytes.subarray(0, HEADER_BYTES - 1));

  assert.deepEqual(parseUpxPackHeader(new DataView(bytes.buffer), 0, 8), {
    error: "UPX PackHeader original file size is invalid."
  });
});

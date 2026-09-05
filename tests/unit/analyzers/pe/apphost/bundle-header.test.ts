"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { parsePeAppHostBundleHeader } from
  "../../../../../analyzers/pe/apphost/bundle-header.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const createReader = (bytes: Uint8Array) => {
  const file = new MockFile(bytes, "bundle.bin");
  return createFileRangeReader(file, 0, file.size);
};

const createHeader = (
  majorVersion = 6,
  embeddedFileCount = 1,
  bundleId = new TextEncoder().encode("id")
): Uint8Array => {
  // Synthetic 128-byte file: enough room for the short ID and the 40-byte v2 extension.
  // Field offsets follow header_fixed_t in dotnet/runtime bundle/header.h.
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, majorVersion, true);
  view.setUint32(4, 0, true);
  view.setInt32(8, embeddedFileCount, true);
  bytes[12] = bundleId.byteLength;
  bytes.set(bundleId, 13);
  return bytes;
};

void test("parsePeAppHostBundleHeader rejects invalid source offsets", async () => {
  const reader = createReader(new Uint8Array(16));

  assert.match((await parsePeAppHostBundleHeader(reader, -1)).issues[0] ?? "", /outside/);
  assert.match((await parsePeAppHostBundleHeader(reader, 16)).issues[0] ?? "", /outside/);
  assert.match((await parsePeAppHostBundleHeader(reader, Number.NaN)).issues[0] ?? "", /outside/);
});

void test("parsePeAppHostBundleHeader reports a truncated fixed header", async () => {
  const result = await parsePeAppHostBundleHeader(createReader(new Uint8Array(12)), 0);

  assert.deepEqual(result, {
    issues: ["Single-file bundle header is truncated before its bundle ID."]
  });
});

void test("parsePeAppHostBundleHeader rejects zero and overlong length encodings", async () => {
  const zeroLength = createHeader();
  zeroLength[12] = 0;
  const continued = createHeader();
  continued[12] = 0x80;
  continued[13] = 0x80;

  assert.match((await parsePeAppHostBundleHeader(createReader(zeroLength), 0)).issues[0] ?? "",
    /invalid length/);
  assert.match((await parsePeAppHostBundleHeader(createReader(continued), 0)).issues[0] ?? "",
    /invalid length/);
});

void test("parsePeAppHostBundleHeader rejects a truncated two-byte length encoding", async () => {
  const bytes = createHeader().subarray(0, 13);
  bytes[12] = 0x80;

  const result = await parsePeAppHostBundleHeader(createReader(bytes), 0);

  assert.match(result.issues[0] ?? "", /invalid length/);
});

void test("parsePeAppHostBundleHeader parses version-one two-byte bundle IDs", async () => {
  const id = new TextEncoder().encode("a".repeat(128));
  const bytes = new Uint8Array(12 + 2 + id.byteLength);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 1, true);
  view.setInt32(8, 2, true);
  // BinaryWriter 7-bit length encoding for 128 is 0x80, 0x01.
  bytes.set([0x80, 0x01], 12);
  bytes.set(id, 14);

  const result = await parsePeAppHostBundleHeader(createReader(bytes), 0);

  assert.equal(result.header?.majorVersion, 1);
  assert.equal(result.header?.bundleId, "a".repeat(128));
  assert.equal(result.header?.depsJson, undefined);
  assert.deepEqual(result.issues, []);
});

void test("parsePeAppHostBundleHeader parses version-two optional locations", async () => {
  const bytes = createHeader(2, 1, new TextEncoder().encode("v2"));
  const fields = 15;
  const view = new DataView(bytes.buffer);
  view.setBigInt64(fields, 1n, true);
  view.setBigInt64(fields + 8, 127n, true);

  const result = await parsePeAppHostBundleHeader(new MockFile(bytes), 0);

  assert.equal(result.header?.majorVersion, 2);
  assert.deepEqual(result.header?.depsJson, { offset: 1n, size: 127n });
  assert.deepEqual(result.issues, []);
});

void test("parsePeAppHostBundleHeader preserves malformed header findings", async () => {
  const bytes = createHeader(9, 0, Uint8Array.from([0xff]));
  const view = new DataView(bytes.buffer);
  const fields = 14;
  view.setBigInt64(fields, -1n, true);
  view.setBigInt64(fields + 8, 1n, true);
  view.setBigInt64(fields + 16, 1n, true);
  view.setBigInt64(fields + 24, 0n, true);
  view.setBigUint64(fields + 32, 2n, true);

  const result = await parsePeAppHostBundleHeader(createReader(bytes), 0);

  assert.equal(result.header?.bundleId, null);
  assert.ok(result.issues.some(issue => issue.includes("version 9.0")));
  assert.ok(result.issues.some(issue => issue.includes("declares no embedded files")));
  assert.ok(result.issues.some(issue => issue.includes("not valid UTF-8")));
  assert.ok(result.issues.some(issue => issue.includes("deps.json")));
  assert.ok(result.issues.some(issue => issue.includes("runtimeconfig.json")));
  assert.ok(result.issues.some(issue => issue.includes("unknown flag bits")));
});

void test("parsePeAppHostBundleHeader reports a truncated variable header", async () => {
  const bytes = createHeader().subarray(0, 20);

  const result = await parsePeAppHostBundleHeader(createReader(bytes), 0);

  assert.match(result.issues.at(-1) ?? "", /header is truncated/);
  assert.equal(result.header, undefined);
});

void test("parsePeAppHostBundleHeader retains nonzero minor versions and negative file counts", async () => {
  // A negative signed count whose byte reversal becomes positive detects endian mistakes.
  const bytes = createHeader(6, -65536);
  new DataView(bytes.buffer).setUint32(4, 1, true);

  const result = await parsePeAppHostBundleHeader(createReader(bytes), 0);

  assert.equal(result.header?.minorVersion, 1);
  assert.equal(result.header?.embeddedFileCount, -65536);
  assert.ok(result.issues.includes("Unsupported single-file bundle header version 6.1."));
  assert.match(result.issues.join(" "), /declares no embedded files/);
});

for (const [offset, size] of [[0n, 1n], [127n, 2n], [1n, -1n]]) {
  void test(`parsePeAppHostBundleHeader flags an invalid location ${offset} + ${size}`, async () => {
    const bytes = createHeader();
    // v2 fields follow the fixed 12 bytes, one length byte, and the two-byte ID.
    const view = new DataView(bytes.buffer);
    view.setBigInt64(15, offset!, true);
    view.setBigInt64(23, size!, true);

    const result = await parsePeAppHostBundleHeader(createReader(bytes), 0);

    assert.deepEqual(result.header?.depsJson, { offset, size });
    assert.deepEqual(result.issues, ["deps.json bundle location is outside the file."]);
  });
}

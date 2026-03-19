"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseClrMetadataRoot } from "../../analyzers/pe/clr-metadata-root.js";
import { MockFile } from "../helpers/mock-file.js";

const align4 = (value: number): number => (value + 3) & ~3;

void test("parseClrMetadataRoot reports unexpected metadata root signatures", async () => {
  const encoder = new TextEncoder();
  const metaOffset = 0x20;
  const metaSize = 0x40;
  const bytes = new Uint8Array(metaOffset + metaSize).fill(0);
  const dv = new DataView(bytes.buffer, metaOffset, metaSize);
  let cursor = 0;
  dv.setUint32(cursor, 0x11111111, true);
  cursor += 4;
  dv.setUint16(cursor, 1, true);
  cursor += 2;
  dv.setUint16(cursor, 1, true);
  cursor += 2;
  dv.setUint32(cursor, 0, true);
  cursor += 4;
  const versionBytes = encoder.encode("v1.0");
  dv.setUint32(cursor, versionBytes.length, true);
  cursor += 4;
  bytes.set(versionBytes, metaOffset + cursor);
  cursor = align4(cursor + versionBytes.length);
  dv.setUint16(cursor, 0, true);
  cursor += 2;
  dv.setUint16(cursor, 0, true);
  const issues: string[] = [];
  const meta = await parseClrMetadataRoot(
    new MockFile(bytes, "meta-bad-sig.bin"),
    metaOffset,
    metaSize,
    issues
  );
  assert.strictEqual(meta, null);
  assert.ok(issues.some(issue => issue.toLowerCase().includes("signature")));
});

void test("parseClrMetadataRoot parses stream headers beyond 0x4000 metadata offsets", async () => {
  const encoder = new TextEncoder();
  const metaOffset = 0x40;
  const metaSize = 0x5000;
  const bytes = new Uint8Array(metaOffset + metaSize).fill(0);
  const dv = new DataView(bytes.buffer, metaOffset, metaSize);
  let cursor = 0;
  dv.setUint32(cursor, 0x424a5342, true);
  cursor += 4;
  dv.setUint16(cursor, 1, true);
  cursor += 2;
  dv.setUint16(cursor, 1, true);
  cursor += 2;
  dv.setUint32(cursor, 0, true);
  cursor += 4;

  const versionLength = 0x4fd0;
  dv.setUint32(cursor, versionLength, true);
  cursor += 4;
  const versionPayload = new Uint8Array(versionLength).fill(0);
  versionPayload.set(encoder.encode("v9.9"));
  bytes.set(versionPayload, metaOffset + cursor);
  cursor = align4(cursor + versionLength);

  dv.setUint16(cursor, 0, true);
  cursor += 2;
  dv.setUint16(cursor, 1, true);
  cursor += 2;

  dv.setUint32(cursor, 0x40, true);
  cursor += 4;
  dv.setUint32(cursor, 0x80, true);
  cursor += 4;
  bytes.set(encoder.encode("#Strings\0"), metaOffset + cursor);

  const issues: string[] = [];
  const meta = await parseClrMetadataRoot(
    new MockFile(bytes, "meta-large-header.bin"),
    metaOffset,
    metaSize,
    issues
  );

  assert.ok(meta);
  assert.strictEqual(meta.version, "v9.9");
  assert.strictEqual(meta.streams.length, 1);
  assert.strictEqual(meta.streams[0]?.name, "#Strings");
  assert.deepStrictEqual(issues, []);
});

void test("parseClrMetadataRoot does not report an incomplete stream list when parsing stops at the stream cap", async () => {
  const metaOffset = 0x20;
  // 2049 is the smallest count above the hard cap of 2048, so this isolates the cap behavior precisely.
  const declaredStreamCount = 2049;
  const parsedStreamCount = 2048;
  const versionLength = 4;
  const streamHeaderBytes = 12;
  const metaSize = align4(16 + versionLength) + 4 + parsedStreamCount * streamHeaderBytes;
  const bytes = new Uint8Array(metaOffset + metaSize).fill(0);
  const dv = new DataView(bytes.buffer, metaOffset, metaSize);

  let cursor = 0;
  dv.setUint32(cursor, 0x424a5342, true);
  cursor += 4;
  dv.setUint16(cursor, 1, true);
  cursor += 2;
  dv.setUint16(cursor, 1, true);
  cursor += 2;
  dv.setUint32(cursor, 0, true);
  cursor += 4;
  dv.setUint32(cursor, versionLength, true);
  cursor += 4;
  bytes.set([0x76, 0x34, 0x2e, 0x30], metaOffset + cursor); // "v4.0"
  cursor = align4(cursor + versionLength);
  dv.setUint16(cursor, 0, true);
  cursor += 2;
  dv.setUint16(cursor, declaredStreamCount, true);
  cursor += 2;

  for (let index = 0; index < parsedStreamCount; index += 1) {
    dv.setUint32(cursor, 0, true);
    cursor += 4;
    dv.setUint32(cursor, 0, true);
    cursor += 4;
    bytes[metaOffset + cursor] = 0x53; // 'S'
    bytes[metaOffset + cursor + 1] = 0;
    cursor += 4;
  }

  const issues: string[] = [];
  const meta = await parseClrMetadataRoot(
    new MockFile(bytes, "meta-stream-cap.bin"),
    metaOffset,
    metaSize,
    issues
  );

  assert.ok(meta);
  assert.strictEqual(meta.streamCount, declaredStreamCount);
  assert.strictEqual(meta.streams.length, parsedStreamCount);
  assert.ok(issues.some(issue => issue.toLowerCase().includes("parsing capped")));
  assert.ok(!issues.some(issue => issue.toLowerCase().includes("incomplete")));
});

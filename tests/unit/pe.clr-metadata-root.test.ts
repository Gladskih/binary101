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
  const meta = await parseClrMetadataRoot(new MockFile(bytes, "meta-bad-sig.bin"), metaOffset, metaSize, issues);
  assert.strictEqual(meta, null);
  assert.ok(issues.some(issue => issue.toLowerCase().includes("signature")));
});

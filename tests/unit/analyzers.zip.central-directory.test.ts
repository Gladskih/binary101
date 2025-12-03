"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { annotateEntryDataOffsets, parseCentralDirectoryEntries } from "../../analyzers/zip/central-directory.js";
import type { ZipCentralDirectoryEntry } from "../../analyzers/zip/index.js";
import { MockFile } from "../helpers/mock-file.js";

const buildCdEntry = (): DataView => {
  const name = new TextEncoder().encode("file.txt");
  const comment = new TextEncoder().encode("note");
  const extra = new Uint8Array([0x01, 0x00, 0x08, 0x00, 0x88, 0x77, 0x00, 0x00, 0x99, 0x88, 0x00, 0x00]);
  const total = 46 + name.length + extra.length + comment.length;
  const buf = new Uint8Array(total);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, 0x02014b50, true);
  dv.setUint16(8, 0, true);
  dv.setUint16(10, 0, true);
  dv.setUint16(12, 0, true);
  dv.setUint16(14, 0, true);
  dv.setUint32(16, 0xdeadbeef, true);
  dv.setUint32(20, 4, true);
  dv.setUint32(24, 4, true);
  dv.setUint16(28, name.length, true);
  dv.setUint16(30, extra.length, true);
  dv.setUint16(32, comment.length, true);
  dv.setUint32(42, 0, true);
  buf.set(name, 46);
  buf.set(extra, 46 + name.length);
  buf.set(comment, 46 + name.length + extra.length);
  return dv;
};

void test("parseCentralDirectoryEntries reads name, comment and ZIP64 extra", () => {
  const dv = buildCdEntry();
  const issues: string[] = [];
  const entries = parseCentralDirectoryEntries(dv, issues);
  assert.strictEqual(entries.length, 1);
  const [entry] = entries;
  if (!entry) assert.fail("Entry not parsed");
  assert.strictEqual(entry.fileName, "file.txt");
  assert.strictEqual(entry.comment, "note");
  assert.strictEqual(typeof entry.uncompressedSize, "number");
  assert.deepEqual(issues, []);
});

void test("annotateEntryDataOffsets sets data offsets and errors for bad headers", async () => {
  const entry: ZipCentralDirectoryEntry = {
    index: 0,
    fileName: "file.txt",
    comment: "",
    compressionMethod: 0,
    compressionName: "Stored",
    flags: 0,
    isUtf8: false,
    isEncrypted: false,
    usesDataDescriptor: false,
    modTimeIso: null,
    crc32: 0,
    compressedSize: 4,
    uncompressedSize: 4,
    diskNumberStart: 0,
    internalAttrs: 0,
    externalAttrs: 0,
    localHeaderOffset: 0
  };
  const localHeader = new Uint8Array(30).fill(0);
  const dv = new DataView(localHeader.buffer);
  dv.setUint32(0, 0x04034b50, true);
  const file = new MockFile(localHeader);
  await annotateEntryDataOffsets(file, [entry]);
  assert.strictEqual(entry.dataOffset, 30);
});

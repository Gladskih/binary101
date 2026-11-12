"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { annotateEntryDataOffsets, parseCentralDirectoryEntries } from "../../../../analyzers/zip/central-directory.js";
import type { ZipCentralDirectoryEntry } from "../../../../analyzers/zip/index.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createZipWithEntries } from "../../../fixtures/zip-fixtures.js";
import { parseZip } from "../../../../analyzers/zip/index.js";

void test("nearby local headers share bounded reads even in shuffled directory order", async context => {
  const file = createZipWithEntries(Array.from({ length: 100 }, (_, index) => ({
    name: `res/item-${index}.xml`, method: 0, data: new Uint8Array([index])
  })));
  const result = await parseZip(file);
  const entries = result!.centralDirectory!.entries.reverse();
  const original = JSON.stringify(entries);
  const slice = context.mock.method(file, "slice");

  await annotateEntryDataOffsets(file, entries);

  assert.ok(slice.mock.callCount() < 10, "headers must not each issue a separate file read");
  assert.equal(JSON.stringify(entries), original);
});

void test("local header failures preserve the first extraction diagnostic", async () => {
  const entry = (await parseZip(createZipWithEntries()))!.centralDirectory!.entries[0]!;
  const unsupported = { ...entry, localHeaderOffset: BigInt(Number.MAX_SAFE_INTEGER) + 1n };
  const truncated = { ...entry, localHeaderOffset: 40 };
  const mismatch = { ...entry, localHeaderOffset: 0 };
  const previous = { ...mismatch, extractError: "Existing error" };

  await annotateEntryDataOffsets(new MockFile(new Uint8Array(64)),
    [unsupported, truncated, mismatch, previous]);

  assert.equal(unsupported.extractError, "Local header offset exceeds supported range.");
  assert.equal(truncated.extractError, "Local file header is truncated or missing.");
  assert.equal(mismatch.extractError, "Local file header signature mismatch.");
  assert.equal(previous.extractError, "Existing error");
});

void test("local names and extra fields locate the exact start and end of compressed data", async () => {
  const entry = { ...(await parseZip(createZipWithEntries()))!.centralDirectory!.entries[0]!,
    localHeaderOffset: 0n, compressedSize: 6 };
  const bytes = new Uint8Array(44);
  const header = new DataView(bytes.buffer);
  header.setUint32(0, 0x04034b50, true);
  header.setUint16(26, 3, true);
  header.setUint16(28, 5, true);

  await annotateEntryDataOffsets(new MockFile(bytes), [entry]);

  assert.deepEqual(entry.localHeader, { offset: 0, nameLength: 3, extraLength: 5 });
  assert.equal(entry.dataOffset, 38);
  assert.equal(entry.dataEnd, 44);
  assert.equal(entry.extractError, undefined);
});

void test("local data may end exactly at EOF, while unsafe sizes and starts past EOF warn", async () => {
  const base = (await parseZip(createZipWithEntries()))!.centralDirectory!.entries[0]!;
  const empty = { ...base, localHeaderOffset: 0, compressedSize: 0 };
  const unsafe = { ...empty, compressedSize: BigInt(Number.MAX_SAFE_INTEGER) + 1n };
  const header = new Uint8Array(30);
  new DataView(header.buffer).setUint32(0, 0x04034b50, true);

  await annotateEntryDataOffsets(new MockFile(header), [empty, unsafe]);

  assert.equal(empty.dataOffset, 30);
  assert.equal(empty.dataEnd, 30);
  assert.equal(empty.extractError, undefined);
  assert.equal(unsafe.extractError, "Compressed size exceeds supported range.");
  new DataView(header.buffer).setUint16(26, 1, true);
  const pastEnd = { ...unsafe };
  delete pastEnd.extractError;

  await annotateEntryDataOffsets(new MockFile(header), [pastEnd]);

  assert.equal(pastEnd.extractError, "Compressed data extends beyond the file size.");
});

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

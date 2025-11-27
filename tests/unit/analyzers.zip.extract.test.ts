"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseZip } from "../../analyzers/zip/index.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

const encoder = new TextEncoder();

type SingleEntryOptions = {
  name?: string;
  method?: number;
  dataBytes?: Uint8Array;
  flags?: number;
  compressedSize?: number;
  uncompressedSize?: number;
};

const buildSingleEntryZip = ({
  name = "file.bin",
  method = 0,
  dataBytes = encoder.encode("abc"),
  flags = 0,
  compressedSize,
  uncompressedSize
}: SingleEntryOptions = {}) => {
  const nameBytes = encoder.encode(name);
  const extraBytes = new Uint8Array(0);
  const compSize = compressedSize ?? dataBytes.length;
  const uncompSize = uncompressedSize ?? dataBytes.length;
  const crc32 = 0x12345678;

  const localHeaderSize = 30 + nameBytes.length + extraBytes.length;
  const localHeader = new Uint8Array(localHeaderSize);
  const lhdv = new DataView(localHeader.buffer);
  lhdv.setUint32(0, 0x04034b50, true);
  lhdv.setUint16(4, 20, true); // version needed
  lhdv.setUint16(6, flags, true);
  lhdv.setUint16(8, method, true);
  lhdv.setUint16(10, 0, true); // mod time
  lhdv.setUint16(12, 0, true); // mod date
  lhdv.setUint32(14, crc32, true);
  lhdv.setUint32(18, compSize >>> 0, true);
  lhdv.setUint32(22, uncompSize >>> 0, true);
  lhdv.setUint16(26, nameBytes.length, true);
  lhdv.setUint16(28, extraBytes.length, true);
  localHeader.set(nameBytes, 30);

  const dataOffset = localHeaderSize;
  const cdOffset = dataOffset + dataBytes.length;

  const cdSize = 46 + nameBytes.length + extraBytes.length;
  const cdEntry = new Uint8Array(cdSize);
  const cddv = new DataView(cdEntry.buffer);
  cddv.setUint32(0, 0x02014b50, true);
  cddv.setUint16(4, 20, true); // version made by
  cddv.setUint16(6, 20, true); // version needed
  cddv.setUint16(8, flags, true);
  cddv.setUint16(10, method, true);
  cddv.setUint16(12, 0, true); // mod time
  cddv.setUint16(14, 0, true); // mod date
  cddv.setUint32(16, crc32, true);
  cddv.setUint32(20, compSize >>> 0, true);
  cddv.setUint32(24, uncompSize >>> 0, true);
  cddv.setUint16(28, nameBytes.length, true);
  cddv.setUint16(30, extraBytes.length, true);
  cddv.setUint16(32, 0, true); // comment length
  cddv.setUint16(34, 0, true); // disk start
  cddv.setUint16(36, 0, true); // internal attrs
  cddv.setUint32(38, 0, true); // external attrs
  cddv.setUint32(42, 0, true); // local header offset
  cdEntry.set(nameBytes, 46);

  const eocd = new Uint8Array(22);
  const eocdDv = new DataView(eocd.buffer);
  eocdDv.setUint32(0, 0x06054b50, true);
  eocdDv.setUint16(4, 0, true); // disk number
  eocdDv.setUint16(6, 0, true); // central dir disk
  eocdDv.setUint16(8, 1, true); // entries this disk
  eocdDv.setUint16(10, 1, true); // total entries
  eocdDv.setUint32(12, cdSize, true);
  eocdDv.setUint32(16, cdOffset, true);
  eocdDv.setUint16(20, 0, true); // comment length

  const totalSize = cdOffset + cdSize + eocd.length;
  const bytes = new Uint8Array(totalSize);
  bytes.set(localHeader, 0);
  bytes.set(dataBytes, dataOffset);
  bytes.set(cdEntry, cdOffset);
  bytes.set(eocd, cdOffset + cdSize);

  return {
    file: new MockFile(bytes, "single-entry.zip", "application/zip"),
    dataOffset,
    dataLength: dataBytes.length
  };
};

void test("parseZip annotates data offsets for stored entries", async () => {
  const { file, dataOffset, dataLength } = buildSingleEntryZip({
    name: "note.txt",
    method: 0,
    dataBytes: encoder.encode("test")
  });
  const result = expectDefined(await parseZip(file));
  const centralDirectory = expectDefined(result.centralDirectory);
  const entry = expectDefined(centralDirectory.entries[0]);

  assert.strictEqual(entry.dataOffset, dataOffset);
  assert.strictEqual(entry.dataLength, dataLength);
  assert.strictEqual(entry.extractError, undefined);
  assert.deepEqual(entry.localHeader, { nameLength: 8, extraLength: 0, offset: 0 });
});

void test("parseZip marks unsupported compression methods", async () => {
  const { file } = buildSingleEntryZip({
    name: "data.bin",
    method: 12, // BZIP2
    dataBytes: encoder.encode("payload")
  });
  const result = expectDefined(await parseZip(file));
  const centralDirectory = expectDefined(result.centralDirectory);
  const entry = expectDefined(centralDirectory.entries[0]);

  assert.strictEqual(entry.dataOffset, 30 + "data.bin".length);
  assert.strictEqual(entry.dataLength, "payload".length);
  const extractError = expectDefined(entry.extractError);
  assert.match(extractError, /not supported/i);
});

void test("parseZip flags entries whose compressed data runs past the file size", async () => {
  const { file } = buildSingleEntryZip({
    name: "short.bin",
    method: 0,
    dataBytes: new Uint8Array([0xaa]),
    compressedSize: 999
  });
  const result = expectDefined(await parseZip(file));
  const centralDirectory = expectDefined(result.centralDirectory);
  const entry = expectDefined(centralDirectory.entries[0]);

  const extractError = expectDefined(entry.extractError);
  assert.match(extractError, /beyond the file size/i);
});

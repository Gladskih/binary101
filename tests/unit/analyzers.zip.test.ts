import assert from "node:assert/strict";
import { test } from "node:test";
import { parseZip } from "../../dist/analyzers/zip/index.js";

// Mock the File object for Node.js environment
class MockFile {
  buffer: Uint8Array;
  name: string;
  size: number;

  constructor(buffer: Uint8Array, name: string) {
    this.buffer = buffer;
    this.name = name;
    this.size = buffer.length;
  }

  slice(start: number, end?: number): MockFile {
    return new MockFile(this.buffer.slice(start, end), this.name);
  }

  async arrayBuffer(): Promise<ArrayBuffer> {
    return this.buffer.slice().buffer;
  }
}

const encoder = new TextEncoder();
type CentralDirectoryOptions = {
  extraBytes?: Uint8Array;
  commentBytes?: Uint8Array;
  compressionMethod?: number;
  compressedSize?: number;
  uncompressedSize?: number;
  localHeaderOffset?: number;
};

const buildDosDateTime = () => {
  const year = 2020 - 1980;
  const month = 5;
  const day = 4;
  const hours = 10;
  const minutes = 20;
  const seconds2 = Math.floor(30 / 2);
  const dosDate = (year << 9) | (month << 5) | day;
  const dosTime = (hours << 11) | (minutes << 5) | seconds2;
  return { dosDate, dosTime };
};

const buildCentralDirectoryEntry = (name: string, options: CentralDirectoryOptions = {}) => {
  const nameBytes = encoder.encode(name);
  const { dosDate, dosTime } = buildDosDateTime();
  const extraBytes = options.extraBytes || new Uint8Array(0);
  const commentBytes = options.commentBytes || new Uint8Array(0);
  const baseLength = 46 + nameBytes.length + extraBytes.length + commentBytes.length;
  const buffer = new ArrayBuffer(baseLength);
  const dv = new DataView(buffer);
  dv.setUint32(0, 0x02014b50, true);
  dv.setUint16(4, 20, true);
  dv.setUint16(6, 20, true);
  dv.setUint16(8, 0, true); // flags
  dv.setUint16(10, options.compressionMethod || 8, true);
  dv.setUint16(12, dosTime, true);
  dv.setUint16(14, dosDate, true);
  dv.setUint32(16, 0x12345678, true);
  dv.setUint32(20, options.compressedSize ?? 5, true);
  dv.setUint32(24, options.uncompressedSize ?? 5, true);
  dv.setUint16(28, nameBytes.length, true);
  dv.setUint16(30, extraBytes.length, true);
  dv.setUint16(32, commentBytes.length, true);
  dv.setUint16(34, 0, true);
  dv.setUint16(36, 0, true);
  dv.setUint32(38, 0x20, true);
  dv.setUint32(42, options.localHeaderOffset ?? 0, true);
  new Uint8Array(buffer, 46, nameBytes.length).set(nameBytes);
  if (extraBytes.length) {
    new Uint8Array(buffer, 46 + nameBytes.length, extraBytes.length).set(extraBytes);
  }
  if (commentBytes.length) {
    new Uint8Array(buffer, 46 + nameBytes.length + extraBytes.length, commentBytes.length).set(commentBytes);
  }
  return new Uint8Array(buffer);
};

const buildEocd = (cdSize, cdOffset, entryCount, placeholders = false) => {
  const bytes = new Uint8Array(22);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 0x06054b50, true);
  dv.setUint16(4, 0, true);
  dv.setUint16(6, 0, true);
  dv.setUint16(8, placeholders ? 0xffff : entryCount, true);
  dv.setUint16(10, placeholders ? 0xffff : entryCount, true);
  dv.setUint32(12, placeholders ? 0xffffffff : cdSize, true);
  dv.setUint32(16, placeholders ? 0xffffffff : cdOffset, true);
  dv.setUint16(20, 0, true);
  return bytes;
};

const buildZip64Extra = (uncompressed, compressed, offset) => {
  const bytes = new Uint8Array(28);
  const dv = new DataView(bytes.buffer);
  dv.setUint16(0, 0x0001, true);
  dv.setUint16(2, 24, true);
  dv.setBigUint64(4, uncompressed, true);
  dv.setBigUint64(12, compressed, true);
  dv.setBigUint64(20, offset, true);
  return bytes;
};

const buildZip64Record = (cdSize, cdOffset) => {
  const bytes = new Uint8Array(56);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 0x06064b50, true);
  dv.setBigUint64(4, 44n, true);
  dv.setUint16(12, 45, true);
  dv.setUint16(14, 45, true);
  dv.setUint32(16, 0, true);
  dv.setUint32(20, 0, true);
  dv.setBigUint64(24, 1n, true);
  dv.setBigUint64(32, 1n, true);
  dv.setBigUint64(40, BigInt(cdSize), true);
  dv.setBigUint64(48, BigInt(cdOffset), true);
  return bytes;
};

const buildZip64Locator = zip64Offset => {
  const bytes = new Uint8Array(20);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 0x07064b50, true);
  dv.setUint32(4, 0, true);
  dv.setBigUint64(8, BigInt(zip64Offset), true);
  dv.setUint32(16, 1, true);
  return bytes;
};

test("parseZip correctly identifies a minimal, empty ZIP file", async () => {
  const emptyZipBytes = new Uint8Array([
    0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);
  const mockFile = new MockFile(emptyZipBytes, "empty.zip");

  const result = await parseZip(mockFile);

  assert.ok(result, "parseZip should return a result for a valid empty ZIP");
  assert.strictEqual(result.eocd.totalEntries, 0, "EOCD should report 0 entries");
  assert.strictEqual(result.centralDirectory.entries.length, 0, "There should be no central directory entries");
  assert.strictEqual(result.issues.length, 0, "There should be no parsing issues for a valid empty zip");
});

test("parseZip returns null for a non-ZIP file", async () => {
  const notZipBytes = new Uint8Array([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
  ]);
  const mockFile = new MockFile(notZipBytes, "not-a-zip.bin");

  const result = await parseZip(mockFile);

  assert.strictEqual(result, null, "parseZip should return null for a file that is not a ZIP");
});

test("parseZip parses central directory entries with timestamps", async () => {
  const cdEntry = buildCentralDirectoryEntry("hello.txt", { compressedSize: 7, uncompressedSize: 7 });
  const cdSize = cdEntry.length;
  const eocd = buildEocd(cdSize, 0, 1);
  const buffer = new Uint8Array(cdSize + eocd.length);
  buffer.set(cdEntry, 0);
  buffer.set(eocd, cdSize);
  const result = await parseZip(new MockFile(buffer, "with-cd.zip"));

  assert.ok(result);
  assert.strictEqual(result.centralDirectory.entries.length, 1);
  const [entry] = result.centralDirectory.entries;
  assert.strictEqual(entry.fileName, "hello.txt");
  assert.strictEqual(entry.compressionName, "Deflated");
  assert.ok(entry.modTimeIso.includes("2020-05-04T10:20:30"));
  assert.strictEqual(result.issues.length, 0);
});

test("parseZip reads ZIP64 metadata and extra fields", async () => {
  const zip64Sizes = {
    uncompressed: 0x111111111n,
    compressed: 0x222222222n,
    offset: 0x333333333n
  };
  const extra = buildZip64Extra(zip64Sizes.uncompressed, zip64Sizes.compressed, zip64Sizes.offset);
  const cdEntry = buildCentralDirectoryEntry("big.bin", {
    compressedSize: 0xffffffff,
    uncompressedSize: 0xffffffff,
    localHeaderOffset: 0xffffffff,
    extraBytes: extra
  });
  const cdSize = cdEntry.length;
  const zip64RecordOffset = cdSize;
  const zip64Record = buildZip64Record(cdSize, 0);
  const locator = buildZip64Locator(zip64RecordOffset);
  const eocd = buildEocd(cdSize, 0, 1, true);

  const totalSize = cdSize + zip64Record.length + locator.length + eocd.length;
  const buffer = new Uint8Array(totalSize);
  let cursor = 0;
  buffer.set(cdEntry, cursor);
  cursor += cdSize;
  buffer.set(zip64Record, cursor);
  cursor += zip64Record.length;
  buffer.set(locator, cursor);
  cursor += locator.length;
  buffer.set(eocd, cursor);

  const result = await parseZip(new MockFile(buffer, "zip64.zip"));
  assert.ok(result.zip64);
  assert.ok(result.zip64Locator);
  assert.strictEqual(result.centralDirectory.entries.length, 1);
  const [entry] = result.centralDirectory.entries;
  assert.strictEqual(entry.uncompressedSize, zip64Sizes.uncompressed);
  assert.strictEqual(entry.compressedSize, zip64Sizes.compressed);
  assert.strictEqual(entry.localHeaderOffset, zip64Sizes.offset);
  assert.strictEqual(result.centralDirectory.truncated, false);
  assert.ok(result.issues.every(issue => issue.toLowerCase().indexOf("error") === -1));
});

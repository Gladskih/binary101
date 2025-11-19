import assert from "node:assert/strict";
import { test } from "node:test";
import { parseZip } from "../../analyzers/zip/index.js";

// Mock the File object for Node.js environment
class MockFile {
  constructor(buffer, name) {
    this.buffer = buffer;
    this.name = name;
    this.size = buffer.length;
  }

  slice(start, end) {
    return new MockFile(this.buffer.slice(start, end));
  }

  async arrayBuffer() {
    return this.buffer.buffer;
  }
}

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

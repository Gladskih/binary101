import assert from "node:assert/strict";
import { test } from "node:test";
import {
  type GzipHeaderScanState,
  createGzipHeader,
  parseGzipOptionalHeader
} from "../../analyzers/gzip/header-scan.js";

const makeGzipFile = (bytes: number[]): File =>
  new File([new Uint8Array(bytes)], "fixture.gz");

void test("createGzipHeader decodes fixed gzip fields", () => {
  const header = createGzipHeader(new Uint8Array([
    0x1f, 0x8b, 0x08, 0x08, 0x78, 0x56, 0x34, 0x12, 0x02, 0x03
  ]));
  assert.equal(header.compressionMethodName, "Deflate");
  assert.equal(header.flags.fname, true);
  assert.equal(header.mtime, 0x12345678);
  assert.equal(header.extraFlags, 2);
  assert.equal(header.osName, "Unix");
});

void test("parseGzipOptionalHeader reads filename, comment, extra, and header crc", async () => {
  const bytes = [
    0x1f, 0x8b, 0x08, 0x1e, 0, 0, 0, 0, 0, 3,
    0x02, 0x00, 0xaa, 0xbb,
    0x61, 0x2e, 0x74, 0x78, 0x74, 0x00,
    0x6f, 0x6b, 0x00,
    0x34, 0x12
  ];
  const state: GzipHeaderScanState = {
    file: makeGzipFile(bytes),
    headerBytes: new Uint8Array(bytes.slice(0, 10)),
    issues: []
  };
  const header = createGzipHeader(state.headerBytes);
  await parseGzipOptionalHeader(state, header);
  assert.equal(header.extra?.xlen, 2);
  assert.equal(header.fileName, "a.txt");
  assert.equal(header.comment, "ok");
  assert.equal(header.headerCrc16, 0x1234);
  assert.equal(header.headerBytesTotal, bytes.length);
  assert.deepEqual(state.issues, []);
});

void test("parseGzipOptionalHeader reports truncated filename without throwing", async () => {
  const bytes = [0x1f, 0x8b, 0x08, 0x08, 0, 0, 0, 0, 0, 3, 0x6e, 0x61, 0x6d, 0x65];
  const state: GzipHeaderScanState = {
    file: makeGzipFile(bytes),
    headerBytes: new Uint8Array(bytes.slice(0, 10)),
    issues: []
  };
  const header = createGzipHeader(state.headerBytes);
  await parseGzipOptionalHeader(state, header);
  assert.equal(header.truncated, true);
  assert.equal(header.fileName, "name");
  assert.match(state.issues.join("\n"), /Original filename is not NUL-terminated/);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  type GzipHeaderScanState,
  createGzipHeader,
  parseGzipOptionalHeader
} from "../../../../analyzers/gzip/header-scan.js";

// RFC 1952, section 2.3.1 defines the fixed gzip header fields and FLG bits.
// https://www.rfc-editor.org/rfc/rfc1952#section-2.3.1
const RFC1952_GZIP_ID1 = 0x1f;
const RFC1952_GZIP_ID2 = 0x8b;
const RFC1952_DEFLATE_COMPRESSION_METHOD = 8;
const RFC1952_BASE_HEADER_BYTES = 10;
const RFC1952_FLAG_FHCRC = 0x02;
const RFC1952_FLAG_FEXTRA = 0x04;
const RFC1952_FLAG_FNAME = 0x08;
const RFC1952_FLAG_FCOMMENT = 0x10;
const GZIP_UNIX_OS = 3;
const GZIP_MAX_COMPRESSION_EXTRA_FLAGS = 2;

const makeGzipFile = (bytes: number[]): File =>
  new File([new Uint8Array(bytes)], "fixture.gz");

void test("createGzipHeader decodes fixed gzip fields", () => {
  const header = createGzipHeader(new Uint8Array([
    RFC1952_GZIP_ID1, RFC1952_GZIP_ID2, RFC1952_DEFLATE_COMPRESSION_METHOD, RFC1952_FLAG_FNAME,
    0x78, 0x56, 0x34, 0x12, GZIP_MAX_COMPRESSION_EXTRA_FLAGS, GZIP_UNIX_OS
  ]));
  assert.equal(header.compressionMethodName, "Deflate");
  assert.equal(header.flags.fname, true);
  assert.equal(header.mtime, 0x12345678);
  assert.equal(header.extraFlags, 2);
  assert.equal(header.osName, "Unix");
});

void test("parseGzipOptionalHeader reads filename, comment, extra, and header crc", async () => {
  const bytes = [
    RFC1952_GZIP_ID1, RFC1952_GZIP_ID2, RFC1952_DEFLATE_COMPRESSION_METHOD,
    RFC1952_FLAG_FEXTRA | RFC1952_FLAG_FNAME | RFC1952_FLAG_FCOMMENT | RFC1952_FLAG_FHCRC,
    0, 0, 0, 0, 0, GZIP_UNIX_OS,
    0x02, 0x00, 0xaa, 0xbb,
    0x61, 0x2e, 0x74, 0x78, 0x74, 0x00,
    0x6f, 0x6b, 0x00,
    0x34, 0x12
  ];
  const state: GzipHeaderScanState = {
    file: makeGzipFile(bytes),
    headerBytes: new Uint8Array(bytes.slice(0, RFC1952_BASE_HEADER_BYTES)),
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
  const bytes = [
    RFC1952_GZIP_ID1, RFC1952_GZIP_ID2, RFC1952_DEFLATE_COMPRESSION_METHOD, RFC1952_FLAG_FNAME,
    0, 0, 0, 0, 0, GZIP_UNIX_OS, 0x6e, 0x61, 0x6d, 0x65
  ];
  const state: GzipHeaderScanState = {
    file: makeGzipFile(bytes),
    headerBytes: new Uint8Array(bytes.slice(0, RFC1952_BASE_HEADER_BYTES)),
    issues: []
  };
  const header = createGzipHeader(state.headerBytes);
  await parseGzipOptionalHeader(state, header);
  assert.equal(header.truncated, true);
  assert.equal(header.fileName, "name");
  assert.match(state.issues.join("\n"), /Original filename is not NUL-terminated/);
});

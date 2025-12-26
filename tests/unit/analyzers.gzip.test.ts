"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseGzip } from "../../analyzers/gzip/index.js";
import { createGzipFile, createGzipWithTruncatedExtra, createTruncatedGzipFile } from "../fixtures/gzip-fixtures.js";
import { crc32, encoder } from "../fixtures/archive-fixture-helpers.js";
import { MockFile } from "../helpers/mock-file.js";

const makeBaseHeader = (opts: { compressionMethod?: number; flags?: number; os?: number } = {}): Uint8Array => {
  const header = new Uint8Array(10).fill(0);
  header[0] = 0x1f;
  header[1] = 0x8b;
  header[2] = opts.compressionMethod ?? 0x08;
  header[3] = opts.flags ?? 0x00;
  header[9] = opts.os ?? 3;
  return header;
};

void test("parseGzip parses gzip header fields and trailer", async () => {
  const payload = encoder.encode("hello from gzip");
  const file = createGzipFile({
    payload,
    filename: "hello.txt",
    comment: "sample comment",
    extra: new Uint8Array([1, 2, 3, 4]),
    includeHeaderCrc16: true,
    mtime: 1_700_000_000,
    xfl: 2,
    os: 3
  });

  const parsed = await parseGzip(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.isGzip, true);
  assert.strictEqual(parsed.fileSize, file.size);

  assert.strictEqual(parsed.header.compressionMethod, 8);
  assert.match(parsed.header.compressionMethodName || "", /deflate/i);
  assert.strictEqual(parsed.header.flags.fextra, true);
  assert.strictEqual(parsed.header.flags.fname, true);
  assert.strictEqual(parsed.header.flags.fcomment, true);
  assert.strictEqual(parsed.header.flags.fhcrc, true);
  assert.strictEqual(parsed.header.flags.reservedBits, 0);
  assert.strictEqual(parsed.header.fileName, "hello.txt");
  assert.strictEqual(parsed.header.comment, "sample comment");
  assert.strictEqual(parsed.header.extra?.xlen, 4);

  assert.strictEqual(parsed.trailer.crc32, crc32(payload));
  assert.strictEqual(parsed.trailer.isize, payload.length);
  assert.ok(parsed.stream.compressedOffset != null);
  assert.ok(parsed.stream.compressedOffset > 0);
  assert.ok(parsed.stream.compressedSize != null);
  assert.ok(parsed.stream.compressedSize > 0);
});

void test("parseGzip returns null for non-gzip signatures", async () => {
  const file = new MockFile(new Uint8Array([0x00, 0x01, 0x02, 0x03]), "not.gz");
  const parsed = await parseGzip(file);
  assert.equal(parsed, null);
});

void test("parseGzip reports reserved gzip flags", async () => {
  const payload = encoder.encode("x");
  const file = createGzipFile({ payload, reservedFlagBits: 0xe0 });
  const parsed = await parseGzip(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.header.flags.reservedBits, 0xe0);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("reserved")));
});

void test("parseGzip reports truncated headers and trailers", async () => {
  const parsed = await parseGzip(createTruncatedGzipFile());
  assert.ok(parsed);
  assert.strictEqual(parsed.stream.truncatedFile, true);
  assert.strictEqual(parsed.header.truncated, true);
  assert.strictEqual(parsed.trailer.truncated, true);
  assert.ok(parsed.issues.length >= 1);
});

void test("parseGzip reports truncated extra fields", async () => {
  const parsed = await parseGzip(createGzipWithTruncatedExtra());
  assert.ok(parsed);
  assert.ok(parsed.header.extra?.truncated);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("extra")));
});

void test("parseGzip warns on unsupported compression methods", async () => {
  const payload = encoder.encode("hello");
  const file = createGzipFile({ payload, compressionMethod: 0, os: 99, includeHeaderCrc16: false });
  const parsed = await parseGzip(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.header.compressionMethod, 0);
  assert.strictEqual(parsed.header.compressionMethodName, null);
  assert.match(parsed.header.osName || "", /OS 99/);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("unsupported")));
});

void test("parseGzip reports missing XLEN when FEXTRA is set but header ends early", async () => {
  const file = new MockFile(makeBaseHeader({ flags: 0x04 }), "missing-xlen.gz", "application/gzip");
  const parsed = await parseGzip(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.header.flags.fextra, true);
  assert.strictEqual(parsed.header.extra, null);
  assert.strictEqual(parsed.header.truncated, true);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("xlen")));
});

void test("parseGzip reports missing CRC16 when FHCRC is set but bytes are missing", async () => {
  const file = new MockFile(makeBaseHeader({ flags: 0x02 }), "missing-fhcrc.gz", "application/gzip");
  const parsed = await parseGzip(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.header.flags.fhcrc, true);
  assert.strictEqual(parsed.header.headerCrc16, null);
  assert.strictEqual(parsed.header.truncated, true);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("crc16")));
});

void test("parseGzip reports unterminated filename", async () => {
  const header = makeBaseHeader({ flags: 0x08 });
  const nameBytes = encoder.encode("no-null-terminator");
  const bytes = new Uint8Array(header.length + nameBytes.length);
  bytes.set(header, 0);
  bytes.set(nameBytes, header.length);
  const file = new MockFile(bytes, "unterminated-name.gz", "application/gzip");
  const parsed = await parseGzip(file);
  assert.ok(parsed);
  assert.strictEqual(parsed.header.flags.fname, true);
  assert.match(parsed.header.fileName || "", /no-null-terminator/);
  assert.strictEqual(parsed.header.truncated, true);
  assert.ok(parsed.issues.some(issue => issue.toLowerCase().includes("filename")));
});

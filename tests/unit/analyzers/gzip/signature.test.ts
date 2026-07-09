"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  GZIP_BASE_HEADER_BYTES,
  GZIP_DEFLATE_COMPRESSION_METHOD,
  GZIP_FLAG_FCOMMENT,
  GZIP_FLAG_FEXTRA,
  GZIP_FLAG_FHCRC,
  GZIP_FLAG_FNAME,
  GZIP_FLAG_FTEXT,
  GZIP_ID1,
  GZIP_ID2,
  GZIP_RESERVED_FLAGS_MASK,
  hasGzipDeflateHeaderBytes,
  hasValidGzipDeflateHeaderView
} from "../../../../analyzers/gzip/signature.js";

// RFC 1952, section 2.3.1 defines the fixed gzip header fields and FLG bits.
// https://www.rfc-editor.org/rfc/rfc1952#section-2.3.1
const RFC1952_GZIP_ID1 = 0x1f;
const RFC1952_GZIP_ID2 = 0x8b;
const RFC1952_DEFLATE_COMPRESSION_METHOD = 8;
const RFC1952_BASE_HEADER_BYTES = 10;
const RFC1952_FLAG_FTEXT = 0x01;
const RFC1952_FLAG_FHCRC = 0x02;
const RFC1952_FLAG_FEXTRA = 0x04;
const RFC1952_FLAG_FNAME = 0x08;
const RFC1952_FLAG_FCOMMENT = 0x10;
const RFC1952_RESERVED_FLAGS_MASK = 0xe0;
const RFC1952_UNIX_OS = 3;

const viewFrom = (bytes: number[]): DataView =>
  new DataView(Uint8Array.from(bytes).buffer);

void test("exports gzip RFC 1952 signature constants", () => {
  assert.equal(GZIP_ID1, RFC1952_GZIP_ID1);
  assert.equal(GZIP_ID2, RFC1952_GZIP_ID2);
  assert.equal(GZIP_DEFLATE_COMPRESSION_METHOD, RFC1952_DEFLATE_COMPRESSION_METHOD);
  assert.equal(GZIP_BASE_HEADER_BYTES, RFC1952_BASE_HEADER_BYTES);
  assert.equal(GZIP_FLAG_FTEXT, RFC1952_FLAG_FTEXT);
  assert.equal(GZIP_FLAG_FHCRC, RFC1952_FLAG_FHCRC);
  assert.equal(GZIP_FLAG_FEXTRA, RFC1952_FLAG_FEXTRA);
  assert.equal(GZIP_FLAG_FNAME, RFC1952_FLAG_FNAME);
  assert.equal(GZIP_FLAG_FCOMMENT, RFC1952_FLAG_FCOMMENT);
  assert.equal(GZIP_RESERVED_FLAGS_MASK, RFC1952_RESERVED_FLAGS_MASK);
});

void test("hasGzipDeflateHeaderBytes recognizes RFC 1952 gzip deflate prefix", () => {
  assert.equal(
    hasGzipDeflateHeaderBytes(Uint8Array.of(
      RFC1952_GZIP_ID1,
      RFC1952_GZIP_ID2,
      RFC1952_DEFLATE_COMPRESSION_METHOD
    )),
    true
  );
  assert.equal(hasGzipDeflateHeaderBytes(Uint8Array.of(RFC1952_GZIP_ID1, RFC1952_GZIP_ID2)), false);
  assert.equal(hasGzipDeflateHeaderBytes(Uint8Array.of(RFC1952_GZIP_ID1, RFC1952_GZIP_ID2, 9)), false);
});

void test("hasValidGzipDeflateHeaderView validates base header length and reserved flags", () => {
  assert.equal(
    hasValidGzipDeflateHeaderView(viewFrom([
      RFC1952_GZIP_ID1, RFC1952_GZIP_ID2, RFC1952_DEFLATE_COMPRESSION_METHOD,
      0, 0, 0, 0, 0, 0, RFC1952_UNIX_OS
    ])),
    true
  );
  assert.equal(
    hasValidGzipDeflateHeaderView(viewFrom([
      RFC1952_GZIP_ID1,
      RFC1952_GZIP_ID2,
      RFC1952_DEFLATE_COMPRESSION_METHOD
    ])),
    false
  );
  assert.equal(
    hasValidGzipDeflateHeaderView(viewFrom([
      RFC1952_GZIP_ID1, RFC1952_GZIP_ID2, RFC1952_DEFLATE_COMPRESSION_METHOD,
      RFC1952_RESERVED_FLAGS_MASK, 0, 0, 0, 0, 0, RFC1952_UNIX_OS
    ])),
    false
  );
});

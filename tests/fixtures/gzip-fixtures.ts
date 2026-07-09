"use strict";

import { deflateRawSync } from "node:zlib";

import { MockFile } from "../helpers/mock-file.js";
import { crc32, encoder, u32le } from "./archive-fixture-helpers.js";

// RFC 1952, section 2.3.1: gzip ID1=0x1f, ID2=0x8b, CM=8 means "deflate",
// base headers are 10 bytes, and FLG uses bits 1-4 for optional sections.
// https://www.rfc-editor.org/rfc/rfc1952#section-2.3.1
const RFC1952_GZIP_ID1 = 0x1f;
const RFC1952_GZIP_ID2 = 0x8b;
const RFC1952_DEFLATE_COMPRESSION_METHOD = 8;
const RFC1952_BASE_HEADER_BYTES = 10;
const RFC1952_FLAG_FHCRC = 0x02;
const RFC1952_FLAG_FEXTRA = 0x04;
const RFC1952_FLAG_FNAME = 0x08;
const RFC1952_FLAG_FCOMMENT = 0x10;
const RFC1952_RESERVED_FLAGS_MASK = 0xe0;

const concatParts = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const part of parts) {
    out.set(part, cursor);
    cursor += part.length;
  }
  return out;
};

const u16le = (value: number): number[] => [value & 0xff, (value >> 8) & 0xff];

export const createGzipFile = (opts: {
  payload: Uint8Array;
  filename?: string | null;
  comment?: string | null;
  extra?: Uint8Array | null;
  includeHeaderCrc16?: boolean;
  reservedFlagBits?: number;
  compressionMethod?: number;
  mtime?: number;
  xfl?: number;
  os?: number;
  name?: string;
}): MockFile => {
  const {
    payload,
    filename = "hello.txt",
    comment = "gzip fixture",
    extra = new Uint8Array([1, 2, 3, 4, 5, 6]),
    includeHeaderCrc16 = true,
    reservedFlagBits = 0,
    compressionMethod = RFC1952_DEFLATE_COMPRESSION_METHOD,
    mtime = 1_700_000_000,
    xfl = 2,
    os = 3,
    name = "sample.gz"
  } = opts;

  const hasExtra = extra != null;
  const hasName = filename != null;
  const hasComment = comment != null;
  const hasHcrc = includeHeaderCrc16;
  const flags =
    (hasExtra ? RFC1952_FLAG_FEXTRA : 0) |
    (hasName ? RFC1952_FLAG_FNAME : 0) |
    (hasComment ? RFC1952_FLAG_FCOMMENT : 0) |
    (hasHcrc ? RFC1952_FLAG_FHCRC : 0) |
    (reservedFlagBits & RFC1952_RESERVED_FLAGS_MASK);

  const header = new Uint8Array(RFC1952_BASE_HEADER_BYTES);
  header[0] = RFC1952_GZIP_ID1;
  header[1] = RFC1952_GZIP_ID2;
  header[2] = compressionMethod & 0xff;
  header[3] = flags & 0xff;
  const dv = new DataView(header.buffer);
  dv.setUint32(4, mtime >>> 0, true);
  header[8] = xfl & 0xff;
  header[9] = os & 0xff;

  const parts: Uint8Array[] = [header];
  if (hasExtra && extra) {
    parts.push(new Uint8Array([...u16le(extra.length), ...extra]));
  }
  if (hasName && filename != null) {
    parts.push(encoder.encode(filename + "\0"));
  }
  if (hasComment && comment != null) {
    parts.push(encoder.encode(comment + "\0"));
  }
  if (hasHcrc) {
    parts.push(new Uint8Array([0xef, 0xbe]));
  }

  const compressed = new Uint8Array(deflateRawSync(Buffer.from(payload)));
  parts.push(compressed);

  const crc = crc32(payload);
  parts.push(new Uint8Array([...u32le(crc), ...u32le(payload.length)]));

  const bytes = concatParts(parts);
  return new MockFile(bytes, name, "application/gzip");
};

export const createTruncatedGzipFile = (): MockFile =>
  new MockFile(
    new Uint8Array([RFC1952_GZIP_ID1, RFC1952_GZIP_ID2, RFC1952_DEFLATE_COMPRESSION_METHOD]),
    "truncated.gz",
    "application/gzip"
  );

export const createGzipWithTruncatedExtra = (): MockFile => {
  const header = new Uint8Array(RFC1952_BASE_HEADER_BYTES);
  header[0] = RFC1952_GZIP_ID1;
  header[1] = RFC1952_GZIP_ID2;
  header[2] = RFC1952_DEFLATE_COMPRESSION_METHOD;
  header[3] = RFC1952_FLAG_FEXTRA;
  const dv = new DataView(header.buffer);
  dv.setUint32(4, 0, true);
  header[8] = 0;
  header[9] = 3;

  const extraHeader = new Uint8Array([0x0a, 0x00, 1, 2]);
  const bytes = concatParts([header, extraHeader]);
  return new MockFile(bytes, "bad-extra.gz", "application/gzip");
};

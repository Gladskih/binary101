"use strict";

import { deflateRawSync } from "node:zlib";

import { MockFile } from "../helpers/mock-file.js";
import { crc32, encoder, u32le } from "./archive-fixture-helpers.js";

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
    compressionMethod = 8,
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
    (hasExtra ? 0x04 : 0) |
    (hasName ? 0x08 : 0) |
    (hasComment ? 0x10 : 0) |
    (hasHcrc ? 0x02 : 0) |
    (reservedFlagBits & 0xe0);

  const header = new Uint8Array(10);
  header[0] = 0x1f;
  header[1] = 0x8b;
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
  new MockFile(new Uint8Array([0x1f, 0x8b, 0x08]), "truncated.gz", "application/gzip");

export const createGzipWithTruncatedExtra = (): MockFile => {
  const header = new Uint8Array(10);
  header[0] = 0x1f;
  header[1] = 0x8b;
  header[2] = 0x08;
  header[3] = 0x04;
  const dv = new DataView(header.buffer);
  dv.setUint32(4, 0, true);
  header[8] = 0;
  header[9] = 3;

  const extraHeader = new Uint8Array([0x0a, 0x00, 1, 2]);
  const bytes = concatParts([header, extraHeader]);
  return new MockFile(bytes, "bad-extra.gz", "application/gzip");
};

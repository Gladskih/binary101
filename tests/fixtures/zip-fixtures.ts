"use strict";

import { deflateRawSync } from "node:zlib";
import { MockFile } from "../helpers/mock-file.js";
import { crc32, encoder } from "./archive-fixture-helpers.js";

// Minimal EOCD only, central directory offset points outside file
export const createZipWithBadCdOffset = () =>
  new MockFile(
    new Uint8Array([
      0x50, 0x4b, 0x05, 0x06, // EOCD signature
      0x00, 0x00, 0x00, 0x00, // disk numbers
      0x01, 0x00, 0x01, 0x00, // entries this/total
      0xff, 0xff, 0xff, 0xff, // central dir size (invalid)
      0xff, 0xff, 0xff, 0xff, // central dir offset (invalid)
      0x00, 0x00 // comment length
    ]),
    "bad-cd.zip",
    "application/zip"
  );

// ZIP64 locator present but missing referenced EOCD
export const createZipWithMissingZip64 = () =>
  new MockFile(
    new Uint8Array([
      0x50, 0x4b, 0x06, 0x07, // ZIP64 EOCD locator signature
      0x00, 0x00, 0x00, 0x00, // disk with EOCD
      0x10, 0x00, 0x00, 0x00, // offset to ZIP64 EOCD (points beyond file)
      0x01, 0x00, 0x00, 0x00, // total disks
      0x50, 0x4b, 0x05, 0x06, // EOCD signature
      0x00, 0x00, 0x00, 0x00, // disk numbers
      0x00, 0x00, 0x00, 0x00, // entries this/total
      0x00, 0x00, 0x00, 0x00, // central dir size/offset
      0x00, 0x00 // comment length
    ]),
    "missing-zip64.zip",
    "application/zip"
  );

export const createZipFile = () =>
  new MockFile(
    new Uint8Array([
      0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]),
    "empty.zip",
    "application/zip"
  );

export const createZipWithEntries = (): MockFile => {
  const entries: Array<{ name: string; method: number; data: Uint8Array }> = [
    { name: "stored.txt", method: 0, data: encoder.encode("stored") },
    { name: "deflated.txt", method: 8, data: encoder.encode("deflated") }
  ];

  const parts: Uint8Array[] = [];
  let cursor = 0;
  const append = (bytes: Uint8Array): number => {
    parts.push(bytes);
    const start = cursor;
    cursor += bytes.length;
    return start;
  };

  type CentralDirectoryEntry = {
    nameBytes: Uint8Array;
    method: number;
    crc: number;
    compSize: number;
    uncompSize: number;
    localOffset: number;
  };
  const cdEntries: CentralDirectoryEntry[] = [];
  entries.forEach(entry => {
    const nameBytes = encoder.encode(entry.name);
    const dataBytes = entry.data;
    const compressedBytes =
      entry.method === 8 ? new Uint8Array(deflateRawSync(Buffer.from(dataBytes))) : dataBytes;
    const crc = crc32(dataBytes);
    const localHeaderSize = 30 + nameBytes.length;
    const localHeader = new Uint8Array(localHeaderSize);
    const lhdv = new DataView(localHeader.buffer);
    lhdv.setUint32(0, 0x04034b50, true);
    lhdv.setUint16(4, 20, true);
    lhdv.setUint16(6, 0, true);
    lhdv.setUint16(8, entry.method, true);
    lhdv.setUint16(10, 0, true);
    lhdv.setUint16(12, 0, true);
    lhdv.setUint32(14, crc, true);
    lhdv.setUint32(18, compressedBytes.length, true);
    lhdv.setUint32(22, dataBytes.length, true);
    lhdv.setUint16(26, nameBytes.length, true);
    lhdv.setUint16(28, 0, true);
    localHeader.set(nameBytes, 30);
    const localOffset = append(localHeader);
    append(compressedBytes);
    cdEntries.push({
      nameBytes,
      method: entry.method,
      crc,
      compSize: compressedBytes.length,
      uncompSize: dataBytes.length,
      localOffset
    });
  });

  const cdStart = cursor;
  cdEntries.forEach(info => {
    const cdSize = 46 + info.nameBytes.length;
    const cdEntry = new Uint8Array(cdSize);
    const cddv = new DataView(cdEntry.buffer);
    cddv.setUint32(0, 0x02014b50, true);
    cddv.setUint16(4, 20, true);
    cddv.setUint16(6, 20, true);
    cddv.setUint16(8, 0, true);
    cddv.setUint16(10, info.method, true);
    cddv.setUint16(12, 0, true);
    cddv.setUint16(14, 0, true);
    cddv.setUint32(16, info.crc, true);
    cddv.setUint32(20, info.compSize, true);
    cddv.setUint32(24, info.uncompSize, true);
    cddv.setUint16(28, info.nameBytes.length, true);
    cddv.setUint16(30, 0, true);
    cddv.setUint16(32, 0, true);
    cddv.setUint16(34, 0, true);
    cddv.setUint16(36, 0, true);
    cddv.setUint32(38, 0, true);
    cddv.setUint32(42, info.localOffset, true);
    cdEntry.set(info.nameBytes, 46);
    append(cdEntry);
  });

  const cdSize = cursor - cdStart;
  const eocd = new Uint8Array(22);
  const eocdDv = new DataView(eocd.buffer);
  eocdDv.setUint32(0, 0x06054b50, true);
  eocdDv.setUint16(4, 0, true);
  eocdDv.setUint16(6, 0, true);
  eocdDv.setUint16(8, entries.length, true);
  eocdDv.setUint16(10, entries.length, true);
  eocdDv.setUint32(12, cdSize, true);
  eocdDv.setUint32(16, cdStart, true);
  eocdDv.setUint16(20, 0, true);
  append(eocd);

  const total = new Uint8Array(cursor);
  let offset = 0;
  parts.forEach(part => {
    total.set(part, offset);
    offset += part.length;
  });

  return new MockFile(total, "entries.zip", "application/zip");
};

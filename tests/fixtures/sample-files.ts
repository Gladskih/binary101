/* eslint-disable max-lines -- test fixtures aggregate many samples */
"use strict";

import { MockFile } from "../helpers/mock-file.js";
import { deflateRawSync } from "node:zlib";
export { createPeWithSectionAndIat, createPeFile, createPePlusFile } from "./sample-files-pe.js";

const fromBase64 = (base64: string): Uint8Array => new Uint8Array(Buffer.from(base64, "base64"));
const encoder = new TextEncoder();

const crc32Table = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let j = 0; j < 8; j += 1) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

const crc32 = (bytes: Uint8Array): number => {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    const idx = (crc ^ byte) & 0xff;
    const tableValue = crc32Table[idx] ?? 0;
    crc = (crc >>> 8) ^ tableValue;
  }
  return (crc ^ 0xffffffff) >>> 0;
};

const encodeVint = (value: number | bigint): number[] => {
  let v = BigInt(value);
  const out = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) byte |= 0x80;
    out.push(byte);
  } while (v !== 0n);
  return out;
};

const u32le = (value: number): number[] => [
  value & 0xff,
  (value >> 8) & 0xff,
  (value >> 16) & 0xff,
  (value >> 24) & 0xff
];
const FILETIME_EPOCH_BIAS_MS = 11644473600000n;

const align4 = (value: number): number => (value + 3) & ~3;

const encodeUtf16Le = (text: string): Uint8Array => {
  const bytes = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    bytes[i * 2] = code & 0xff;
    bytes[i * 2 + 1] = code >> 8;
  }
  return bytes;
};

const makeNullTerminatedAscii = (text: string): Uint8Array => {
  const data = encoder.encode(text);
  const out = new Uint8Array(data.length + 1);
  out.set(data, 0);
  out[out.length - 1] = 0;
  return out;
};

const makeNullTerminatedUnicode = (text: string): Uint8Array => {
  const data = encodeUtf16Le(text);
  const out = new Uint8Array(data.length + 2);
  out.set(data, 0);
  return out;
};

const concatParts = (parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let cursor = 0;
  parts.forEach(part => {
    out.set(part, cursor);
    cursor += part.length;
  });
  return out;
};

const writeGuid = (buffer: Uint8Array, offset: number, guidText: string): void => {
  const parts = guidText.split("-");
  const [data1Text, data2Text, data3Text, tailStart, tailEnd] = parts;
  if (!data1Text || !data2Text || !data3Text || !tailStart || !tailEnd) {
    throw new Error("Invalid GUID text");
  }
  const data1 = Number.parseInt(data1Text, 16);
  const data2 = Number.parseInt(data2Text, 16);
  const data3 = Number.parseInt(data3Text, 16);
  const tail = tailStart + tailEnd;
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  view.setUint32(offset, data1, true);
  view.setUint16(offset + 4, data2, true);
  view.setUint16(offset + 6, data3, true);
  for (let i = 0; i < 8; i += 1) {
    const byte = Number.parseInt(tail.slice(i * 2, i * 2 + 2), 16);
    buffer[offset + 8 + i] = byte;
  }
};

const encodeDosDateTime = (date: number | string | Date): { dosDate: number; dosTime: number } => {
  const d = new Date(date);
  const year = Math.max(1980, Math.min(2107, d.getUTCFullYear()));
  const dosDate =
    ((year - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate();
  const dosTime =
    (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | Math.floor(d.getUTCSeconds() / 2);
  return { dosDate, dosTime };
};

export const createPngFile = () =>
  new MockFile(
    fromBase64("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/5+hHgAFgwJ/l7nnMgAAAABJRU5ErkJggg=="),
    "sample.png",
    "image/png"
  );

export const createGifFile = () =>
  new MockFile(
    fromBase64("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=="),
    "sample.gif",
    "image/gif"
  );

export const createJpegFile = () =>
  new MockFile(
    fromBase64("/9j/4AAQSkZJRgABAQEAYABgAAD/2wCEAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAALCAABAAEBAREA/8QAFQABAQAAAAAAAAAAAAAAAAAAAAj/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAAH/AP/EABQQAQAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAAAl/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAwEBPwE//8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAgEBPwE//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAwEBPwE//9k="),
    "sample.jpg",
    "image/jpeg"
  );

export const createWebpFile = () =>
  new MockFile(
    fromBase64("UklGRiIAAABXRUJQVlA4ICAAAAAwAQCdASoBAAEAAQAcJaQAA3AA/vuUAAA="),
    "sample.webp",
    "image/webp"
  );

export const createMp4File = () =>
  new MockFile(
    new Uint8Array([
      0x00, 0x00, 0x00, 0x18, // size
      0x66, 0x74, 0x79, 0x70, // "ftyp"
      0x69, 0x73, 0x6f, 0x6d, // major brand "isom"
      0x00, 0x00, 0x02, 0x00, // minor version
      0x69, 0x73, 0x6f, 0x6d, // compatible brand "isom"
      0x6d, 0x70, 0x34, 0x31 // compatible brand "mp41"
    ]),
    "sample.mp4",
    "video/mp4"
  );

export const createFb2File = () => {
  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    "<FictionBook>",
    "<description><title-info><book-title>Example</book-title></title-info></description>",
    "<body><section><p>Hello world</p></section></body>",
    "</FictionBook>"
  ].join("\n");
  return new MockFile(encoder.encode(xml), "sample.fb2", "text/xml");
};

const formatOffset = (value: number): string => value.toString(8).padStart(7, "0") + "\0";
const writeString = (buffer: Uint8Array, text: string, offset: number, length: number): void => {
  const bytes = encoder.encode(text);
  const max = Math.min(bytes.length, length);
  buffer.set(bytes.slice(0, max), offset);
};

export const createTarFile = () => {
  const blockSize = 512;
  const header = new Uint8Array(blockSize).fill(0);
  writeString(header, "hello.txt", 0, 100);
  writeString(header, "0000777\0", 100, 8);
  writeString(header, "0000000\0", 108, 8);
  writeString(header, "0000000\0", 116, 8);
  writeString(header, "00000000000\0", 124, 12);
  writeString(header, "00000000000\0", 136, 12);
  // Checksum placeholder of eight spaces
  for (let i = 148; i < 156; i += 1) header[i] = 0x20;
  writeString(header, "0", 156, 1);
  writeString(header, "ustar", 257, 6);
  writeString(header, "00", 263, 2);
  writeString(header, "user", 265, 32);
  writeString(header, "group", 297, 32);

  let sum = 0;
  for (let i = 0; i < header.length; i += 1) sum += header[i] ?? 0;
  const checksum = formatOffset(sum);
  writeString(header, checksum, 148, 8);

  const endBlock = new Uint8Array(blockSize).fill(0);
  const tarBytes = new Uint8Array(blockSize * 2);
  tarBytes.set(header, 0);
  tarBytes.set(endBlock, blockSize);
  return new MockFile(tarBytes, "sample.tar", "application/x-tar");
};

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

export const createLnkFile = () => {
  const linkFlags =
    0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040 | 0x00000080;
  const header = new Uint8Array(0x4c).fill(0);
  const hdv = new DataView(header.buffer);
  hdv.setUint32(0, 0x4c, true);
  writeGuid(header, 4, "00021401-0000-0000-c000-000000000046");
  hdv.setUint32(0x14, linkFlags, true);
  hdv.setUint32(0x18, 0x00000020, true);
  const filetime = (BigInt(Date.UTC(2024, 0, 2, 12, 0, 0)) + FILETIME_EPOCH_BIAS_MS) * 10000n;
  hdv.setBigUint64(0x1c, filetime, true);
  hdv.setBigUint64(0x24, filetime, true);
  hdv.setBigUint64(0x2c, filetime, true);
  hdv.setUint32(0x34, 12345, true);
  hdv.setUint32(0x38, 1, true);
  hdv.setUint32(0x3c, 1, true);

  const dosTimestamp = encodeDosDateTime(new Date(Date.UTC(2024, 0, 2, 12, 0, 0)));

  const buildVolumeId = () => {
    const label = makeNullTerminatedAscii("DATA");
    const size = 0x10 + label.length;
    const vol = new Uint8Array(size).fill(0);
    const vdv = new DataView(vol.buffer);
    vdv.setUint32(0, size, true);
    vdv.setUint32(4, 3, true);
    vdv.setUint32(8, 0x12345678, true);
    vdv.setUint32(12, 0x10, true);
    vol.set(label, 0x10);
    return vol;
  };

  const volumeId = buildVolumeId();
  const localBasePath = makeNullTerminatedAscii("C:\\Program Files\\Example");
  const commonPathSuffix = makeNullTerminatedAscii("app.exe");
  const localBasePathUnicode = makeNullTerminatedUnicode("C:\\Program Files\\Example");
  const commonPathSuffixUnicode = makeNullTerminatedUnicode("app.exe");

  const buildLinkInfo = () => {
    const headerSize = 0x24;
    let cursor = headerSize;
    type LinkOffsets = {
      volumeId: number;
      localBasePath: number;
      commonPathSuffix: number;
      localBasePathUnicode: number;
      commonPathSuffixUnicode: number;
    };
    const offsets: LinkOffsets = {
      volumeId: 0,
      localBasePath: 0,
      commonPathSuffix: 0,
      localBasePathUnicode: 0,
      commonPathSuffixUnicode: 0
    };
    const add = (key: keyof LinkOffsets, length: number): void => {
      cursor = align4(cursor);
      offsets[key] = cursor;
      cursor += length;
    };
    add("volumeId", volumeId.length);
    add("localBasePath", localBasePath.length);
    add("commonPathSuffix", commonPathSuffix.length);
    add("localBasePathUnicode", localBasePathUnicode.length);
    add("commonPathSuffixUnicode", commonPathSuffixUnicode.length);
    const size = align4(cursor);
    const info = new Uint8Array(size).fill(0);
    const idv = new DataView(info.buffer);
    idv.setUint32(0, size, true);
    idv.setUint32(4, headerSize, true);
    idv.setUint32(8, 0x00000001, true);
    idv.setUint32(0x0c, offsets.volumeId, true);
    idv.setUint32(0x10, offsets.localBasePath, true);
    idv.setUint32(0x14, 0, true);
    idv.setUint32(0x18, offsets.commonPathSuffix, true);
    idv.setUint32(0x1c, offsets.localBasePathUnicode, true);
    idv.setUint32(0x20, offsets.commonPathSuffixUnicode, true);
    info.set(volumeId, offsets.volumeId);
    info.set(localBasePath, offsets.localBasePath);
    info.set(commonPathSuffix, offsets.commonPathSuffix);
    info.set(localBasePathUnicode, offsets.localBasePathUnicode);
    info.set(commonPathSuffixUnicode, offsets.commonPathSuffixUnicode);
    return info;
  };

  const buildUnicodeStringData = (text: string): Uint8Array => {
    const totalChars = text.length + 1;
    const bytes = new Uint8Array(2 + totalChars * 2).fill(0);
    const sdv = new DataView(bytes.buffer);
    sdv.setUint16(0, totalChars, true);
    for (let i = 0; i < text.length; i += 1) {
      sdv.setUint16(2 + i * 2, text.charCodeAt(i), true);
    }
    return bytes;
  };

  const buildEnvironmentBlock = (target: string): Uint8Array => {
    const blockSize = 0x314;
    const block = new Uint8Array(blockSize).fill(0);
    const bdv = new DataView(block.buffer);
    bdv.setUint32(0, blockSize, true);
    bdv.setUint32(4, 0xa0000001, true);
    const ansi = makeNullTerminatedAscii(target);
    const unicode = makeNullTerminatedUnicode(target);
    block.set(ansi.slice(0, 260), 8);
    block.set(unicode.slice(0, 520), 8 + 260);
    return block;
  };

  const buildKnownFolderBlock = () => {
    const block = new Uint8Array(0x1c).fill(0);
    const kdv = new DataView(block.buffer);
    kdv.setUint32(0, 0x1c, true);
    kdv.setUint32(4, 0xa000000b, true);
    writeGuid(block, 8, "fdd39ad0-238f-46af-adb4-6c85480369c7");
    kdv.setUint32(0x18, 0x10, true);
    return block;
  };

  const buildPropertyValue = (
    type: number,
    value: number | string
  ): { size: number; body: Uint8Array } => {
    const vtSize = 4; // VARTYPE (u16) + padding (u16)
    if (type === 0x1f && typeof value === "string") {
      const length = value.length + 1;
      const data = new Uint8Array(4 + length * 2).fill(0);
      const dv = new DataView(data.buffer);
      dv.setUint32(0, length, true);
      for (let i = 0; i < value.length; i += 1) {
        dv.setUint16(4 + i * 2, value.charCodeAt(i), true);
      }
      const body = new Uint8Array(vtSize + data.length);
      const bdv = new DataView(body.buffer);
      bdv.setUint16(0, type, true);
      // padding already zero
      body.set(data, vtSize);
      return { size: body.length, body };
    }
    if (type === 0x48 && typeof value === "string") {
      const body = new Uint8Array(vtSize + 16).fill(0);
      const bdv = new DataView(body.buffer);
      bdv.setUint16(0, type, true);
      writeGuid(body, vtSize, value);
      return { size: body.length, body };
    }
    if (type === 0x13 && typeof value === "number") {
      const body = new Uint8Array(vtSize + 4).fill(0);
      const bdv = new DataView(body.buffer);
      bdv.setUint16(0, type, true);
      bdv.setUint32(vtSize, value >>> 0, true);
      return { size: body.length, body };
    }
    return { size: vtSize, body: new Uint8Array(vtSize) };
  };

  const buildPropertyStoreBlock = (): Uint8Array => {
    const buildSpsStorage = (
      fmtid: string,
      props: Array<{ pid: number; type: number; value: number | string }>
    ): Uint8Array => {
      const entries = props.map(({ pid, type, value }) => {
        const val = buildPropertyValue(type, value);
        const entry = new Uint8Array(8 + val.size);
        const dv = new DataView(entry.buffer);
        dv.setUint32(0, val.size, true);
        dv.setUint32(4, pid, true);
        entry.set(val.body, 8);
        return entry;
      });
      const terminator = new Uint8Array(8).fill(0);
      const storageSize = 24 + entries.reduce<number>((sum, e) => sum + e.length, 0) + terminator.length;
      const storage = new Uint8Array(storageSize).fill(0);
      const sdv = new DataView(storage.buffer);
      sdv.setUint32(0, storageSize, true);
      sdv.setUint32(4, 0x53505331, true); // "SPS1" as 0x53505331 ("SPS1")
      writeGuid(storage, 8, fmtid);
      let cursor = 24;
      entries.forEach(entry => {
        storage.set(entry, cursor);
        cursor += entry.length;
      });
      storage.set(terminator, cursor);
      return storage;
    };

    const volumeStorage = buildSpsStorage("446d16b1-8dad-4870-a748-402ea43d788c", [
      { pid: 104, type: 0x48, value: "8e44de00-5103-3a0b-4785-67a8d9b71bc0" }
    ]);
    const linkStorage = buildSpsStorage("f29f85e0-4ff9-1068-ab91-08002b27b3d9", [
      { pid: 2, type: 0x1f, value: "C:\\Program Files\\Example\\app.exe" }
    ]);

    const body = concatParts([volumeStorage, linkStorage]);
    const blockSize = body.length + 8;
    const block = new Uint8Array(blockSize).fill(0);
    const bdv = new DataView(block.buffer);
    bdv.setUint32(0, blockSize, true);
    bdv.setUint32(4, 0xa0000009, true);
    block.set(body, 8);
    return block;
  };

  const buildRootShellItem = (clsid: string): Uint8Array => {
    const body = new Uint8Array(1 + 16).fill(0);
    body[0] = 0x1f;
    writeGuid(body, 1, clsid);
    const item = new Uint8Array(body.length + 2).fill(0);
    new DataView(item.buffer).setUint16(0, item.length, true);
    item.set(body, 2);
    return item;
  };

  const buildFileExtensionBlock = (longName: string): Uint8Array => {
    const nameBytes = makeNullTerminatedUnicode(longName);
    const version = 3;
    const headerSize = 20; // size (2) + version (2) + sig (4) + times (8) + unknown (2) + longSize (2)
    const blockSize = headerSize + nameBytes.length;
    const block = new Uint8Array(blockSize).fill(0);
    const dv = new DataView(block.buffer);
    dv.setUint16(0, blockSize, true);
    dv.setUint16(2, version, true);
    dv.setUint32(4, 0xbeef0004, true);
    // Creation and access FAT times left as zero.
    dv.setUint16(16, 0x0014, true); // typical value for Windows XP/2003, but not interpreted
    dv.setUint16(18, nameBytes.length, true);
    block.set(nameBytes, headerSize);
    return block;
  };

  const buildFileShellItem = (
    type: number,
    shortName: string,
    longName: string,
    attributes: number,
    sizeBytes: number
  ): Uint8Array => {
    const shortBytes = makeNullTerminatedAscii(shortName);
    const longBlock = buildFileExtensionBlock(longName);
    const base = 12 + shortBytes.length;
    const padding = base % 2 === 0 ? 0 : 1;
    const bodyLength = base + padding + longBlock.length;
    const body = new Uint8Array(bodyLength).fill(0);
    const dv = new DataView(body.buffer);
    dv.setUint8(0, type);
    // Sort index (byte 1) left as zero.
    dv.setUint32(2, sizeBytes >>> 0, true);
    dv.setUint16(6, dosTimestamp.dosDate, true);
    dv.setUint16(8, dosTimestamp.dosTime, true);
    dv.setUint16(10, attributes, true);
    body.set(shortBytes, 12);
    let offset = 12 + shortBytes.length;
    if (padding) {
      body[offset] = 0;
      offset += 1;
    }
    body.set(longBlock, offset);
    const item = new Uint8Array(body.length + 2).fill(0);
    new DataView(item.buffer).setUint16(0, item.length, true);
    item.set(body, 2);
    return item;
  };

  const buildDriveShellItem = (driveLetter: string): Uint8Array => {
    const text = `${driveLetter.toUpperCase()}:`;
    const label = makeNullTerminatedAscii(text);
    const body = new Uint8Array(2 + label.length).fill(0);
    body[0] = 0x2f;
    body[1] = 0x00;
    body.set(label, 2);
    const item = new Uint8Array(body.length + 2).fill(0);
    new DataView(item.buffer).setUint16(0, item.length, true);
    item.set(body, 2);
    return item;
  };

  const buildIdList = () => {
    const items = [
      buildRootShellItem("20d04fe0-3aea-1069-a2d8-08002b30309d"),
      buildDriveShellItem("C"),
      buildFileShellItem(0x31, "PROGRA~1", "Program Files", 0x0010, 0),
      buildFileShellItem(0x31, "Example", "Example", 0x0010, 0),
      buildFileShellItem(0x32, "APP.EXE", "app.exe", 0x0020, 12345)
    ];
    const idListSize = items.reduce((sum, item) => sum + item.length, 0) + 2;
    const list = new Uint8Array(2 + idListSize).fill(0);
    const ldv = new DataView(list.buffer);
    ldv.setUint16(0, idListSize, true);
    let cursor = 2;
    items.forEach(item => {
      list.set(item, cursor);
      cursor += item.length;
    });
    ldv.setUint16(cursor, 0, true);
    return list;
  };

  const idList = buildIdList();

  const linkInfo = buildLinkInfo();
  const strings = [
    buildUnicodeStringData("Sample shortcut"),
    buildUnicodeStringData(".\\Example\\app.exe"),
    buildUnicodeStringData("C:\\Program Files\\Example"),
    buildUnicodeStringData("--demo"),
    buildUnicodeStringData("%SystemRoot%\\system32\\shell32.dll,0")
  ];
  const envBlock = buildEnvironmentBlock("%USERPROFILE%\\Example\\app.exe");
  const knownFolderBlock = buildKnownFolderBlock();
  const propertyStoreBlock = buildPropertyStoreBlock();
  const terminalBlock = new Uint8Array(4).fill(0);

  const bytes = concatParts([
    header,
    idList,
    linkInfo,
    ...strings,
    envBlock,
    knownFolderBlock,
    propertyStoreBlock,
    terminalBlock
  ]);
  return new MockFile(bytes, "sample.lnk", "application/octet-stream");
};

export const createDosMzExe = () => {
  const bytes = new Uint8Array(128).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint16(0x00, 0x5a4d, true); // MZ
  dv.setUint16(0x02, 128, true); // bytes in last page
  dv.setUint16(0x04, 1, true); // pages
  dv.setUint16(0x08, 4, true); // header size in paragraphs
  dv.setUint16(0x0a, 0, true); // min extra paragraphs
  dv.setUint16(0x0c, 0xffff, true); // max extra paragraphs
  dv.setUint16(0x0e, 0, true); // ss
  dv.setUint16(0x10, 0x00b8, true); // sp
  dv.setUint16(0x18, 0x0040, true); // relocation table offset
  dv.setUint32(0x3c, 0, true); // no extended header
  const stub = encoder.encode("DOS stub - no PE header");
  bytes.set(stub.slice(0, bytes.length - 64), 64);
  return new MockFile(bytes, "dos-stub.exe", "application/x-msdos-program");
};

export const createPngWithIhdr = () =>
  new MockFile(
    fromBase64("iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAB7GkOtAAAADUlEQVR42mNk+M9QDwADaQH4UNIAMwAAAABJRU5ErkJggg=="),
    "two-by-two.png",
    "image/png"
  );

export const createPdfFile = () => {
  const header = "%PDF-1.4\n";
  const obj1 = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
  const obj2 = "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n";
  const obj3 =
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>\nendobj\n";
  const obj4 = "4 0 obj\n<< /Length 11 >>\nstream\nHello World\nendstream\nendobj\n";

  const offsets: number[] = [];
  let cursor = 0;
  const add = (segment: string): string => {
    offsets.push(cursor);
    cursor += Buffer.byteLength(segment, "latin1");
    return segment;
  };

  const body = [add(header), add(obj1), add(obj2), add(obj3), add(obj4)].join("");
  const [, obj1Offset, obj2Offset, obj3Offset, obj4Offset] = offsets as [
    number,
    number,
    number,
    number,
    number
  ];
  const xrefOffset = cursor;
  const pad = (value: number): string => value.toString().padStart(10, "0");
  const xref =
    "xref\n0 5\n" +
    `${pad(0)} 65535 f \n` +
    `${pad(obj1Offset)} 00000 n \n` +
    `${pad(obj2Offset)} 00000 n \n` +
    `${pad(obj3Offset)} 00000 n \n` +
    `${pad(obj4Offset)} 00000 n \n`;
  const trailer = `trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  const pdfText = body + xref + trailer;
  return new MockFile(encoder.encode(pdfText), "sample.pdf", "application/pdf");
};

export const createFb2TextOnlyFile = createFb2File;

const buildElf64File = () => {
  const headerSize = 64;
  const phSize = 56;
  const shSize = 64;
  const phoff = headerSize;
  const shoff = phoff + phSize;
  const shstrOffset = shoff + shSize * 2;
  const shstrContent = encoder.encode("\0.shstrtab\0");
  const totalSize = shstrOffset + shstrContent.length;
  const bytes = new Uint8Array(totalSize).fill(0);
  const dv = new DataView(bytes.buffer);
  // e_ident
  dv.setUint32(0, 0x7f454c46, false); // ELF
  dv.setUint8(4, 2); // 64-bit
  dv.setUint8(5, 1); // little endian
  dv.setUint8(6, 1); // version
  // e_type, e_machine, e_version
  dv.setUint16(16, 2, true); // executable
  dv.setUint16(18, 0x3e, true); // x86-64
  dv.setUint32(20, 1, true);
  dv.setBigUint64(24, 0x400000n, true); // entry
  dv.setBigUint64(32, BigInt(phoff), true);
  dv.setBigUint64(40, BigInt(shoff), true);
  dv.setUint32(48, 0, true); // flags
  dv.setUint16(52, headerSize, true);
  dv.setUint16(54, phSize, true);
  dv.setUint16(56, 1, true);
  dv.setUint16(58, shSize, true);
  dv.setUint16(60, 2, true); // shnum
  dv.setUint16(62, 1, true); // shstrndx
  // Program header (single load segment)
  dv.setUint32(phoff + 0, 1, true); // PT_LOAD
  dv.setUint32(phoff + 4, 5, true); // flags R+X
  dv.setBigUint64(phoff + 8, 0n, true); // offset
  dv.setBigUint64(phoff + 16, 0x400000n, true); // vaddr
  dv.setBigUint64(phoff + 24, 0x400000n, true); // paddr
  dv.setBigUint64(phoff + 32, BigInt(totalSize), true); // filesz
  dv.setBigUint64(phoff + 40, BigInt(totalSize), true); // memsz
  dv.setBigUint64(phoff + 48, 0x1000n, true); // align
  // Section header 0 (null)
  // Section header 1 (.shstrtab)
  const sh1 = shoff + shSize;
  dv.setUint32(sh1 + 0, 1, true); // name offset in shstrtab
  dv.setUint32(sh1 + 4, 3, true); // type: STRTAB
  dv.setBigUint64(sh1 + 8, 0n, true); // flags
  dv.setBigUint64(sh1 + 16, 0n, true); // addr
  dv.setBigUint64(sh1 + 24, BigInt(shstrOffset), true); // offset
  dv.setBigUint64(sh1 + 32, BigInt(shstrContent.length), true); // size
  dv.setUint32(sh1 + 40, 0, true); // link
  dv.setUint32(sh1 + 44, 0, true); // info
  dv.setBigUint64(sh1 + 48, 1n, true); // addralign
  dv.setBigUint64(sh1 + 56, 0n, true); // entsize

  bytes.set(shstrContent, shstrOffset);
  return bytes;
};

export const createElfFile = () =>
  new MockFile(buildElf64File(), "sample.elf", "application/x-elf");

export const createMp3File = () => {
  const versionBits = 0x3;
  const layerBits = 0x1;
  const bitrateIndex = 0x9; // 128 kbps
  const sampleRateIndex = 0x0; // 44100
  const header =
    (0x7ff << 21) |
    (versionBits << 19) |
    (layerBits << 17) |
    (1 << 16) | // no CRC
    (bitrateIndex << 12) |
    (sampleRateIndex << 10) |
    (0 << 9) | // padding
    (0 << 6) | // channel mode stereo
    (0 << 4) |
    (0 << 2) |
    0;
  const frameLength = Math.floor((1152 * 128000) / (8 * 44100));
  const totalLength = frameLength * 2;
  const bytes = new Uint8Array(totalLength).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, header, false);
  view.setUint32(frameLength, header, false);
  return new MockFile(bytes, "sample.mp3", "audio/mpeg");
};

export const createSevenZipFile = () => {
  const header = new Uint8Array(32).fill(0);
  const sig = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
  header.set(sig, 0);
  header[6] = 0; // version major
  header[7] = 4; // version minor
  // next header located immediately after the start header
  const view = new DataView(header.buffer);
  view.setBigUint64(12, 0n, true); // next header offset
  view.setBigUint64(20, 2n, true); // next header size
  const nextHeader = new Uint8Array([0x01, 0x00]); // minimal header + terminator
  const combined = new Uint8Array(header.length + nextHeader.length);
  combined.set(header, 0);
  combined.set(nextHeader, header.length);
  return new MockFile(combined, "sample.7z", "application/x-7z-compressed");
};

export const createRar4File = () => {
  const signature = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
  const LONG_BLOCK = 0x8000;
  const fileData = new Uint8Array([0x48, 0x69]); // "Hi"
  const fileName = encoder.encode("hello.txt");

  const mainHeadSize = 13;
  const mainHeader = [
    0x00,
    0x00, // CRC16 placeholder
    0x73, // HEAD3_MAIN
    0x00,
    0x00, // flags
    mainHeadSize & 0xff,
    (mainHeadSize >> 8) & 0xff,
    0x00,
    0x00, // HighPosAV
    0x00,
    0x00,
    0x00,
    0x00 // PosAV
  ];

  const fileHeadSize = 32 + fileName.length;
  const fileFlags = LONG_BLOCK;
  const fileHeader = [
    0x00,
    0x00, // CRC16 placeholder
    0x74, // HEAD3_FILE
    fileFlags & 0xff,
    (fileFlags >> 8) & 0xff,
    fileHeadSize & 0xff,
    (fileHeadSize >> 8) & 0xff,
    ...u32le(fileData.length),
    ...u32le(fileData.length),
    0x02, // host OS Windows
    ...u32le(crc32(fileData)),
    ...u32le(0), // file time
    20, // UnpVer
    0x30, // Store method
    fileName.length & 0xff,
    (fileName.length >> 8) & 0xff,
    ...u32le(0x20), // file attributes
    ...fileName
  ];

  const endHeader = [0x00, 0x00, 0x7b, 0x00, 0x00, 0x07, 0x00];

  const bytes = new Uint8Array(
    signature.length + mainHeader.length + fileHeader.length + fileData.length + endHeader.length
  );
  let cursor = 0;
  [signature, mainHeader, fileHeader].forEach(part => {
    bytes.set(part, cursor);
    cursor += part.length;
  });
  bytes.set(fileData, cursor);
  cursor += fileData.length;
  bytes.set(endHeader, cursor);

  return new MockFile(bytes, "sample.rar", "application/x-rar-compressed");
};

export const createRar5File = () => {
  const signature = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];
  const HFL_DATA = 0x0002;
  const FHFL_CRC32 = 0x0004;

  const fileData = new Uint8Array([0x48, 0x69]); // "Hi"
  const fileName = encoder.encode("note.txt");
  const buildHeader = (headerFields: number[]): number[] => {
    const sizeBytes = encodeVint(headerFields.length);
    const headerBytes = Uint8Array.from([...sizeBytes, ...headerFields]);
    const headerCrc = crc32(headerBytes);
    return [...u32le(headerCrc), ...headerBytes];
  };

  const mainHeader = buildHeader([
    ...encodeVint(1), // main header type
    ...encodeVint(0), // header flags
    ...encodeVint(0) // archive flags
  ]);

  const fileHeader = buildHeader([
    ...encodeVint(2), // file header type
    ...encodeVint(HFL_DATA), // header flags (data area present)
    ...encodeVint(fileData.length), // packed size
    ...encodeVint(FHFL_CRC32), // file flags
    ...encodeVint(fileData.length), // unpacked size
    ...encodeVint(0x20), // file attributes
    ...u32le(crc32(fileData)), // data CRC
    ...encodeVint(0), // compression info (store)
    ...encodeVint(0), // host OS Windows
    ...encodeVint(fileName.length),
    ...fileName
  ]);

  const endHeader = buildHeader([
    ...encodeVint(5), // end of archive
    ...encodeVint(0), // header flags
    ...encodeVint(0) // archive flags
  ]);

  const bytes = new Uint8Array(
    signature.length + mainHeader.length + fileHeader.length + fileData.length + endHeader.length
  );
  let cursor = 0;
  [signature, mainHeader, fileHeader].forEach(part => {
    bytes.set(part, cursor);
    cursor += part.length;
  });
  bytes.set(fileData, cursor);
  cursor += fileData.length;
  bytes.set(endHeader, cursor);

  return new MockFile(bytes, "sample-v5.rar", "application/x-rar-compressed");
};

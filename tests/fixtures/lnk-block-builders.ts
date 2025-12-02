"use strict";

import {
  align4,
  concatParts,
  encodeDosDateTime,
  makeNullTerminatedAscii,
  makeNullTerminatedUnicode,
  writeGuid
} from "./lnk-fixture-helpers.js";

export type DosTimestamp = { dosDate: number; dosTime: number };

export const buildVolumeId = (labelText: string): Uint8Array => {
  const label = makeNullTerminatedAscii(labelText);
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

export const buildLinkInfo = (
  volumeId: Uint8Array,
  localBasePath: Uint8Array,
  commonPathSuffix: Uint8Array,
  localBasePathUnicode: Uint8Array,
  commonPathSuffixUnicode: Uint8Array
): Uint8Array => {
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

export const buildUnicodeStringData = (text: string): Uint8Array => {
  const totalChars = text.length + 1;
  const bytes = new Uint8Array(2 + totalChars * 2).fill(0);
  const sdv = new DataView(bytes.buffer);
  sdv.setUint16(0, totalChars, true);
  for (let i = 0; i < text.length; i += 1) {
    sdv.setUint16(2 + i * 2, text.charCodeAt(i), true);
  }
  return bytes;
};

export const buildEnvironmentBlock = (target: string): Uint8Array => {
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

export const buildKnownFolderBlock = (): Uint8Array => {
  const block = new Uint8Array(0x1c).fill(0);
  const kdv = new DataView(block.buffer);
  kdv.setUint32(0, 0x1c, true);
  kdv.setUint32(4, 0xa000000b, true);
  writeGuid(block, 8, "fdd39ad0-238f-46af-adb4-6c85480369c7");
  kdv.setUint32(0x18, 0x10, true);
  return block;
};

export const buildPropertyValue = (
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

export const buildPropertyStoreBlock = (): Uint8Array => {
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

export const buildRootShellItem = (clsid: string): Uint8Array => {
  const body = new Uint8Array(1 + 16).fill(0);
  body[0] = 0x1f;
  writeGuid(body, 1, clsid);
  const item = new Uint8Array(body.length + 2).fill(0);
  new DataView(item.buffer).setUint16(0, item.length, true);
  item.set(body, 2);
  return item;
};

export const buildFileExtensionBlock = (longName: string): Uint8Array => {
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

export const buildFileShellItem = (
  type: number,
  shortName: string,
  longName: string,
  attributes: number,
  sizeBytes: number,
  dosTimestamp: DosTimestamp
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
  let cursor = 12 + shortBytes.length;
  if (padding) {
    body[cursor] = 0;
    cursor += 1;
  }
  body.set(longBlock, cursor);
  const item = new Uint8Array(body.length + 2).fill(0);
  new DataView(item.buffer).setUint16(0, item.length, true);
  item.set(body, 2);
  return item;
};

export const buildDriveShellItem = (driveLetter: string): Uint8Array => {
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

export const buildIdList = (dosTimestamp: DosTimestamp): Uint8Array => {
  const items = [
    buildRootShellItem("20d04fe0-3aea-1069-a2d8-08002b30309d"),
    buildDriveShellItem("C"),
    buildFileShellItem(0x31, "PROGRA~1", "Program Files", 0x0010, 0, dosTimestamp),
    buildFileShellItem(0x31, "Example", "Example", 0x0010, 0, dosTimestamp),
    buildFileShellItem(0x32, "APP.EXE", "app.exe", 0x0020, 12345, dosTimestamp)
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

export const createDosTimestamp = () => encodeDosDateTime(new Date(Date.UTC(2024, 0, 2, 12, 0, 0)));

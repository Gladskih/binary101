"use strict";

import {
  FAT_MAGIC,
  FAT_MAGIC_64,
  MH_CIGAM,
  MH_CIGAM_64,
  MH_MAGIC,
  MH_MAGIC_64
} from "./commands.js";
import type { MachOFileHeader, MachOSegment } from "./types.js";

export type MachOMagicInfo = {
  kind: "thin" | "fat";
  is64: boolean;
  littleEndian: boolean;
  magic: number;
  magicName: string;
};

export type MachORangeReader = {
  read: (offset: number, size: number) => Promise<DataView>;
  readZeroTerminatedString: (offset: number, maxLength: number) => Promise<string>;
};

const bigFromUint32 = (value: number): bigint => BigInt(value >>> 0);
const EMPTY_VIEW = new DataView(new ArrayBuffer(0));
const MACHO_READER_WINDOW_BYTES = 64 * 1024;

const magicInfoFromValue = (magic: number): MachOMagicInfo | null => {
  switch (magic) {
    case MH_MAGIC:
      return { kind: "thin", is64: false, littleEndian: false, magic, magicName: "MH_MAGIC" };
    case MH_CIGAM:
      return { kind: "thin", is64: false, littleEndian: true, magic, magicName: "MH_CIGAM" };
    case MH_MAGIC_64:
      return { kind: "thin", is64: true, littleEndian: false, magic, magicName: "MH_MAGIC_64" };
    case MH_CIGAM_64:
      return { kind: "thin", is64: true, littleEndian: true, magic, magicName: "MH_CIGAM_64" };
    case FAT_MAGIC:
      return { kind: "fat", is64: false, littleEndian: false, magic, magicName: "FAT_MAGIC" };
    case FAT_MAGIC_64:
      return { kind: "fat", is64: true, littleEndian: false, magic, magicName: "FAT_MAGIC_64" };
    default:
      return null;
  }
};

const getMachOMagicInfo = (view: DataView, offset = 0): MachOMagicInfo | null => {
  if (offset + 4 > view.byteLength) return null;
  return magicInfoFromValue(view.getUint32(offset, false));
};

const machOMagicName = (magic: number): string | null => magicInfoFromValue(magic)?.magicName || null;

const isRangeWithin = (limit: number, offset: number, size: number): boolean =>
  Number.isInteger(offset) &&
  Number.isInteger(size) &&
  offset >= 0 &&
  size >= 0 &&
  offset <= limit &&
  size <= limit - offset;

const clampRangeSize = (limit: number, offset: number, size: number): number => {
  if (offset < 0 || offset >= limit || size <= 0) return 0;
  return Math.min(size, limit - offset);
};

const readRange = async (file: File, offset: number, size: number): Promise<DataView> =>
  new DataView(await file.slice(offset, offset + size).arrayBuffer());

const createRangeReader = (
  file: File,
  baseOffset: number,
  limit: number
): MachORangeReader => {
  let windowOffset = -1;
  let windowView: DataView | null = null;

  const read = async (offset: number, size: number): Promise<DataView> => {
    const availableSize = clampRangeSize(limit, offset, size);
    if (availableSize <= 0) return EMPTY_VIEW;
    if (
      windowView &&
      offset >= windowOffset &&
      offset + availableSize <= windowOffset + windowView.byteLength
    ) {
      return subView(windowView, offset - windowOffset, availableSize);
    }
    const readSize =
      availableSize > MACHO_READER_WINDOW_BYTES
        ? availableSize
        : clampRangeSize(limit, offset, Math.max(availableSize, MACHO_READER_WINDOW_BYTES));
    const view = await readRange(file, baseOffset + offset, readSize);
    if (availableSize <= MACHO_READER_WINDOW_BYTES) {
      windowOffset = offset;
      windowView = view;
    } else {
      windowOffset = -1;
      windowView = null;
    }
    return availableSize === view.byteLength
      ? view
      : subView(view, 0, Math.min(availableSize, view.byteLength));
  };

  const readZeroTerminatedString = async (offset: number, maxLength: number): Promise<string> => {
    if (offset < 0 || offset >= limit || maxLength <= 0) return "";
    let cursor = offset;
    let remaining = Math.min(maxLength, limit - offset);
    let text = "";
    while (remaining > 0) {
      const chunk = await read(cursor, Math.min(remaining, MACHO_READER_WINDOW_BYTES));
      if (!chunk.byteLength) break;
      for (let index = 0; index < chunk.byteLength; index += 1) {
        const byteValue = chunk.getUint8(index);
        if (byteValue === 0) return text;
        text += String.fromCharCode(byteValue);
      }
      cursor += chunk.byteLength;
      remaining -= chunk.byteLength;
    }
    return text;
  };

  return {
    read,
    readZeroTerminatedString
  };
};

const readFixedString = (view: DataView, offset: number, length: number): string => {
  let text = "";
  for (let index = 0; index < length && offset + index < view.byteLength; index += 1) {
    const byteValue = view.getUint8(offset + index);
    if (byteValue === 0) break;
    text += String.fromCharCode(byteValue);
  }
  return text;
};

const readZeroTerminatedString = (bytes: Uint8Array, offset: number): string => {
  if (offset < 0 || offset >= bytes.length) return "";
  let text = "";
  for (let index = offset; index < bytes.length; index += 1) {
    const byteValue = bytes[index];
    if (byteValue == null || byteValue === 0) break;
    text += String.fromCharCode(byteValue);
  }
  return text;
};

const subView = (view: DataView, offset: number, length: number): DataView =>
  new DataView(view.buffer, view.byteOffset + offset, length);

const formatPackedVersion = (value: number): string =>
  `${(value >>> 16) & 0xffff}.${(value >>> 8) & 0xff}.${value & 0xff}`;

const formatBuildToolVersion = (value: number): string =>
  value > 0xffff ? formatPackedVersion(value) : String(value >>> 0);

const formatSourceVersion = (value: bigint): string => {
  // source_version_command.version packs A.B.C.D.E as 24/10/10/10/10 bits in
  // mach-o/loader.h.
  const major = Number((value >> 40n) & 0xffffffn);
  const minor = Number((value >> 30n) & 0x3ffn);
  const patch = Number((value >> 20n) & 0x3ffn);
  const build = Number((value >> 10n) & 0x3ffn);
  const revision = Number(value & 0x3ffn);
  return `${major}.${minor}.${patch}.${build}.${revision}`;
};

const formatUuid = (view: DataView, offset: number): string => {
  const bytes: string[] = [];
  for (let index = 0; index < 16 && offset + index < view.byteLength; index += 1) {
    bytes.push(view.getUint8(offset + index).toString(16).padStart(2, "0"));
  }
  return [
    bytes.slice(0, 4).join(""),
    bytes.slice(4, 6).join(""),
    bytes.slice(6, 8).join(""),
    bytes.slice(8, 10).join(""),
    bytes.slice(10, 16).join("")
  ].join("-");
};

const resolveEntryVirtualAddress = (segments: MachOSegment[], entryoff: bigint): bigint | null => {
  for (const segment of segments) {
    if (entryoff < segment.fileoff || entryoff >= segment.fileoff + segment.filesize) continue;
    return segment.vmaddr + (entryoff - segment.fileoff);
  }
  return null;
};

const parseHeader = (view: DataView, magicInfo: MachOMagicInfo): MachOFileHeader => {
  // Field offsets match mach_header / mach_header_64 in mach-o/loader.h.
  const little = magicInfo.littleEndian;
  return {
    magic: magicInfo.magic,
    is64: magicInfo.is64,
    littleEndian: little,
    cputype: view.getUint32(4, little),
    cpusubtype: view.getUint32(8, little),
    filetype: view.getUint32(12, little),
    ncmds: view.getUint32(16, little),
    sizeofcmds: view.getUint32(20, little),
    flags: view.getUint32(24, little),
    reserved: magicInfo.is64 ? view.getUint32(28, little) : null
  };
};

export {
  bigFromUint32,
  clampRangeSize,
  createRangeReader,
  formatBuildToolVersion,
  formatPackedVersion,
  formatSourceVersion,
  formatUuid,
  getMachOMagicInfo,
  machOMagicName,
  isRangeWithin,
  parseHeader,
  readFixedString,
  readRange,
  readZeroTerminatedString,
  resolveEntryVirtualAddress,
  subView
};

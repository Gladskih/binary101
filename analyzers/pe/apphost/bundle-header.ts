"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeAppHostBundleHeader, PeAppHostBundleLocation } from "./types.js";

// Packed little-endian header_fixed_t: uint32 major at 0, uint32 minor at 4,
// int32 file count at 8 (12 bytes total). The length-prefixed ID starts at 12;
// its one/two-byte prefix requires 13/14 bytes to read.
// v2 adds two 16-byte location_t records (int64 offset at 0, size at 8), then
// uint64 flags at 32: 40 extra bytes. These offsets are relative to the end of the ID.
// https://github.com/dotnet/runtime/blob/main/src/native/corehost/bundle/header.h
type BundleHeaderParseResult = {
  header?: PeAppHostBundleHeader;
  issues: string[];
};

const decodeUtf8 = (bytes: Uint8Array): string | null => {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
};

const readBundleIdLength = (view: DataView): { length: number; prefixBytes: number } | null => {
  // reader_t::read_path_length accepts at most two 7-bit bytes:
  // bit 7 (0x80) means continuation; bits 0..6 (0x7f) carry the length payload.
  // https://github.com/dotnet/runtime/blob/main/src/native/corehost/bundle/reader.cpp
  // The caller has validated the fixed header and first length byte.
  const first = view.getUint8(12);
  if ((first & 0x80) === 0) return { length: first, prefixBytes: 1 };
  if (view.byteLength < 14) return null;
  const second = view.getUint8(13);
  return (second & 0x80) === 0
    ? { length: (second << 7) | (first & 0x7f), prefixBytes: 2 }
    : null;
};

const validBundleVersion = (major: number, minor: number): boolean =>
  // 1.0: .NET Core 3.x; 2.0: .NET 5; 6.0: .NET 6+.
  // https://github.com/dotnet/runtime/blob/main/src/native/corehost/bundle/header.cpp
  minor === 0 && (major === 1 || major === 2 || major === 6);

const locationFrom = (view: DataView, offset: number): PeAppHostBundleLocation => ({
  offset: view.getBigInt64(offset, true),
  size: view.getBigInt64(offset + 8, true)
});

const validateLocation = (
  location: PeAppHostBundleLocation,
  label: string,
  fileSize: number,
  issues: string[]
): void => {
  if (location.offset === 0n && location.size === 0n) return;
  if (location.offset <= 0n || location.size <= 0n ||
    location.offset + location.size > BigInt(fileSize)) {
    issues.push(`${label} bundle location is outside the file.`);
  }
};

const parseVersionTwoFields = (
  view: DataView,
  offset: number,
  fileSize: number,
  issues: string[]
): Pick<PeAppHostBundleHeader, "depsJson" | "runtimeConfigJson" | "flags"> => {
  const depsJson = locationFrom(view, offset);
  const runtimeConfigJson = locationFrom(view, offset + 16);
  validateLocation(depsJson, "deps.json", fileSize, issues);
  validateLocation(runtimeConfigJson, "runtimeconfig.json", fileSize, issues);
  return { depsJson, runtimeConfigJson, flags: view.getBigUint64(offset + 32, true) };
};

const parseHeaderContent = (
  view: DataView,
  idOffset: number,
  idSize: number,
  fileSize: number,
  issues: string[]
): BundleHeaderParseResult => {
  const majorVersion = view.getUint32(0, true);
  const bundleId = decodeUtf8(new Uint8Array(view.buffer, view.byteOffset + idOffset, idSize));
  if (bundleId == null) issues.push("Single-file bundle ID is not valid UTF-8.");
  const extra = majorVersion >= 2
    ? parseVersionTwoFields(view, idOffset + idSize, fileSize, issues)
    : {};
  // header_flags_t defines only netcoreapp3_compat_mode (bit 0), in header.h above.
  if (extra.flags != null && (extra.flags & ~1n) !== 0n) {
    issues.push("Single-file bundle header contains unknown flag bits.");
  }
  return {
    header: { majorVersion, minorVersion: view.getUint32(4, true),
      embeddedFileCount: view.getInt32(8, true), bundleId, ...extra },
    issues
  };
};

const validHeaderOffset = (fileOffset: number, fileSize: number): boolean =>
  Number.isSafeInteger(fileOffset) && fileOffset >= 0 && fileOffset < fileSize;

export const parsePeAppHostBundleHeader = async (
  reader: FileRangeReader,
  fileOffset: number
): Promise<BundleHeaderParseResult> => {
  if (!validHeaderOffset(fileOffset, reader.size)) {
    return { issues: ["Single-file bundle header offset is outside the file."] };
  }
  const issues: string[] = [];
  const prefix = await reader.read(fileOffset, 14);
  if (prefix.byteLength < 13) {
    return { issues: ["Single-file bundle header is truncated before its bundle ID."] };
  }
  const majorVersion = prefix.getUint32(0, true);
  const minorVersion = prefix.getUint32(4, true);
  const idLength = readBundleIdLength(prefix);
  if (!idLength || idLength.length <= 0) {
    return { issues: ["Single-file bundle ID has an invalid length encoding."] };
  }
  if (!validBundleVersion(majorVersion, minorVersion)) {
    issues.push(`Unsupported single-file bundle header version ${majorVersion}.${minorVersion}.`);
  }
  if (prefix.getInt32(8, true) <= 0) issues.push("Single-file bundle declares no embedded files.");
  const totalSize = 12 + idLength.prefixBytes + idLength.length + (majorVersion >= 2 ? 40 : 0);
  const view = await reader.read(fileOffset, totalSize);
  if (view.byteLength !== totalSize) {
    return { issues: [...issues, "Single-file bundle header is truncated."] };
  }
  return parseHeaderContent(view, 12 + idLength.prefixBytes, idLength.length, reader.size, issues);
};

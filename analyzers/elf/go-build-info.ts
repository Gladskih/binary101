import { createFileRangeReader } from "../file-range-reader.js";
import type { ElfSectionHeader } from "./types.js";
import { elfFileRange } from "./relocation-reader.js";

export interface GoBuildInfo { version: string; moduleInfo: string }

// Go 1.18+ inline strings: https://go.dev/src/debug/buildinfo/buildinfo.go
const readString = (bytes: Uint8Array, offset: number): { bytes: Uint8Array; end: number } | null => {
  let size = 0n;
  for (let index = 0; index < 10 && offset + index < bytes.length; index++) {
    const byte = bytes[offset + index]!;
    size |= BigInt(byte & 127) << BigInt(index * 7);
    if (byte >= 128) continue;
    const start = offset + index + 1;
    if (size > BigInt(bytes.length - start)) return null;
    return { bytes: bytes.subarray(start, start + Number(size)),
      end: start + Number(size) };
  }
  return null;
};

function decodeModule(bytes: Uint8Array, decoder: TextDecoder): string {
  // Go strips two 16-byte binary sentinels; decode framing as bytes, not UTF-8 characters.
  return bytes.length >= 33 && bytes[bytes.length - 17] === 10
    ? decoder.decode(bytes.subarray(16, -16)) : "";
}

function hasBuildInfoHeader(bytes: Uint8Array): boolean {
  return bytes.length >= 32 && bytes[0] === 255 &&
    new TextDecoder().decode(bytes.subarray(1, 14)) === " Go buildinf:";
}

function decodeBuildInfo(bytes: Uint8Array, issues: string[]): GoBuildInfo | null {
  if (!hasBuildInfoHeader(bytes)) {
    issues.push("Go build information header is invalid or truncated.");
    return null;
  }
  if ((bytes[15]! & 2) === 0) {
    issues.push("Go build information uses the pre-1.18 pointer layout, which is not decoded.");
    return null;
  }
  const version = readString(bytes, 32);
  const module = version && readString(bytes, version.end);
  if (!version?.bytes.length || !module) {
    issues.push("Go build information strings are invalid or truncated.");
    return null;
  }
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    return { version: decoder.decode(version.bytes), moduleInfo: decodeModule(module.bytes, decoder) };
  } catch {
    issues.push("Go build information contains invalid UTF-8.");
    return null;
  }
}

export const parseGoBuildInfo = async (file: File, sections: ElfSectionHeader[],
  issues: string[]): Promise<GoBuildInfo | null> => {
  const section = sections.find(section => section.name === ".go.buildinfo");
  if (!section) return null;
  const range = elfFileRange(section.offset, section.size, file.size);
  // Resource policy: cap metadata at 1 MiB, independent of executable size.
  if (!range || range.size > 1024 * 1024) {
    issues.push("Go build information is outside the file or exceeds the 1 MiB limit.");
    return null;
  }
  return decodeBuildInfo(await createFileRangeReader(file, range.offset, range.size)
    .readBytes(0, range.size), issues);
};

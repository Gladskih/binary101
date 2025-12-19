"use strict";

import { alignUpTo, readAsciiString } from "../../binary-utils.js";
import type { ElfDebugLinkInfo, ElfSectionHeader } from "./types.js";

const toSafeIndex = (value: bigint, label: string, issues: string[]): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num) || num < 0) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

export async function parseElfDebugLink(
  file: File,
  sections: ElfSectionHeader[],
  littleEndian: boolean
): Promise<ElfDebugLinkInfo | null> {
  const debugLink = sections.find(sec => sec.name === ".gnu_debuglink" && sec.size > 0n);
  if (!debugLink) return null;

  const issues: string[] = [];
  const start = toSafeIndex(debugLink.offset, ".gnu_debuglink offset", issues);
  const size = toSafeIndex(debugLink.size, ".gnu_debuglink size", issues);
  if (start == null || size == null || size <= 0) return { fileName: "", crc32: null, issues };

  const end = Math.min(file.size, start + size);
  if (start >= file.size || end <= start) {
    issues.push(".gnu_debuglink falls outside the file.");
    return { fileName: "", crc32: null, issues };
  }
  if (end !== start + size) issues.push(".gnu_debuglink is truncated.");
  const bytes = new Uint8Array(await file.slice(start, end).arrayBuffer());
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const fileName = readAsciiString(dv, 0, dv.byteLength);
  const crcOffset = alignUpTo(fileName.length + 1, 4);
  let crc32: number | null = null;
  if (crcOffset + 4 <= dv.byteLength) {
    crc32 = dv.getUint32(crcOffset, littleEndian);
  } else {
    issues.push(".gnu_debuglink is missing the CRC32.");
  }
  return { fileName, crc32, issues };
}


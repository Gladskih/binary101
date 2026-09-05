"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import { scanAppHostSection } from "./section-scan.js";
import { APP_BINARY_PLACEHOLDER_TEXT } from "./patterns.js";
import type { PeSection } from "../types.js";
import { parsePeAppHostBundleHeader } from "./bundle-header.js";
import type {
  PeAppHostAnalysis,
  PeAppHostBinding,
  PeAppHostLocator
} from "./types.js";

type BundleHeaderCache = Map<bigint, Awaited<ReturnType<typeof parsePeAppHostBundleHeader>>>;

const isWritableInitializedData = (section: PeSection): boolean =>
  // Microsoft PE format: IMAGE_SCN_CNT_INITIALIZED_DATA and IMAGE_SCN_MEM_WRITE.
  // https://learn.microsoft.com/windows/win32/debug/pe-format#section-flags
  (section.characteristics & 0x00000040) !== 0 &&
  (section.characteristics & 0x80000000) !== 0;

// scanAppHostSection validates the file offset and clamps this mapped size to EOF.
// Raw/virtual section extents: https://learn.microsoft.com/windows/win32/debug/pe-format#section-table-section-headers
const sectionFileSize = (section: PeSection): number =>
  Math.min(section.sizeOfRawData >>> 0,
    (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0));

const fileOffsetToRva = (section: PeSection, fileOffset: number): number =>
  (section.virtualAddress >>> 0) + fileOffset - (section.pointerToRawData >>> 0);

const decodeBindingValue = (bytes: Uint8Array): string | null => {
  try {
    const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    // Candidate filenames exclude C0 controls (U+0000..U+001F), below ASCII space.
    // https://learn.microsoft.com/windows/win32/fileio/naming-a-file#naming-conventions
    if (!value.toLowerCase().endsWith(".dll") ||
      [...value].some(character => character.charCodeAt(0) < 0x20)) return null;
    return value;
  } catch {
    return null;
  }
};

const readBindingAt = async (
  reader: FileRangeReader,
  section: PeSection,
  suffixOffset: number
): Promise<PeAppHostBinding | null> => {
  const sectionStart = section.pointerToRawData >>> 0;
  // HostWriter replaces apphost's 1025-byte embed array, including its trailing NUL:
  // https://github.com/dotnet/runtime/blob/main/src/native/corehost/apphost/apphost.c
  // Include the preceding NUL as well as the 1020 bytes before the four-byte suffix.
  // 4 bytes are ASCII ".dll"; 5 includes its terminating NUL. This suffix search is
  // a binding heuristic; the apphost format permits up to 1024 UTF-8 path bytes.
  const windowStart = Math.max(sectionStart, suffixOffset - 1021);
  const bytes = await reader.readBytes(windowStart, suffixOffset + 5 - windowStart);
  if (bytes.byteLength !== suffixOffset + 5 - windowStart) return null;
  const suffixIndex = suffixOffset - windowStart;
  const start = bytes.subarray(0, suffixIndex).lastIndexOf(0) + 1;
  if (start === 0 && windowStart !== sectionStart) return null;
  const valueBytes = bytes.subarray(start, suffixIndex + 4);
  // The validated suffix contributes four bytes, so the path cannot be empty.
  if (valueBytes.byteLength > 1024) return null;
  const value = decodeBindingValue(valueBytes);
  return value == null ? null : {
    rva: fileOffsetToRva(section, windowStart + start),
    kind: "managed-assembly",
    value
  };
};

const readLocatorAt = async (
  reader: FileRangeReader,
  section: PeSection,
  signatureOffset: number,
  issues: string[],
  headers: BundleHeaderCache
): Promise<PeAppHostLocator> => {
  // The packed marker is int64 header offset (8 bytes) followed by the signature.
  // https://github.com/dotnet/runtime/blob/main/src/native/corehost/apphost/bundle_marker.c
  const markerOffset = signatureOffset - 8;
  const rva = fileOffsetToRva(section, Math.max(markerOffset, section.pointerToRawData >>> 0));
  if (markerOffset < (section.pointerToRawData >>> 0)) {
    issues.push(".NET apphost bundle signature precedes its containing section locator.");
    return { rva, bundleHeaderOffset: null };
  }
  const locator = await reader.read(markerOffset, 8);
  if (locator.byteLength !== 8) {
    issues.push(".NET apphost bundle locator is truncated.");
    return { rva, bundleHeaderOffset: null };
  }
  const bundleHeaderOffset = locator.getBigInt64(0, true);
  if (bundleHeaderOffset === 0n) return { rva, bundleHeaderOffset };
  if (bundleHeaderOffset < 0n || bundleHeaderOffset >= BigInt(reader.size) ||
    bundleHeaderOffset > BigInt(Number.MAX_SAFE_INTEGER)) {
    issues.push(".NET apphost bundle header offset points outside the file.");
    return { rva, bundleHeaderOffset };
  }
  const parsed = headers.get(bundleHeaderOffset) ??
    await parsePeAppHostBundleHeader(reader, Number(bundleHeaderOffset));
  headers.set(bundleHeaderOffset, parsed);
  issues.push(...parsed.issues);
  return {
    rva,
    bundleHeaderOffset,
    ...(parsed.header ? { bundleHeader: parsed.header } : {})
  };
};

const uniqueBindings = (bindings: PeAppHostBinding[]): PeAppHostBinding[] =>
  [...new Map(bindings.map(binding => [`${binding.rva}:${binding.value}`, binding])).values()];

const addBindingIssues = (bindings: PeAppHostBinding[], issues: string[]): void => {
  if (!bindings.length) issues.push("The embedded managed application path was not found.");
  if (bindings.length > 1) issues.push("Multiple embedded managed application paths were found.");
};

export const analyzePeAppHost = async (
  file: File,
  reader: FileRangeReader,
  sections: readonly PeSection[]
): Promise<PeAppHostAnalysis | null> => {
  const issues: string[] = [];
  const locators: PeAppHostLocator[] = [];
  const bindings: PeAppHostBinding[] = [];
  const headers: BundleHeaderCache = new Map();
  for (const section of sections.filter(isWritableInitializedData)) {
    const matches = await scanAppHostSection(
      file, section.pointerToRawData >>> 0, sectionFileSize(section)
    );
    issues.push(...matches.issues);
    for (const offset of matches.locators) {
      locators.push(await readLocatorAt(reader, section, offset, issues, headers));
    }
    for (const { offset, kind } of matches.bindings) {
      if (kind === "unbound-placeholder") {
        bindings.push({
          rva: fileOffsetToRva(section, offset),
          kind: "unbound-placeholder",
          value: APP_BINARY_PLACEHOLDER_TEXT
        });
      } else {
        const binding = await readBindingAt(reader, section, offset);
        if (binding) bindings.push(binding);
      }
    }
  }
  if (!locators.length) return null;
  if (locators.length > 1) issues.push("Multiple .NET apphost bundle locators were found.");
  const distinctBindings = uniqueBindings(bindings);
  addBindingIssues(distinctBindings, issues);
  return { locators, bindings: distinctBindings, issues: [...new Set(issues)] };
};

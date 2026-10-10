"use strict";

import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import type { PeClrHeader } from "./types.js";
import { decodeReadyToRunSections, type ReadyToRunSectionCache } from "./ready-to-run-sections.js";
import { readyToRunPointerSize } from "./ready-to-run-target.js";
import { validateReadyToRunReferences } from "./ready-to-run-references.js";
import type { PeClrReadyToRun } from "./ready-to-run-types.js";
import { readReadyToRunDirectory } from "./ready-to-run-directory.js";
import { decodeReadyToRunComponents } from "./ready-to-run-components.js";
import { decodeReadyToRunDebugSections } from "./ready-to-run-debug-sections.js";

const emptyReadyToRun = (
  status: PeClrReadyToRun["status"],
  issues: string[]
): PeClrReadyToRun => ({
  status,
  signature: null,
  majorVersion: null,
  minorVersion: null,
  flags: null,
  sectionCount: 0,
  sections: [],
  issues
});

const classifyNativeHeader = (signature: number): PeClrReadyToRun => ({
  // NGen's version-specific CORCOMPILE_HEADER must not be read as ReadyToRun.
  // https://raw.githubusercontent.com/dotnet/coreclr/master/src/inc/corcompile.h
  ...emptyReadyToRun(signature === 0x0045474e ? "ngen" : "unknown-managed-native-header", []),
  signature
});

const decodeHeader = async (
  reader: FileRangeReader, mapper: RvaToOffset, rva: number,
  size: number | undefined, header: DataView, machine: number | undefined
): Promise<PeClrReadyToRun> => {
  const signature = header.getUint32(0, true);
  if (signature !== 0x00525452) return classifyNativeHeader(signature);
  const issues: string[] = [];
  const sectionCount = header.getUint32(12, true);
  const sections = await readReadyToRunDirectory(reader, mapper, rva + 16,
    Math.min(size === undefined ? sectionCount * 12 : size - 16, 0x100000000 - rva - 16),
    sectionCount, issues);
  const cache: ReadyToRunSectionCache = new Map();
  await decodeReadyToRunSections(reader, mapper, sections, readyToRunPointerSize(machine), issues, cache);
  validateReadyToRunReferences(sections, machine, issues);
  const data: PeClrReadyToRun = { status: "ready-to-run", signature,
    majorVersion: header.getUint16(4, true), minorVersion: header.getUint16(6, true),
    flags: header.getUint32(8, true), sectionCount, sections, issues };
  await decodeReadyToRunComponents(reader, mapper, data, machine, cache);
  await decodeReadyToRunDebugSections(reader, mapper, data, machine);
  return data;
};

// Composite RTR_HEADER exports carry an RVA, without a directory size.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/PEReaderExtensions.cs
export const parseReadyToRunImageHeader = async (
  reader: FileRangeReader, mapper: RvaToOffset, rva: number,
  size: number | undefined, machine?: number
): Promise<PeClrReadyToRun> => {
  try {
    const offset = mapper(rva);
    if (offset == null || !Number.isSafeInteger(offset) || offset < 0 || offset >= reader.size) {
      return emptyReadyToRun("unmapped", ["ManagedNativeHeader RVA could not be mapped to a file offset."]);
    }
    const header = await readMappedRvaPrefix(reader, rva, Math.min(size ?? 16, 16), mapper);
    if (header.byteLength < 16) {
      return emptyReadyToRun("truncated", ["ManagedNativeHeader is shorter than 16 bytes."]);
    }
    return await decodeHeader(reader, mapper, rva, size, header, machine);
  } catch (error) {
    return emptyReadyToRun("truncated", [error instanceof Error ? error.message : "ReadyToRun header read failed"]);
  }
};

export const parseReadyToRun = async (
  reader: FileRangeReader, mapper: RvaToOffset, clr: PeClrHeader, machine?: number
): Promise<PeClrReadyToRun> => clr.ManagedNativeHeaderRVA === 0 && clr.ManagedNativeHeaderSize === 0
  ? emptyReadyToRun("absent", [])
  : parseReadyToRunImageHeader(reader, mapper, clr.ManagedNativeHeaderRVA,
    clr.ManagedNativeHeaderSize, machine);

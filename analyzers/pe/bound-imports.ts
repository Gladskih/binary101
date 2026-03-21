"use strict";

import { readAsciiString } from "../../binary-utils.js";
import type {
  AddCoverageRegion,
  PeDataDirectory,
  RvaToOffset
} from "./types.js";

const IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE = 8; // winnt.h: IMAGE_BOUND_IMPORT_DESCRIPTOR is 8 bytes.

const readBoundedAsciiString = async (
  file: File,
  offset: number,
  limit: number
): Promise<{ text: string; truncated: boolean } | null> => {
  if (offset < 0 || offset >= file.size || limit <= 0) return null;
  const readLength = Math.min(limit, file.size - offset);
  const view = new DataView(await file.slice(offset, offset + readLength).arrayBuffer());
  const text = readAsciiString(view, 0, readLength);
  return { text, truncated: text.length === readLength };
};

const readBoundImportName = async (
  file: File,
  nameOffset: number,
  directoryStart: number,
  directoryEnd: number,
  warnings: Set<string>
): Promise<string> => {
  if (nameOffset < directoryStart || nameOffset >= directoryEnd) {
    warnings.add("Bound import name offset points outside directory.");
    return "";
  }
  if (nameOffset >= file.size) {
    warnings.add("Bound import name offset points outside file data.");
    return "";
  }
  const result = await readBoundedAsciiString(file, nameOffset, directoryEnd - nameOffset);
  if (!result) {
    warnings.add("Bound import name offset points outside file data.");
    return "";
  }
  if (result.truncated) warnings.add("Bound import name is truncated.");
  return result.text;
};

export interface PeBoundImportEntry {
  name: string;
  TimeDateStamp: number;
  NumberOfModuleForwarderRefs: number;
}

export async function parseBoundImports(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<{ entries: PeBoundImportEntry[]; warning?: string } | null> {
  const dir = dataDirs.find(d => d.name === "BOUND_IMPORT");
  if (!dir?.rva) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  const availableDirSize = Math.max(0, Math.min(dir.size, file.size - base));
  addCoverageRegion("BOUND_IMPORT", base, availableDirSize);
  if (availableDirSize < IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE) {
    return {
      entries: [],
      warning: "Bound import directory is smaller than one descriptor; file may be truncated."
    };
  }
  const end = base + availableDirSize;
  const entries: PeBoundImportEntry[] = [];
  const warnings = new Set<string>();
  let off = base;
  while (off + IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE <= end) {
    const dv = new DataView(
      await file.slice(off, off + IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE).arrayBuffer()
    );
    if (dv.byteLength < IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE) {
      warnings.add("Bound import descriptor truncated.");
      break;
    }
    const TimeDateStamp = dv.getUint32(0, true);
    const OffsetModuleName = dv.getUint16(4, true);
    const NumberOfModuleForwarderRefs = dv.getUint16(6, true);
    if (!TimeDateStamp && !OffsetModuleName && !NumberOfModuleForwarderRefs) break;
    entries.push({
      name: OffsetModuleName
        ? await readBoundImportName(file, base + OffsetModuleName, base, end, warnings)
        : "",
      TimeDateStamp,
      NumberOfModuleForwarderRefs
    });
    const nextOff =
      off + IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE + NumberOfModuleForwarderRefs * IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE;
    if (nextOff > end) {
      warnings.add("Bound import forwarder refs extend past directory.");
      break;
    }
    off = nextOff;
  }
  const warning = warnings.size ? Array.from(warnings).join(" | ") : undefined;
  return warning ? { entries, warning } : { entries };
}

"use strict";

import { readAsciiString } from "../../binary-utils.js";
import type { FileRangeReader } from "../file-range-reader.js";
import type { PeDataDirectory, RvaToOffset } from "./types.js";

const IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE = 8; // winnt.h: IMAGE_BOUND_IMPORT_DESCRIPTOR is 8 bytes.

const readBoundedAsciiString = async (
  reader: FileRangeReader,
  offset: number,
  limit: number
): Promise<{ text: string; truncated: boolean } | null> => {
  if (offset < 0 || offset >= reader.size || limit <= 0) return null;
  const readLength = Math.min(limit, reader.size - offset);
  const view = await reader.read(offset, readLength);
  const text = readAsciiString(view, 0, readLength);
  return { text, truncated: text.length === readLength };
};

const readBoundImportName = async (
  reader: FileRangeReader,
  nameOffset: number,
  directoryStart: number,
  directoryEnd: number,
  warnings: Set<string>
): Promise<string> => {
  if (nameOffset < directoryStart || nameOffset >= directoryEnd) {
    warnings.add("Bound import name offset points outside directory.");
    return "";
  }
  if (nameOffset >= reader.size) {
    warnings.add("Bound import name offset points outside file data.");
    return "";
  }
  const result = await readBoundedAsciiString(reader, nameOffset, directoryEnd - nameOffset);
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
  forwarderRefs?: PeBoundForwarderRef[];
}

export interface PeBoundForwarderRef {
  name: string;
  TimeDateStamp: number;
}

type BoundImportRecord = {
  TimeDateStamp: number;
  OffsetModuleName: number;
  reservedOrForwarderRefCount: number;
};

const readBoundImportRecord = async (
  reader: FileRangeReader,
  offset: number
): Promise<BoundImportRecord | null> => {
  const dv = await reader.read(offset, IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE);
  if (dv.byteLength < IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE) {
    return null;
  }
  return {
    TimeDateStamp: dv.getUint32(0, true),
    OffsetModuleName: dv.getUint16(4, true),
    reservedOrForwarderRefCount: dv.getUint16(6, true)
  };
};

export async function parseBoundImports(
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<{ entries: PeBoundImportEntry[]; warning?: string } | null> {
  const dir = dataDirs.find(d => d.name === "BOUND_IMPORT");
  if (!dir?.rva) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) {
    return { entries: [], warning: "Bound import directory RVA does not map to file data." };
  }
  if (base < 0 || base >= reader.size) {
    return { entries: [], warning: "Bound import directory starts outside file data." };
  }
  const availableDirSize = Math.max(0, Math.min(dir.size, reader.size - base));
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
    const record = await readBoundImportRecord(reader, off);
    if (!record) {
      warnings.add("Bound import descriptor truncated.");
      break;
    }
    const {
      TimeDateStamp,
      OffsetModuleName,
      reservedOrForwarderRefCount: NumberOfModuleForwarderRefs
    } = record;
    if (!TimeDateStamp && !OffsetModuleName && !NumberOfModuleForwarderRefs) break;
    const forwarderRefs: PeBoundForwarderRef[] = [];
    const availableForwarderRefCount = Math.floor(
      Math.max(0, end - (off + IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE)) / IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE
    );
    const readableForwarderRefCount = Math.min(NumberOfModuleForwarderRefs, availableForwarderRefCount);
    if (readableForwarderRefCount < NumberOfModuleForwarderRefs) {
      warnings.add("Bound import forwarder refs extend past directory.");
    }
    for (let forwarderIndex = 0; forwarderIndex < readableForwarderRefCount; forwarderIndex += 1) {
      const forwarderOffset =
        off + IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE + forwarderIndex * IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE;
      const forwarderRef = await readBoundImportRecord(reader, forwarderOffset);
      if (!forwarderRef) {
        warnings.add("Bound import forwarder ref truncated.");
        break;
      }
      forwarderRefs.push({
        name: forwarderRef.OffsetModuleName
          ? await readBoundImportName(
              reader,
              base + forwarderRef.OffsetModuleName,
              base,
              end,
              warnings
            )
          : "",
        TimeDateStamp: forwarderRef.TimeDateStamp
      });
    }
    entries.push({
      name: OffsetModuleName
        ? await readBoundImportName(reader, base + OffsetModuleName, base, end, warnings)
        : "",
      TimeDateStamp,
      NumberOfModuleForwarderRefs,
      ...(forwarderRefs.length ? { forwarderRefs } : {})
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

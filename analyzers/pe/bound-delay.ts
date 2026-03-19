"use strict";

import { readAsciiString } from "../../binary-utils.js";
import type {
  AddCoverageRegion,
  PeDataDirectory,
  RvaToOffset
} from "./types.js";

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
  const result = await readBoundedAsciiString(
    file,
    nameOffset,
    Math.min(256, directoryEnd - nameOffset)
  );
  if (!result) {
    warnings.add("Bound import name offset points outside file data.");
    return "";
  }
  if (result.truncated) warnings.add("Bound import name is truncated.");
  return result.text;
};

const readDelayImportName = async (
  file: File,
  nameOffset: number,
  warnings: Set<string>
): Promise<string> => {
  if (nameOffset < 0 || nameOffset >= file.size) {
    warnings.add("Delay import name RVA does not map to file data.");
    return "";
  }
  const result = await readBoundedAsciiString(file, nameOffset, 256);
  if (!result) {
    warnings.add("Delay import name RVA does not map to file data.");
    return "";
  }
  if (result.truncated) warnings.add("Delay import name string truncated.");
  return result.text;
};

const readDelayImportHintName = async (
  file: File,
  rvaToOff: RvaToOffset,
  hintNameRva: number,
  warnings: Set<string>
): Promise<{ ordinal?: number; hint?: number; name?: string }> => {
  const hintNameOff = rvaToOff(hintNameRva);
  if (hintNameOff == null || hintNameOff < 0 || hintNameOff >= file.size) {
    warnings.add("Delay import hint/name RVA does not map to file data.");
    return { name: "<bad RVA>" };
  }
  const hintView = new DataView(await file.slice(hintNameOff, hintNameOff + 2).arrayBuffer());
  if (hintView.byteLength < 2) {
    warnings.add("Delay import hint/name table truncated.");
    return { name: "" };
  }
  const hint = hintView.getUint16(0, true);
  const result = await readBoundedAsciiString(file, hintNameOff + 2, 256);
  if (!result) {
    warnings.add("Delay import name string does not map to file data.");
    return { hint, name: "" };
  }
  if (result.truncated) warnings.add("Delay import name string truncated.");
  return { hint, name: result.text };
};

export interface PeBoundImportEntry {
  name: string;
  TimeDateStamp: number;
  NumberOfModuleForwarderRefs: number;
}

export interface PeDelayImportEntry {
  name: string;
  Attributes: number;
  ModuleHandleRVA: number;
  ImportAddressTableRVA: number;
  ImportNameTableRVA: number;
  BoundImportAddressTableRVA: number;
  UnloadInformationTableRVA: number;
  TimeDateStamp: number;
  functions: Array<{ ordinal?: number; hint?: number; name?: string }>;
}

export async function parseBoundImports(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<{ entries: PeBoundImportEntry[]; warning?: string } | null> {
  const dir = dataDirs.find(d => d.name === "BOUND_IMPORT");
  if (!dir?.rva || dir.size < 8) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  addCoverageRegion("BOUND_IMPORT", base, dir.size);
  const end = base + dir.size;
  const entries: PeBoundImportEntry[] = [];
  const warnings = new Set<string>();
  let off = base;
  while (off + 8 <= end) {
    const dv = new DataView(await file.slice(off, off + 8).arrayBuffer());
    if (dv.byteLength < 8) {
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
    const nextOff = off + 8 + NumberOfModuleForwarderRefs * 8;
    if (nextOff > end) {
      warnings.add("Bound import forwarder refs extend past directory.");
      break;
    }
    off = nextOff;
  }
  const warning = warnings.size ? Array.from(warnings).join(" · ") : undefined;
  return warning ? { entries, warning } : { entries };
}

export async function parseDelayImports(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion,
  isPlus: boolean,
  _imageBase: number
): Promise<{ entries: PeDelayImportEntry[]; warning?: string } | null> {
  const dir = dataDirs.find(d => d.name === "DELAY_IMPORT");
  if (!dir?.rva || dir.size < 32) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  addCoverageRegion("DELAY_IMPORT", base, dir.size);
  const end = base + dir.size;
  const entries: PeDelayImportEntry[] = [];
  const warnings = new Set<string>();
  let off = base;
  while (off + 32 <= end) {
    const dv = new DataView(await file.slice(off, off + 32).arrayBuffer());
    if (dv.byteLength < 32) {
      warnings.add("Delay import descriptor truncated.");
      break;
    }
    const Attributes = dv.getUint32(0, true);
    const DllNameRVA = dv.getUint32(4, true);
    const ModuleHandleRVA = dv.getUint32(8, true);
    const ImportAddressTableRVA = dv.getUint32(12, true);
    const ImportNameTableRVA = dv.getUint32(16, true);
    const BoundImportAddressTableRVA = dv.getUint32(20, true);
    const UnloadInformationTableRVA = dv.getUint32(24, true);
    const TimeDateStamp = dv.getUint32(28, true);
    if (!Attributes && !DllNameRVA) break;
    if (Attributes !== 0) warnings.add("Delay import descriptor Attributes must be zero.");
    const nameOff = rvaToOff(DllNameRVA);
    if (DllNameRVA && nameOff == null) warnings.add("Delay import name RVA does not map to file data.");
    const functions: Array<{ ordinal?: number; hint?: number; name?: string }> = [];
    const intRva = ImportNameTableRVA >>> 0;
    const intOff = intRva ? rvaToOff(intRva) : null;
    if (intOff != null) {
      if (isPlus) {
        for (let index = 0; index < 8 * 16384; index += 8) {
          const thunkView = new DataView(await file.slice(intOff + index, intOff + index + 8).arrayBuffer());
          if (thunkView.byteLength < 8) {
            warnings.add("Delay import thunk table truncated (64-bit).");
            break;
          }
          const value = thunkView.getBigUint64(0, true);
          if (value === 0n) break;
          if ((value & 0x8000000000000000n) !== 0n) {
            functions.push({ ordinal: Number(value & 0xffffn) });
          } else {
            functions.push(await readDelayImportHintName(file, rvaToOff, Number(value & 0xffffffffn), warnings));
          }
        }
      } else {
        for (let index = 0; index < 4 * 32768; index += 4) {
          const thunkView = new DataView(await file.slice(intOff + index, intOff + index + 4).arrayBuffer());
          if (thunkView.byteLength < 4) {
            warnings.add("Delay import thunk table truncated (32-bit).");
            break;
          }
          const value = thunkView.getUint32(0, true);
          if (value === 0) break;
          if ((value & 0x80000000) !== 0) {
            functions.push({ ordinal: value & 0xffff });
          } else {
            functions.push(await readDelayImportHintName(file, rvaToOff, value, warnings));
          }
        }
      }
    }
    entries.push({
      name: nameOff != null ? await readDelayImportName(file, nameOff, warnings) : "",
      Attributes,
      ModuleHandleRVA,
      ImportAddressTableRVA,
      ImportNameTableRVA,
      BoundImportAddressTableRVA,
      UnloadInformationTableRVA,
      TimeDateStamp,
      functions
    });
    off += 32;
  }
  const warning = warnings.size ? Array.from(warnings).join(" · ") : undefined;
  return warning ? { entries, warning } : { entries };
}

"use strict";

import { readAsciiString } from "../../binary-utils.js";
import type {
  AddCoverageRegion,
  PeDataDirectory,
  RvaToOffset
} from "./types.js";

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
    let name = "";
    const nameOff = base + OffsetModuleName;
    if (nameOff >= base && nameOff < end) {
      const nameView = new DataView(await file.slice(nameOff, nameOff + 256).arrayBuffer());
      name = readAsciiString(nameView, 0, 256);
    } else if (OffsetModuleName) {
      warnings.add("Bound import name offset points outside directory.");
    }
    entries.push({ name, TimeDateStamp, NumberOfModuleForwarderRefs });
    off += 8;
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
  imageBase: number
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
    let name = "";
    const nameOff = rvaToOff(DllNameRVA);
    if (nameOff != null) {
      const nameView = new DataView(await file.slice(nameOff, nameOff + 256).arrayBuffer());
      name = readAsciiString(nameView, 0, 256);
    } else if (DllNameRVA) {
      warnings.add("Delay import name RVA does not map to file data.");
    }
    const rvaFromMaybeVa = (value: number): number => {
      const isRva = (Attributes & 1) !== 0;
      const raw = value >>> 0;
      if (raw === 0) return 0;
      if (isRva) return raw;
      const baseImage = imageBase >>> 0;
      return ((raw - baseImage) >>> 0);
    };
    const functions: Array<{ ordinal?: number; hint?: number; name?: string }> = [];
    const intRva = rvaFromMaybeVa(ImportNameTableRVA);
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
            const hintNameRva = Number(value & 0xffffffffn);
            const hintNameOff = rvaToOff(hintNameRva);
            if (hintNameOff != null) {
              const hintView = new DataView(await file.slice(hintNameOff, hintNameOff + 2).arrayBuffer());
              if (hintView.byteLength < 2) break;
              const hint = hintView.getUint16(0, true);
              let funcName = "";
              let pos = hintNameOff + 2;
              for (;;) {
                const chunk = new Uint8Array(await file.slice(pos, pos + 64).arrayBuffer());
                const zeroIndex = chunk.indexOf(0);
                if (chunk.byteLength === 0 || (zeroIndex === -1 && pos + 64 > file.size)) {
                  warnings.add("Delay import name string truncated.");
                  break;
                }
                if (zeroIndex === -1) {
                  funcName += String.fromCharCode(...chunk);
                  pos += 64;
                  if (pos > file.size) break;
                } else {
                  if (zeroIndex > 0) funcName += String.fromCharCode(...chunk.slice(0, zeroIndex));
                  break;
                }
              }
              functions.push({ hint, name: funcName });
            } else {
              functions.push({ name: "<bad RVA>" });
            }
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
            const hintNameOff = rvaToOff(value);
            if (hintNameOff != null) {
              const hintView = new DataView(await file.slice(hintNameOff, hintNameOff + 2).arrayBuffer());
              if (hintView.byteLength < 2) break;
              const hint = hintView.getUint16(0, true);
              let funcName = "";
              let pos = hintNameOff + 2;
              for (;;) {
                const chunk = new Uint8Array(await file.slice(pos, pos + 64).arrayBuffer());
                const zeroIndex = chunk.indexOf(0);
                if (chunk.byteLength === 0 || (zeroIndex === -1 && pos + 64 > file.size)) {
                  warnings.add("Delay import name string truncated.");
                  break;
                }
                if (zeroIndex === -1) {
                  funcName += String.fromCharCode(...chunk);
                  pos += 64;
                  if (pos > file.size) break;
                } else {
                  if (zeroIndex > 0) funcName += String.fromCharCode(...chunk.slice(0, zeroIndex));
                  break;
                }
              }
              functions.push({ hint, name: funcName });
            } else {
              functions.push({ name: "<bad RVA>" });
            }
          }
        }
      }
    }
    entries.push({
      name,
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

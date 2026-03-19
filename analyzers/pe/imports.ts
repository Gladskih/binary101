"use strict";

import { readAsciiString } from "../../binary-utils.js";
import type {
  AddCoverageRegion,
  PeDataDirectory,
  RvaToOffset
} from "./types.js";

export interface PeImportFunction {
  ordinal?: number;
  hint?: number;
  name?: string;
}

export interface PeImportEntry {
  dll: string;
  functions: PeImportFunction[];
}

export interface PeImportParseResult {
  entries: PeImportEntry[];
  warning?: string;
}

export async function parseImportDirectory(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion,
  isPlus: boolean
): Promise<PeImportParseResult> {
  const impDir = dataDirs.find(d => d.name === "IMPORT");
  const imports: PeImportEntry[] = [];
  const warnings = new Set<string>();
  const isReadableOffset = (offset: number | null): offset is number =>
    offset != null && offset >= 0 && offset < file.size;
  if (!impDir?.rva) return { entries: imports };
  const start = rvaToOff(impDir.rva);
  if (start == null || start >= file.size) return { entries: imports };
  const availableDirSize = Math.max(0, Math.min(impDir.size, file.size - start));
  addCoverageRegion("IMPORT directory", start, availableDirSize);
  const maxDescriptors = Math.ceil(availableDirSize / 20);
  const addWarning = (msg: string): void => {
    warnings.add(msg);
  };
  for (let index = 0; index < maxDescriptors; index += 1) {
    const offset = start + index * 20;
    const descriptorSize = Math.min(20, Math.max(0, availableDirSize - index * 20));
    if (descriptorSize <= 0) break;
    const descriptorTruncated = descriptorSize < 20;
    const desc = new DataView(await file.slice(offset, offset + descriptorSize).arrayBuffer());
    const readDescriptorField = (fieldOffset: number, fieldName: string): number | null => {
      if (desc.byteLength < fieldOffset + 4) {
        addWarning(`Import descriptor is truncated before the ${fieldName} field.`);
        return null;
      }
      return desc.getUint32(fieldOffset, true);
    };
    const originalFirstThunk = readDescriptorField(0, "OriginalFirstThunk") ?? 0;
    const nameRva = readDescriptorField(12, "name RVA") ?? 0;
    const firstThunk = readDescriptorField(16, "thunk RVA") ?? 0;
    if (!originalFirstThunk && !nameRva && !firstThunk) break;
    const nameOffset = rvaToOff(nameRva);
    let dllName = "";
    if (isReadableOffset(nameOffset)) {
      const dv = new DataView(await file.slice(nameOffset, nameOffset + 256).arrayBuffer());
      dllName = readAsciiString(dv, 0, 256);
    } else if (nameRva) {
      addWarning("Import name RVA does not map to file data.");
    }
    if (descriptorTruncated) break;
    const thunkRva = originalFirstThunk || firstThunk;
    const thunkOffset = rvaToOff(thunkRva);
    const functions: PeImportFunction[] = [];
    if (!isReadableOffset(thunkOffset)) {
      if (thunkRva) addWarning("Import thunk RVA does not map to file data.");
    } else {
      if (isPlus) {
        for (let t = 0; t < 8 * 16384; t += 8) {
          const dv = new DataView(await file.slice(thunkOffset + t, thunkOffset + t + 8).arrayBuffer());
          if (dv.byteLength < 8) {
            addWarning("Import thunks truncated (64-bit).");
            break;
          }
          const value = dv.getBigUint64(0, true);
          if (value === 0n) break;
          if ((value & 0x8000000000000000n) !== 0n) {
            if ((value & 0x7fffffffffff0000n) !== 0n) {
              addWarning("Import ordinal thunk has reserved bits set.");
            }
            functions.push({ ordinal: Number(value & 0xffffn) });
          } else {
            const hintNameRva = Number(value & 0xffffffffn);
            const hintNameOffset = rvaToOff(hintNameRva);
            if (isReadableOffset(hintNameOffset)) {
              const hintView = new DataView(await file.slice(hintNameOffset, hintNameOffset + 2).arrayBuffer());
              if (hintView.byteLength < 2) {
                addWarning("Import hint/name table truncated.");
                break;
              }
              const hint = hintView.getUint16(0, true);
              let name = "";
              let pos = hintNameOffset + 2;
              for (;;) {
                const chunk = new Uint8Array(await file.slice(pos, pos + 64).arrayBuffer());
                const zeroIndex = chunk.indexOf(0);
                if (chunk.byteLength === 0) {
                  addWarning("Import name string truncated.");
                  break;
                }
                if (zeroIndex === -1) {
                  name += String.fromCharCode(...chunk);
                  pos += 64;
                  if (pos > file.size) break;
                } else {
                  if (zeroIndex > 0) name += String.fromCharCode(...chunk.slice(0, zeroIndex));
                  break;
                }
              }
              functions.push({ hint, name });
            } else {
              functions.push({ name: "<bad RVA>" });
            }
          }
        }
      } else {
        for (let t = 0; t < 4 * 32768; t += 4) {
          const dv = new DataView(await file.slice(thunkOffset + t, thunkOffset + t + 4).arrayBuffer());
          if (dv.byteLength < 4) {
            addWarning("Import thunks truncated (32-bit).");
            break;
          }
          const value = dv.getUint32(0, true);
          if (value === 0) break;
          if ((value & 0x80000000) !== 0) {
            if ((value & 0x7fff0000) !== 0) {
              addWarning("Import ordinal thunk has reserved bits set.");
            }
            functions.push({ ordinal: value & 0xffff });
          } else {
            const hintNameOffset = rvaToOff(value);
            if (isReadableOffset(hintNameOffset)) {
              const hintView = new DataView(await file.slice(hintNameOffset, hintNameOffset + 2).arrayBuffer());
              if (hintView.byteLength < 2) {
                addWarning("Import hint/name table truncated.");
                break;
              }
              const hint = hintView.getUint16(0, true);
              let name = "";
              let pos = hintNameOffset + 2;
              for (;;) {
                const chunk = new Uint8Array(await file.slice(pos, pos + 64).arrayBuffer());
                const zeroIndex = chunk.indexOf(0);
                if (chunk.byteLength === 0) {
                  addWarning("Import name string truncated.");
                  break;
                }
                if (zeroIndex === -1) {
                  name += String.fromCharCode(...chunk);
                  pos += 64;
                  if (pos > file.size) break;
                } else {
                  if (zeroIndex > 0) name += String.fromCharCode(...chunk.slice(0, zeroIndex));
                  break;
                }
              }
              functions.push({ hint, name });
            } else {
              functions.push({ name: "<bad RVA>" });
            }
          }
        }
      }
    }
    imports.push({ dll: dllName, functions });
  }
  const warning = warnings.size ? Array.from(warnings).join(" · ") : undefined;
  return warning ? { entries: imports, warning } : { entries: imports };
}

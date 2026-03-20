"use strict";

import { readAsciiString } from "../../binary-utils.js";
import type {
  AddCoverageRegion,
  PeDataDirectory,
  RvaToOffset
} from "./types.js";

const IMAGE_IMPORT_DESCRIPTOR_SIZE = 20;
const IMAGE_THUNK_DATA32_SIZE = 4;
const IMAGE_THUNK_DATA64_SIZE = 8;
const IMAGE_ORDINAL_FLAG32 = 0x80000000;
const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000n;
const IMAGE_IMPORT_NAME_MASK64 = 0x7fffffffn;
const IMAGE_IMPORT_NAME_RESERVED_MASK64 = 0x7fffffff80000000n;
const IMAGE_IMPORT_ORDINAL_RESERVED_MASK64 = 0x7fffffffffff0000n;

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
  const maxThunkEntries = (entrySize: number): number =>
    Math.floor(file.size / entrySize) + 1;
  if (!impDir?.rva) return { entries: imports };
  const start = rvaToOff(impDir.rva);
  if (start == null || start >= file.size) return { entries: imports };
  const availableDirSize = Math.max(0, Math.min(impDir.size, file.size - start));
  addCoverageRegion("IMPORT directory", start, availableDirSize);
  const maxDescriptors = Math.ceil(availableDirSize / IMAGE_IMPORT_DESCRIPTOR_SIZE);
  const addWarning = (msg: string): void => {
    warnings.add(msg);
  };
  for (let index = 0; index < maxDescriptors; index += 1) {
    const offset = start + index * IMAGE_IMPORT_DESCRIPTOR_SIZE;
    const descriptorSize = Math.min(
      IMAGE_IMPORT_DESCRIPTOR_SIZE,
      Math.max(0, availableDirSize - index * IMAGE_IMPORT_DESCRIPTOR_SIZE)
    );
    if (descriptorSize <= 0) break;
    const descriptorTruncated = descriptorSize < IMAGE_IMPORT_DESCRIPTOR_SIZE;
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
    const functions: PeImportFunction[] = [];
    if (thunkRva) {
      if (isPlus) {
        for (let thunkIndex = 0; thunkIndex < maxThunkEntries(IMAGE_THUNK_DATA64_SIZE); thunkIndex += 1) {
          const thunkEntryRva = thunkRva + thunkIndex * IMAGE_THUNK_DATA64_SIZE;
          const thunkEntryOffset = rvaToOff(thunkEntryRva >>> 0);
          if (!isReadableOffset(thunkEntryOffset)) {
            if (thunkIndex === 0) addWarning("Import thunk RVA does not map to file data.");
            break;
          }
          const dv = new DataView(
            await file
              .slice(thunkEntryOffset, thunkEntryOffset + IMAGE_THUNK_DATA64_SIZE)
              .arrayBuffer()
          );
          if (dv.byteLength < IMAGE_THUNK_DATA64_SIZE) {
            addWarning("Import thunks truncated (64-bit).");
            break;
          }
          const value = dv.getBigUint64(0, true);
          if (value === 0n) break;
          if ((value & IMAGE_ORDINAL_FLAG64) !== 0n) {
            if ((value & IMAGE_IMPORT_ORDINAL_RESERVED_MASK64) !== 0n) {
              addWarning("Import ordinal thunk has reserved bits set.");
            }
            functions.push({ ordinal: Number(value & 0xffffn) });
          } else {
            if ((value & IMAGE_IMPORT_NAME_RESERVED_MASK64) !== 0n) {
              addWarning("Import name thunk has reserved bits set.");
            }
            const hintNameRva = Number(value & IMAGE_IMPORT_NAME_MASK64);
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
        for (let thunkIndex = 0; thunkIndex < maxThunkEntries(IMAGE_THUNK_DATA32_SIZE); thunkIndex += 1) {
          const thunkEntryRva = thunkRva + thunkIndex * IMAGE_THUNK_DATA32_SIZE;
          const thunkEntryOffset = rvaToOff(thunkEntryRva >>> 0);
          if (!isReadableOffset(thunkEntryOffset)) {
            if (thunkIndex === 0) addWarning("Import thunk RVA does not map to file data.");
            break;
          }
          const dv = new DataView(
            await file
              .slice(thunkEntryOffset, thunkEntryOffset + IMAGE_THUNK_DATA32_SIZE)
              .arrayBuffer()
          );
          if (dv.byteLength < IMAGE_THUNK_DATA32_SIZE) {
            addWarning("Import thunks truncated (32-bit).");
            break;
          }
          const value = dv.getUint32(0, true);
          if (value === 0) break;
          if ((value & IMAGE_ORDINAL_FLAG32) !== 0) {
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

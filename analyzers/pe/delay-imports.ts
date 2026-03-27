"use strict";

import type { PeDataDirectory, RvaToOffset } from "./types.js";
import { createPeRangeReader, type PeRangeReader } from "./range-reader.js";
import { readMappedNullTerminatedAsciiString } from "./mapped-ascii-string.js";

// Microsoft PE format, Delay Import tables: IMAGE_DELAYLOAD_DESCRIPTOR is eight DWORDs.
const IMAGE_DELAYLOAD_DESCRIPTOR_SIZE = 32;
// Microsoft PE format, Delay Import Name Table: PE32 uses 32-bit thunks, PE32+ uses 64-bit thunks.
const IMAGE_THUNK_DATA32_SIZE = Uint32Array.BYTES_PER_ELEMENT;
const IMAGE_THUNK_DATA64_SIZE = BigUint64Array.BYTES_PER_ELEMENT;
const IMAGE_IMPORT_BY_NAME_HINT_SIZE = Uint16Array.BYTES_PER_ELEMENT; // PE format, Hint/Name Table.
const IMAGE_ORDINAL_FLAG32 = 0x80000000; // PE32 import-by-ordinal flag.
const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000n; // PE32+ import-by-ordinal flag.
const IMAGE_ORDINAL_MASK32 = 0xffff; // winnt.h: import-by-ordinal stores the ordinal in the low 16 bits.
const IMAGE_ORDINAL_MASK64 = 0xffffn; // winnt.h: import-by-ordinal stores the ordinal in the low 16 bits.
const IMAGE_DELAY_IMPORT_ORDINAL_RESERVED_MASK32 = 0x7fff0000; // PE32 ordinal thunks reserve bits 30-15.
// Microsoft PE format, Delay Import Name Table: PE32+ name thunks store a 31-bit RVA and reserve bits 62-31.
const IMAGE_DELAY_IMPORT_NAME_MASK64 = 0x7fffffffn; // PE32+ keeps the import-by-name RVA in bits 30-0.
const IMAGE_DELAY_IMPORT_NAME_RESERVED_MASK64 = 0x7fffffff80000000n; // PE32+ reserves bits 62-31.
const IMAGE_DELAY_IMPORT_ORDINAL_RESERVED_MASK64 = 0x7fffffffffff0000n; // PE32+ ordinal thunks reserve bits 62-16.
const readDelayImportName = async (
  reader: PeRangeReader,
  file: File,
  rvaToOff: RvaToOffset,
  nameRva: number,
  warnings: Set<string>
): Promise<string> => {
  const result = await readMappedNullTerminatedAsciiString(
    reader,
    file.size,
    rvaToOff,
    nameRva >>> 0,
    file.size
  );
  if (!result) {
    warnings.add("Delay import name RVA does not map to file data.");
    return "";
  }
  if (!result.terminated) warnings.add("Delay import name string truncated.");
  return result.text;
};
const readDelayImportHintName = async (
  reader: PeRangeReader,
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
  const hintView = new DataView(
    await file.slice(hintNameOff, hintNameOff + IMAGE_IMPORT_BY_NAME_HINT_SIZE).arrayBuffer()
  );
  if (hintView.byteLength < IMAGE_IMPORT_BY_NAME_HINT_SIZE) {
    warnings.add("Delay import hint/name table truncated.");
    return { name: "" };
  }
  const hint = hintView.getUint16(0, true);
  const result = await readMappedNullTerminatedAsciiString(
    reader,
    file.size,
    rvaToOff,
    (hintNameRva + IMAGE_IMPORT_BY_NAME_HINT_SIZE) >>> 0,
    file.size
  );
  if (!result) {
    warnings.add("Delay import hint/name RVA does not map to file data.");
    return { hint, name: "" };
  }
  if (!result.terminated) warnings.add("Delay import name string truncated.");
  return { hint, name: result.text };
};
const readDelayThunkFunctions32 = async (
  reader: PeRangeReader,
  file: File,
  rvaToOff: RvaToOffset,
  intRva: number,
  warnings: Set<string>,
  maxThunkEntries: (entrySize: number) => number
): Promise<Array<{ ordinal?: number; hint?: number; name?: string }>> => {
  const functions: Array<{ ordinal?: number; hint?: number; name?: string }> = [];
  for (let index = 0; index < maxThunkEntries(IMAGE_THUNK_DATA32_SIZE); index += 1) {
    const thunkEntryRva = intRva + index * IMAGE_THUNK_DATA32_SIZE;
    const thunkEntryOff = rvaToOff(thunkEntryRva >>> 0);
    if (thunkEntryOff == null) {
      warnings.add("Delay import thunk RVA does not map to file data.");
      break;
    }
    if (thunkEntryOff < 0 || thunkEntryOff + IMAGE_THUNK_DATA32_SIZE > file.size) {
      warnings.add("Delay import thunk table truncated (32-bit).");
      break;
    }
    const thunkView = new DataView(
      await file.slice(thunkEntryOff, thunkEntryOff + IMAGE_THUNK_DATA32_SIZE).arrayBuffer()
    );
    if (thunkView.byteLength < IMAGE_THUNK_DATA32_SIZE) {
      warnings.add("Delay import thunk table truncated (32-bit).");
      break;
    }
    const value = thunkView.getUint32(0, true);
    if (value === 0) break;
    if ((value & IMAGE_ORDINAL_FLAG32) !== 0) {
      if ((value & IMAGE_DELAY_IMPORT_ORDINAL_RESERVED_MASK32) !== 0) {
        warnings.add("Delay import ordinal thunk has reserved bits set.");
      }
      functions.push({ ordinal: value & IMAGE_ORDINAL_MASK32 });
      continue;
    }
    functions.push(await readDelayImportHintName(reader, file, rvaToOff, value, warnings));
  }
  return functions;
};
const readDelayThunkFunctions64 = async (
  reader: PeRangeReader,
  file: File,
  rvaToOff: RvaToOffset,
  intRva: number,
  warnings: Set<string>,
  maxThunkEntries: (entrySize: number) => number
): Promise<Array<{ ordinal?: number; hint?: number; name?: string }>> => {
  const functions: Array<{ ordinal?: number; hint?: number; name?: string }> = [];
  for (let index = 0; index < maxThunkEntries(IMAGE_THUNK_DATA64_SIZE); index += 1) {
    const thunkEntryRva = intRva + index * IMAGE_THUNK_DATA64_SIZE;
    const thunkEntryOff = rvaToOff(thunkEntryRva >>> 0);
    if (thunkEntryOff == null) {
      warnings.add("Delay import thunk RVA does not map to file data.");
      break;
    }
    if (thunkEntryOff < 0 || thunkEntryOff + IMAGE_THUNK_DATA64_SIZE > file.size) {
      warnings.add("Delay import thunk table truncated (64-bit).");
      break;
    }
    const thunkView = new DataView(
      await file.slice(thunkEntryOff, thunkEntryOff + IMAGE_THUNK_DATA64_SIZE).arrayBuffer()
    );
    if (thunkView.byteLength < IMAGE_THUNK_DATA64_SIZE) {
      warnings.add("Delay import thunk table truncated (64-bit).");
      break;
    }
    const value = thunkView.getBigUint64(0, true);
    if (value === 0n) break;
    if ((value & IMAGE_ORDINAL_FLAG64) !== 0n) {
      if ((value & IMAGE_DELAY_IMPORT_ORDINAL_RESERVED_MASK64) !== 0n) {
        warnings.add("Delay import ordinal thunk has reserved bits set.");
      }
      functions.push({ ordinal: Number(value & IMAGE_ORDINAL_MASK64) });
      continue;
    }
    if ((value & IMAGE_DELAY_IMPORT_NAME_RESERVED_MASK64) !== 0n) {
      warnings.add("Delay import name thunk has reserved bits set.");
    }
    functions.push(
      await readDelayImportHintName(
        reader,
        file,
        rvaToOff,
        Number(value & IMAGE_DELAY_IMPORT_NAME_MASK64),
        warnings
      )
    );
  }
  return functions;
};
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
const parseDelayImportsWithThunkReader = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  readDelayThunkFunctions: (
    reader: PeRangeReader,
    file: File,
    rvaToOff: RvaToOffset,
    intRva: number,
    warnings: Set<string>,
    maxThunkEntries: (entrySize: number) => number
  ) => Promise<Array<{ ordinal?: number; hint?: number; name?: string }>>
): Promise<{ entries: PeDelayImportEntry[]; warning?: string } | null> => {
  const dir = dataDirs.find(d => d.name === "DELAY_IMPORT");
  if (!dir?.rva) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) {
    return { entries: [], warning: "Delay import directory RVA does not map to file data." };
  }
  if (base < 0 || base >= file.size) {
    return { entries: [], warning: "Delay import directory starts outside file data." };
  }
  const availableDirSize = Math.max(0, Math.min(dir.size, Math.max(0, file.size - base)));
  const entries: PeDelayImportEntry[] = [];
  const warnings = new Set<string>();
  const reader = createPeRangeReader(file, 0, file.size);
  if (dir.size < IMAGE_DELAYLOAD_DESCRIPTOR_SIZE || availableDirSize < IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) {
    warnings.add("Delay import directory is smaller than one descriptor; file may be truncated.");
    return { entries, warning: Array.from(warnings).join(" | ") };
  }
  const maxThunkEntries = (entrySize: number): number => Math.floor(file.size / entrySize) + 1;
  const maxDescriptors = Math.ceil(dir.size / IMAGE_DELAYLOAD_DESCRIPTOR_SIZE);
  for (let index = 0; index < maxDescriptors; index += 1) {
    const descriptorRva = (dir.rva + index * IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) >>> 0;
    const descriptorOff = rvaToOff(descriptorRva);
    const remaining = dir.size - index * IMAGE_DELAYLOAD_DESCRIPTOR_SIZE;
    if (descriptorOff == null || descriptorOff < 0) {
      warnings.add("Delay import descriptor RVA does not map to file data.");
      break;
    }
    if (remaining <= 0) break;
    const descriptorSize = Math.min(IMAGE_DELAYLOAD_DESCRIPTOR_SIZE, remaining);
    const dv = new DataView(await file.slice(descriptorOff, descriptorOff + descriptorSize).arrayBuffer());
    if (dv.byteLength < IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) {
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
    if (
      !Attributes &&
      !DllNameRVA &&
      !ModuleHandleRVA &&
      !ImportAddressTableRVA &&
      !ImportNameTableRVA &&
      !BoundImportAddressTableRVA &&
      !UnloadInformationTableRVA &&
      !TimeDateStamp
    ) {
      break;
    }
    if (Attributes !== 0) {
      warnings.add("Delay import descriptor has non-zero Attributes.");
    }
    if (!DllNameRVA) {
      warnings.add("Delay import descriptor is missing the DLL name RVA.");
      continue;
    }
    const nameOff = rvaToOff(DllNameRVA);
    if (DllNameRVA && nameOff == null) warnings.add("Delay import name RVA does not map to file data.");
    const intRva = ImportNameTableRVA >>> 0;
    const intOff = intRva ? rvaToOff(intRva) : null;
    const functions = !intRva
      ? []
      : intOff == null
        ? (warnings.add("Delay Import Name Table RVA does not map to file data."), [])
        : await readDelayThunkFunctions(
            reader,
            file,
            rvaToOff,
            intRva,
            warnings,
            maxThunkEntries
          );
    entries.push({
      name:
        nameOff != null
          ? await readDelayImportName(reader, file, rvaToOff, DllNameRVA, warnings)
          : "",
      Attributes,
      ModuleHandleRVA,
      ImportAddressTableRVA,
      ImportNameTableRVA,
      BoundImportAddressTableRVA,
      UnloadInformationTableRVA,
      TimeDateStamp,
      functions
    });
  }
  const warning = warnings.size ? Array.from(warnings).join(" | ") : undefined;
  return warning ? { entries, warning } : { entries };
};
export const parseDelayImports32 = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<{ entries: PeDelayImportEntry[]; warning?: string } | null> =>
  parseDelayImportsWithThunkReader(file, dataDirs, rvaToOff, readDelayThunkFunctions32);
export const parseDelayImports64 = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): Promise<{ entries: PeDelayImportEntry[]; warning?: string } | null> =>
  parseDelayImportsWithThunkReader(file, dataDirs, rvaToOff, readDelayThunkFunctions64);

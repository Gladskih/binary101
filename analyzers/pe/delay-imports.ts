"use strict";

import type {
  AddCoverageRegion,
  PeDataDirectory,
  RvaToOffset
} from "./types.js";

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
// Microsoft PE format, Delay Import Name Table: PE32+ name thunks store a 31-bit RVA and reserve bits 62-31.
const IMAGE_DELAY_IMPORT_NAME_MASK64 = 0x7fffffffn; // PE32+ keeps the import-by-name RVA in bits 30-0.
const IMAGE_DELAY_IMPORT_NAME_RESERVED_MASK64 = 0x7fffffff80000000n; // PE32+ reserves bits 62-31.
// Parser policy: read NUL-terminated strings incrementally instead of slicing the full tail of a malformed file.
const NULL_TERMINATED_ASCII_READ_CHUNK_SIZE = 64;

const readNullTerminatedAsciiString = async (
  file: File,
  offset: number
): Promise<{ text: string; truncated: boolean } | null> => {
  if (offset < 0 || offset >= file.size) return null;
  let text = "";
  let position = offset;
  while (position < file.size) {
    const chunk = new Uint8Array(
      await file.slice(position, position + NULL_TERMINATED_ASCII_READ_CHUNK_SIZE).arrayBuffer()
    );
    if (chunk.byteLength === 0) break;
    const zeroIndex = chunk.indexOf(0);
    if (zeroIndex !== -1) {
      if (zeroIndex > 0) text += String.fromCharCode(...chunk.slice(0, zeroIndex));
      return { text, truncated: false };
    }
    text += String.fromCharCode(...chunk);
    position += chunk.byteLength;
  }
  return { text, truncated: true };
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
  const result = await readNullTerminatedAsciiString(file, nameOffset);
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
  const hintView = new DataView(
    await file.slice(hintNameOff, hintNameOff + IMAGE_IMPORT_BY_NAME_HINT_SIZE).arrayBuffer()
  );
  if (hintView.byteLength < IMAGE_IMPORT_BY_NAME_HINT_SIZE) {
    warnings.add("Delay import hint/name table truncated.");
    return { name: "" };
  }
  const hint = hintView.getUint16(0, true);
  const result = await readNullTerminatedAsciiString(file, hintNameOff + IMAGE_IMPORT_BY_NAME_HINT_SIZE);
  if (!result) {
    warnings.add("Delay import name string does not map to file data.");
    return { hint, name: "" };
  }
  if (result.truncated) warnings.add("Delay import name string truncated.");
  return { hint, name: result.text };
};

const readDelayThunkFunctions32 = async (
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
    if (thunkEntryOff == null) break;
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
      functions.push({ ordinal: value & IMAGE_ORDINAL_MASK32 });
      continue;
    }
    functions.push(await readDelayImportHintName(file, rvaToOff, value, warnings));
  }
  return functions;
};

const readDelayThunkFunctions64 = async (
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
    if (thunkEntryOff == null) break;
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
      functions.push({ ordinal: Number(value & IMAGE_ORDINAL_MASK64) });
      continue;
    }
    if ((value & IMAGE_DELAY_IMPORT_NAME_RESERVED_MASK64) !== 0n) {
      warnings.add("Delay import name thunk has reserved bits set.");
    }
    functions.push(
      await readDelayImportHintName(
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
  addCoverageRegion: AddCoverageRegion,
  readDelayThunkFunctions: (
    file: File,
    rvaToOff: RvaToOffset,
    intRva: number,
    warnings: Set<string>,
    maxThunkEntries: (entrySize: number) => number
  ) => Promise<Array<{ ordinal?: number; hint?: number; name?: string }>>
): Promise<{ entries: PeDelayImportEntry[]; warning?: string } | null> => {
  const dir = dataDirs.find(d => d.name === "DELAY_IMPORT");
  if (!dir?.rva || dir.size < IMAGE_DELAYLOAD_DESCRIPTOR_SIZE) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  addCoverageRegion("DELAY_IMPORT", base, dir.size);
  const end = base + dir.size;
  const entries: PeDelayImportEntry[] = [];
  const warnings = new Set<string>();
  const maxThunkEntries = (entrySize: number): number => Math.floor(file.size / entrySize) + 1;
  let off = base;
  while (off + IMAGE_DELAYLOAD_DESCRIPTOR_SIZE <= end) {
    const dv = new DataView(await file.slice(off, off + IMAGE_DELAYLOAD_DESCRIPTOR_SIZE).arrayBuffer());
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
    if (!Attributes && !DllNameRVA) break;
    if (Attributes !== 0) warnings.add("Delay import descriptor Attributes must be zero.");
    const nameOff = rvaToOff(DllNameRVA);
    if (DllNameRVA && nameOff == null) warnings.add("Delay import name RVA does not map to file data.");
    const intRva = ImportNameTableRVA >>> 0;
    const intOff = intRva ? rvaToOff(intRva) : null;
    const functions = !intRva
      ? []
      : intOff == null
        ? (warnings.add("Delay Import Name Table RVA does not map to file data."), [])
        : await readDelayThunkFunctions(file, rvaToOff, intRva, warnings, maxThunkEntries);
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
    off += IMAGE_DELAYLOAD_DESCRIPTOR_SIZE;
  }
  const warning = warnings.size ? Array.from(warnings).join(" | ") : undefined;
  return warning ? { entries, warning } : { entries };
};

export const parseDelayImports32 = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<{ entries: PeDelayImportEntry[]; warning?: string } | null> =>
  parseDelayImportsWithThunkReader(
    file,
    dataDirs,
    rvaToOff,
    addCoverageRegion,
    readDelayThunkFunctions32
  );

export const parseDelayImports64 = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): Promise<{ entries: PeDelayImportEntry[]; warning?: string } | null> =>
  parseDelayImportsWithThunkReader(
    file,
    dataDirs,
    rvaToOff,
    addCoverageRegion,
    readDelayThunkFunctions64
  );

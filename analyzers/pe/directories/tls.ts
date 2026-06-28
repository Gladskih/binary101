"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import {
  formatTlsCharacteristicsReservedBits,
  isKnownTlsCharacteristicsAlignment,
  tlsCharacteristicsReservedBits
} from "../tls-characteristics.js";
import type { PeDataDirectory, PeSection, PeTlsDirectory, RvaToOffset } from "../types.js";
import { isReadableMappedTlsVa, isTlsImageVa, toTlsRvaFromVa } from "./tls-addresses.js";

// Microsoft PE format, "The TLS Directory":
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-directory
// PE32 fields end at DWORD Characteristics offset 20; PE32+ ends at offset 36.
const IMAGE_TLS_DIRECTORY32_SIZE = 0x18;
const IMAGE_TLS_DIRECTORY64_SIZE = 0x28;
const TLS_CALLBACK_ENTRY_SIZE32 = Uint32Array.BYTES_PER_ELEMENT;
const TLS_CALLBACK_ENTRY_SIZE64 = BigUint64Array.BYTES_PER_ELEMENT;
const TLS_INDEX_STORAGE_SIZE = Uint32Array.BYTES_PER_ELEMENT;

const createTlsWarningResult = (warnings: string[]): PeTlsDirectory => ({
  StartAddressOfRawData: 0n,
  EndAddressOfRawData: 0n,
  AddressOfIndex: 0n,
  AddressOfCallBacks: 0n,
  SizeOfZeroFill: 0,
  Characteristics: 0,
  CallbackCount: 0,
  CallbackRvas: [],
  warnings,
  parsed: false
});

const addTlsRawDataWarnings = (
  startAddressOfRawData: bigint,
  endAddressOfRawData: bigint,
  imageBase: bigint,
  rvaToOff: RvaToOffset,
  fileSize: number,
  warnings: string[]
): void => {
  if (startAddressOfRawData === 0n && endAddressOfRawData === 0n) return;
  if (startAddressOfRawData === 0n || endAddressOfRawData === 0n || endAddressOfRawData < startAddressOfRawData) {
    warnings.push("TLS raw data VA range is invalid.");
    return;
  }
  const lastRawDataByteVa = endAddressOfRawData > startAddressOfRawData
    ? endAddressOfRawData - 1n
    : endAddressOfRawData;
  if (
    !isReadableMappedTlsVa(startAddressOfRawData, 1, imageBase, rvaToOff, fileSize) ||
    !isReadableMappedTlsVa(lastRawDataByteVa, 1, imageBase, rvaToOff, fileSize)
  ) {
    warnings.push("TLS raw data VA range does not map to file data.");
  }
};

const addTlsFieldWarnings = (
  startAddressOfRawData: bigint,
  endAddressOfRawData: bigint,
  characteristics: number,
  imageBase: bigint,
  rvaToOff: RvaToOffset,
  fileSize: number,
  warnings: string[]
): void => {
  if (tlsCharacteristicsReservedBits(characteristics) !== 0) {
    warnings.push(
      `TLS Characteristics has reserved bits set: ${formatTlsCharacteristicsReservedBits(characteristics)}.`
    );
  }
  if (!isKnownTlsCharacteristicsAlignment(characteristics)) {
    warnings.push("TLS Characteristics uses an unknown alignment value.");
  }
  addTlsRawDataWarnings(startAddressOfRawData, endAddressOfRawData, imageBase, rvaToOff, fileSize, warnings);
};

const addTlsIndexWarning = (
  addressOfIndex: bigint,
  imageBase: bigint,
  sections: PeSection[],
  warnings: string[]
): void => {
  // Microsoft PE format, "The TLS Directory": AddressOfIndex is the VA of an
  // ordinary data location where the loader writes the module TLS index.
  // That slot may be in virtual zero-fill data, so file-backed readability is
  // not required.
  if (!isTlsImageVa(addressOfIndex, TLS_INDEX_STORAGE_SIZE, imageBase, sections)) {
    warnings.push(`TLS AddressOfIndex pointer 0x${addressOfIndex.toString(16)} is not a valid image VA.`);
  }
};

const readTlsCallbackRvas32 = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  tableRva: number,
  imageBase: bigint,
  warnings: string[]
): Promise<{ rvas: number[]; tableBytes: number }> => {
  const callbacks: number[] = [];
  for (let index = 0; ; index += 1) {
    const entryRva = (tableRva + index * TLS_CALLBACK_ENTRY_SIZE32) >>> 0;
    const entryOff = rvaToOff(entryRva);
    if (entryOff == null || entryOff < 0 || entryOff + TLS_CALLBACK_ENTRY_SIZE32 > reader.size) {
      warnings.push("TLS callback table is truncated or unmapped before the null terminator.");
      return { rvas: callbacks, tableBytes: callbacks.length * TLS_CALLBACK_ENTRY_SIZE32 };
    }
    const dv = await reader.read(entryOff, TLS_CALLBACK_ENTRY_SIZE32);
    if (dv.byteLength < TLS_CALLBACK_ENTRY_SIZE32) {
      warnings.push("TLS callback table is truncated before a complete pointer entry.");
      return { rvas: callbacks, tableBytes: callbacks.length * TLS_CALLBACK_ENTRY_SIZE32 };
    }
    const pointer = BigInt(dv.getUint32(0, true));
    if (pointer === 0n) return { rvas: callbacks, tableBytes: (index + 1) * TLS_CALLBACK_ENTRY_SIZE32 };
    const rva = toTlsRvaFromVa(pointer, imageBase);
    if (rva != null) {
      callbacks.push(rva);
      continue;
    }
    warnings.push(`TLS callback pointer 0x${pointer.toString(16)} is not a valid VA.`);
  }
};

const readTlsCallbackRvas64 = async (
  reader: FileRangeReader,
  rvaToOff: RvaToOffset,
  tableRva: number,
  imageBase: bigint,
  warnings: string[]
): Promise<{ rvas: number[]; tableBytes: number }> => {
  const callbacks: number[] = [];
  for (let index = 0; ; index += 1) {
    const entryRva = (tableRva + index * TLS_CALLBACK_ENTRY_SIZE64) >>> 0;
    const entryOff = rvaToOff(entryRva);
    if (entryOff == null || entryOff < 0 || entryOff + TLS_CALLBACK_ENTRY_SIZE64 > reader.size) {
      warnings.push("TLS callback table is truncated or unmapped before the null terminator.");
      return { rvas: callbacks, tableBytes: callbacks.length * TLS_CALLBACK_ENTRY_SIZE64 };
    }
    const dv = await reader.read(entryOff, TLS_CALLBACK_ENTRY_SIZE64);
    if (dv.byteLength < TLS_CALLBACK_ENTRY_SIZE64) {
      warnings.push("TLS callback table is truncated before a complete pointer entry.");
      return { rvas: callbacks, tableBytes: callbacks.length * TLS_CALLBACK_ENTRY_SIZE64 };
    }
    const pointer = dv.getBigUint64(0, true);
    if (pointer === 0n) return { rvas: callbacks, tableBytes: (index + 1) * TLS_CALLBACK_ENTRY_SIZE64 };
    const rva = toTlsRvaFromVa(pointer, imageBase);
    if (rva != null) {
      callbacks.push(rva);
      continue;
    }
    warnings.push(`TLS callback pointer 0x${pointer.toString(16)} is not a valid VA.`);
  }
};

export const parseTlsDirectory32 = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  sections: PeSection[] = []
): Promise<PeTlsDirectory | null> => {
  const dir = dataDirs.find(entry => entry.name === "TLS");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  const warnings: string[] = [];
  if (!dir.rva) {
    warnings.push("TLS directory has a non-zero size but RVA is 0.");
    return createTlsWarningResult(warnings);
  }
  if (dir.size < IMAGE_TLS_DIRECTORY32_SIZE) {
    warnings.push("TLS directory is smaller than the 32-bit TLS header size (0x18 bytes).");
    return createTlsWarningResult(warnings);
  }
  const base = rvaToOff(dir.rva);
  if (base == null) {
    warnings.push("TLS directory RVA could not be mapped to a file offset.");
    return createTlsWarningResult(warnings);
  }
  const readableSize = Math.max(0, Math.min(dir.size, reader.size - base));
  if (readableSize < IMAGE_TLS_DIRECTORY32_SIZE) {
    warnings.push("TLS directory is truncated by end of file.");
    return createTlsWarningResult(warnings);
  }
  const dv = await reader.read(base, IMAGE_TLS_DIRECTORY32_SIZE);
  if (dv.byteLength < IMAGE_TLS_DIRECTORY32_SIZE) {
    warnings.push("TLS directory is truncated before the full 32-bit header could be read.");
    return createTlsWarningResult(warnings);
  }
  const StartAddressOfRawData = BigInt(dv.getUint32(0, true));
  const EndAddressOfRawData = BigInt(dv.getUint32(4, true));
  const AddressOfIndex = BigInt(dv.getUint32(8, true));
  const AddressOfCallBacks = BigInt(dv.getUint32(12, true));
  const SizeOfZeroFill = dv.getUint32(16, true);
  const Characteristics = dv.getUint32(20, true);
  addTlsFieldWarnings(
    StartAddressOfRawData,
    EndAddressOfRawData,
    Characteristics,
    imageBase,
    rvaToOff,
    reader.size,
    warnings
  );
  addTlsIndexWarning(AddressOfIndex, imageBase, sections, warnings);
  const callbackTableRva = toTlsRvaFromVa(AddressOfCallBacks, imageBase);
  const callbackTableOff = callbackTableRva != null ? rvaToOff(callbackTableRva) : null;
  if (AddressOfCallBacks !== 0n && callbackTableRva == null) {
    warnings.push(`TLS AddressOfCallBacks pointer 0x${AddressOfCallBacks.toString(16)} is not a valid VA.`);
  } else if (callbackTableRva != null && callbackTableOff == null) {
    warnings.push(`TLS callback table RVA 0x${callbackTableRva.toString(16)} could not be mapped to a file offset.`);
  }
  const callbackInfo = callbackTableRva != null
    ? await readTlsCallbackRvas32(reader, rvaToOff, callbackTableRva, imageBase, warnings)
    : { rvas: [], tableBytes: 0 };
  return {
    StartAddressOfRawData,
    EndAddressOfRawData,
    AddressOfIndex,
    AddressOfCallBacks,
    SizeOfZeroFill,
    Characteristics,
    CallbackCount: callbackInfo.rvas.length,
    CallbackRvas: callbackInfo.rvas,
    ...(warnings.length ? { warnings } : {}),
    parsed: true
  };
};

export const parseTlsDirectory64 = async (
  reader: FileRangeReader,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  imageBase: bigint,
  sections: PeSection[] = []
): Promise<PeTlsDirectory | null> => {
  const dir = dataDirs.find(entry => entry.name === "TLS");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  const warnings: string[] = [];
  if (!dir.rva) {
    warnings.push("TLS directory has a non-zero size but RVA is 0.");
    return createTlsWarningResult(warnings);
  }
  if (dir.size < IMAGE_TLS_DIRECTORY64_SIZE) {
    warnings.push("TLS directory is smaller than the 64-bit TLS header size (0x28 bytes).");
    return createTlsWarningResult(warnings);
  }
  const base = rvaToOff(dir.rva);
  if (base == null) {
    warnings.push("TLS directory RVA could not be mapped to a file offset.");
    return createTlsWarningResult(warnings);
  }
  const readableSize = Math.max(0, Math.min(dir.size, reader.size - base));
  if (readableSize < IMAGE_TLS_DIRECTORY64_SIZE) {
    warnings.push("TLS directory is truncated by end of file.");
    return createTlsWarningResult(warnings);
  }
  const dv = await reader.read(base, IMAGE_TLS_DIRECTORY64_SIZE);
  if (dv.byteLength < IMAGE_TLS_DIRECTORY64_SIZE) {
    warnings.push("TLS directory is truncated before the full 64-bit header could be read.");
    return createTlsWarningResult(warnings);
  }
  const StartAddressOfRawDataVa = dv.getBigUint64(0, true);
  const EndAddressOfRawDataVa = dv.getBigUint64(8, true);
  const AddressOfIndexVa = dv.getBigUint64(16, true);
  const AddressOfCallBacksVa = dv.getBigUint64(24, true);
  const SizeOfZeroFill = dv.getUint32(32, true);
  const Characteristics = dv.getUint32(36, true);
  addTlsFieldWarnings(
    StartAddressOfRawDataVa,
    EndAddressOfRawDataVa,
    Characteristics,
    imageBase,
    rvaToOff,
    reader.size,
    warnings
  );
  addTlsIndexWarning(AddressOfIndexVa, imageBase, sections, warnings);
  const callbackTableRva = toTlsRvaFromVa(AddressOfCallBacksVa, imageBase);
  const callbackTableOff = callbackTableRva != null ? rvaToOff(callbackTableRva) : null;
  if (AddressOfCallBacksVa !== 0n && callbackTableRva == null) {
    warnings.push(`TLS AddressOfCallBacks pointer 0x${AddressOfCallBacksVa.toString(16)} is not a valid VA.`);
  } else if (callbackTableRva != null && callbackTableOff == null) {
    warnings.push(`TLS callback table RVA 0x${callbackTableRva.toString(16)} could not be mapped to a file offset.`);
  }
  const callbackInfo = callbackTableRva != null
    ? await readTlsCallbackRvas64(reader, rvaToOff, callbackTableRva, imageBase, warnings)
    : { rvas: [], tableBytes: 0 };
  return {
    StartAddressOfRawData: StartAddressOfRawDataVa,
    EndAddressOfRawData: EndAddressOfRawDataVa,
    AddressOfIndex: AddressOfIndexVa,
    AddressOfCallBacks: AddressOfCallBacksVa,
    SizeOfZeroFill,
    Characteristics,
    CallbackCount: callbackInfo.rvas.length,
    CallbackRvas: callbackInfo.rvas,
    ...(warnings.length ? { warnings } : {}),
    parsed: true
  };
};

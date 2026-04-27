"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeDataDirectory, PeTlsDirectory, RvaToOffset } from "../types.js";

const MAX_RVA_BIGINT = 0xffff_ffffn;
// Microsoft PE format, "The TLS Directory": PE32 fields end at Characteristics
// offset 20 with size 4.
const IMAGE_TLS_DIRECTORY32_SIZE = 0x18;
// Microsoft PE format, "The TLS Directory": PE32+ fields end at Characteristics
// offset 36 with size 4.
const IMAGE_TLS_DIRECTORY64_SIZE = 0x28;
const TLS_CALLBACK_ENTRY_SIZE32 = Uint32Array.BYTES_PER_ELEMENT;
const TLS_CALLBACK_ENTRY_SIZE64 = BigUint64Array.BYTES_PER_ELEMENT;

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

const toRvaFromVa = (virtualAddress: bigint, imageBase: bigint): number | null => {
  if (virtualAddress === 0n) return null;
  if (virtualAddress < imageBase) return null;
  const delta = virtualAddress - imageBase;
  if (delta > MAX_RVA_BIGINT) return null;
  return Number(delta);
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
    const rva = toRvaFromVa(pointer, imageBase);
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
    const rva = toRvaFromVa(pointer, imageBase);
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
  imageBase: bigint
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
  const callbackTableRva = toRvaFromVa(AddressOfCallBacks, imageBase);
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
  imageBase: bigint
): Promise<PeTlsDirectory | null> => {
  const dir = dataDirs.find(entry => entry.name === "TLS");
  if (!dir || (dir.rva === 0 && dir.size === 0)) return null;
  const warnings: string[] = [];
  if (!dir.rva) {
    warnings.push("TLS directory has a non-zero size but RVA is 0.");
    return createTlsWarningResult(warnings);
  }
  if (dir.size < IMAGE_TLS_DIRECTORY64_SIZE) {
    warnings.push("TLS directory is smaller than the 64-bit TLS header size (0x30 bytes).");
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

  const callbackTableRva = toRvaFromVa(AddressOfCallBacksVa, imageBase);
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

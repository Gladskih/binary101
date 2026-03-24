"use strict";

import type { AddCoverageRegion, PeDataDirectory, PeTlsDirectory, RvaToOffset } from "./types.js";

const MAX_RVA_BIGINT = 0xffff_ffffn;
const IMAGE_TLS_DIRECTORY32_SIZE = 0x18; // Microsoft PE format: IMAGE_TLS_DIRECTORY32 is six DWORDs.
const IMAGE_TLS_DIRECTORY64_SIZE = 0x30; // Microsoft PE format: IMAGE_TLS_DIRECTORY64 is four ULONGLONGs plus two DWORDs.
const TLS_CALLBACK_ENTRY_SIZE32 = Uint32Array.BYTES_PER_ELEMENT;
const TLS_CALLBACK_ENTRY_SIZE64 = BigUint64Array.BYTES_PER_ELEMENT;

const createTlsWarningResult = (warnings: string[]): PeTlsDirectory => ({
  StartAddressOfRawData: 0,
  EndAddressOfRawData: 0,
  AddressOfIndex: 0,
  AddressOfCallBacks: 0,
  SizeOfZeroFill: 0,
  Characteristics: 0,
  CallbackCount: 0,
  CallbackRvas: [],
  warnings,
  parsed: false
});

const toRvaFromVa32 = (virtualAddress: number, imageBase: number): number | null => {
  if (!Number.isSafeInteger(virtualAddress) || virtualAddress <= 0) return null;
  if (!Number.isSafeInteger(imageBase) || imageBase < 0) return null;
  if (virtualAddress < imageBase) return null;
  const delta = virtualAddress - imageBase;
  if (!Number.isSafeInteger(delta) || delta < 0 || delta > 0xffff_ffff) return null;
  return delta >>> 0;
};

const toRvaFromVa64 = (virtualAddress: bigint, imageBase: bigint): number | null => {
  if (virtualAddress === 0n) return null;
  if (virtualAddress < imageBase) return null;
  const delta = virtualAddress - imageBase;
  if (delta > MAX_RVA_BIGINT) return null;
  return Number(delta);
};

const readTlsCallbackRvas32 = async (
  file: File,
  rvaToOff: RvaToOffset,
  tableRva: number,
  imageBase: number,
  warnings: string[]
): Promise<{ rvas: number[]; tableBytes: number }> => {
  const callbacks: number[] = [];
  for (let index = 0; ; index += 1) {
    const entryRva = (tableRva + index * TLS_CALLBACK_ENTRY_SIZE32) >>> 0;
    const entryOff = rvaToOff(entryRva);
    if (entryOff == null || entryOff < 0 || entryOff + TLS_CALLBACK_ENTRY_SIZE32 > file.size) {
      warnings.push("TLS callback table is truncated or unmapped before the null terminator.");
      return { rvas: callbacks, tableBytes: callbacks.length * TLS_CALLBACK_ENTRY_SIZE32 };
    }
    const dv = new DataView(
      await file.slice(entryOff, entryOff + TLS_CALLBACK_ENTRY_SIZE32).arrayBuffer()
    );
    if (dv.byteLength < TLS_CALLBACK_ENTRY_SIZE32) {
      warnings.push("TLS callback table is truncated before a complete pointer entry.");
      return { rvas: callbacks, tableBytes: callbacks.length * TLS_CALLBACK_ENTRY_SIZE32 };
    }
    const pointer = dv.getUint32(0, true);
    if (pointer === 0) return { rvas: callbacks, tableBytes: (index + 1) * TLS_CALLBACK_ENTRY_SIZE32 };
    const rva = toRvaFromVa32(pointer, imageBase);
    if (rva != null) {
      callbacks.push(rva);
      continue;
    }
    warnings.push(`TLS callback pointer 0x${pointer.toString(16)} is not a valid VA.`);
  }
};

const readTlsCallbackRvas64 = async (
  file: File,
  rvaToOff: RvaToOffset,
  tableRva: number,
  imageBase: bigint,
  warnings: string[]
): Promise<{ rvas: number[]; tableBytes: number }> => {
  const callbacks: number[] = [];
  for (let index = 0; ; index += 1) {
    const entryRva = (tableRva + index * TLS_CALLBACK_ENTRY_SIZE64) >>> 0;
    const entryOff = rvaToOff(entryRva);
    if (entryOff == null || entryOff < 0 || entryOff + TLS_CALLBACK_ENTRY_SIZE64 > file.size) {
      warnings.push("TLS callback table is truncated or unmapped before the null terminator.");
      return { rvas: callbacks, tableBytes: callbacks.length * TLS_CALLBACK_ENTRY_SIZE64 };
    }
    const dv = new DataView(
      await file.slice(entryOff, entryOff + TLS_CALLBACK_ENTRY_SIZE64).arrayBuffer()
    );
    if (dv.byteLength < TLS_CALLBACK_ENTRY_SIZE64) {
      warnings.push("TLS callback table is truncated before a complete pointer entry.");
      return { rvas: callbacks, tableBytes: callbacks.length * TLS_CALLBACK_ENTRY_SIZE64 };
    }
    const pointer = dv.getBigUint64(0, true);
    if (pointer === 0n) return { rvas: callbacks, tableBytes: (index + 1) * TLS_CALLBACK_ENTRY_SIZE64 };
    const rva = toRvaFromVa64(pointer, imageBase);
    if (rva != null) {
      callbacks.push(rva);
      continue;
    }
    warnings.push(`TLS callback pointer 0x${pointer.toString(16)} is not a valid VA.`);
  }
};

export const parseTlsDirectory32 = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion,
  imageBase: number
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
  const readableSize = Math.max(0, Math.min(dir.size, file.size - base));
  addCoverageRegion("TLS directory", base, readableSize);
  if (readableSize < IMAGE_TLS_DIRECTORY32_SIZE) {
    warnings.push("TLS directory is truncated by end of file.");
    return createTlsWarningResult(warnings);
  }
  const buf = await file.slice(base, base + IMAGE_TLS_DIRECTORY32_SIZE).arrayBuffer();
  if (buf.byteLength < IMAGE_TLS_DIRECTORY32_SIZE) {
    warnings.push("TLS directory is truncated before the full 32-bit header could be read.");
    return createTlsWarningResult(warnings);
  }
  const dv = new DataView(buf);
  const StartAddressOfRawData = dv.getUint32(0, true);
  const EndAddressOfRawData = dv.getUint32(4, true);
  const AddressOfIndex = dv.getUint32(8, true);
  const AddressOfCallBacks = dv.getUint32(12, true);
  const SizeOfZeroFill = dv.getUint32(16, true);
  const Characteristics = dv.getUint32(20, true);
  const callbackTableRva = toRvaFromVa32(AddressOfCallBacks, imageBase);
  const callbackTableOff = callbackTableRva != null ? rvaToOff(callbackTableRva) : null;
  if (AddressOfCallBacks !== 0 && callbackTableRva == null) {
    warnings.push(`TLS AddressOfCallBacks pointer 0x${AddressOfCallBacks.toString(16)} is not a valid VA.`);
  } else if (callbackTableRva != null && callbackTableOff == null) {
    warnings.push(`TLS callback table RVA 0x${callbackTableRva.toString(16)} could not be mapped to a file offset.`);
  }
  const callbackInfo = callbackTableRva != null
    ? await readTlsCallbackRvas32(file, rvaToOff, callbackTableRva, imageBase, warnings)
    : { rvas: [], tableBytes: 0 };
  if (
    callbackTableOff != null &&
    callbackTableOff >= 0 &&
    callbackTableOff < file.size &&
    callbackInfo.tableBytes > 0
  ) {
    addCoverageRegion("TLS callbacks", callbackTableOff, callbackInfo.tableBytes);
  }
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
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion,
  imageBase: number
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
  const readableSize = Math.max(0, Math.min(dir.size, file.size - base));
  addCoverageRegion("TLS directory", base, readableSize);
  if (readableSize < IMAGE_TLS_DIRECTORY64_SIZE) {
    warnings.push("TLS directory is truncated by end of file.");
    return createTlsWarningResult(warnings);
  }
  const buf = await file.slice(base, base + IMAGE_TLS_DIRECTORY64_SIZE).arrayBuffer();
  if (buf.byteLength < IMAGE_TLS_DIRECTORY64_SIZE) {
    warnings.push("TLS directory is truncated before the full 64-bit header could be read.");
    return createTlsWarningResult(warnings);
  }
  const dv = new DataView(buf);
  const StartAddressOfRawDataVa = dv.getBigUint64(0, true);
  const EndAddressOfRawDataVa = dv.getBigUint64(8, true);
  const AddressOfIndexVa = dv.getBigUint64(16, true);
  const AddressOfCallBacksVa = dv.getBigUint64(24, true);
  const SizeOfZeroFill = dv.getUint32(32, true);
  const Characteristics = dv.getUint32(36, true);

  const imageBaseBigint = Number.isSafeInteger(imageBase) && imageBase >= 0 ? BigInt(imageBase) : 0n;
  const callbackTableRva = toRvaFromVa64(AddressOfCallBacksVa, imageBaseBigint);
  const callbackTableOff = callbackTableRva != null ? rvaToOff(callbackTableRva) : null;
  if (AddressOfCallBacksVa !== 0n && callbackTableRva == null) {
    warnings.push(`TLS AddressOfCallBacks pointer 0x${AddressOfCallBacksVa.toString(16)} is not a valid VA.`);
  } else if (callbackTableRva != null && callbackTableOff == null) {
    warnings.push(`TLS callback table RVA 0x${callbackTableRva.toString(16)} could not be mapped to a file offset.`);
  }
  const callbackInfo = callbackTableRva != null
    ? await readTlsCallbackRvas64(file, rvaToOff, callbackTableRva, imageBaseBigint, warnings)
    : { rvas: [], tableBytes: 0 };
  if (
    callbackTableOff != null &&
    callbackTableOff >= 0 &&
    callbackTableOff < file.size &&
    callbackInfo.tableBytes > 0
  ) {
    addCoverageRegion("TLS callbacks", callbackTableOff, callbackInfo.tableBytes);
  }
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

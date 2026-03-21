"use strict";

import type { AddCoverageRegion, PeDataDirectory, PeTlsDirectory, RvaToOffset } from "./types.js";

const MAX_RVA_BIGINT = 0xffff_ffffn;
const IMAGE_TLS_DIRECTORY32_SIZE = 0x18; // Microsoft PE format: IMAGE_TLS_DIRECTORY32 is six DWORDs.
const IMAGE_TLS_DIRECTORY64_SIZE = 0x30; // Microsoft PE format: IMAGE_TLS_DIRECTORY64 is four ULONGLONGs plus two DWORDs.
const TLS_CALLBACK_ENTRY_SIZE32 = Uint32Array.BYTES_PER_ELEMENT;
const TLS_CALLBACK_ENTRY_SIZE64 = BigUint64Array.BYTES_PER_ELEMENT;

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
  imageBase: number
): Promise<{ rvas: number[]; tableBytes: number }> => {
  const callbacks: number[] = [];
  for (let index = 0; ; index += 1) {
    const entryRva = (tableRva + index * TLS_CALLBACK_ENTRY_SIZE32) >>> 0;
    const entryOff = rvaToOff(entryRva);
    if (entryOff == null || entryOff < 0 || entryOff + TLS_CALLBACK_ENTRY_SIZE32 > file.size) {
      return { rvas: callbacks, tableBytes: callbacks.length * TLS_CALLBACK_ENTRY_SIZE32 };
    }
    const dv = new DataView(
      await file.slice(entryOff, entryOff + TLS_CALLBACK_ENTRY_SIZE32).arrayBuffer()
    );
    if (dv.byteLength < TLS_CALLBACK_ENTRY_SIZE32) {
      return { rvas: callbacks, tableBytes: callbacks.length * TLS_CALLBACK_ENTRY_SIZE32 };
    }
    const pointer = dv.getUint32(0, true);
    if (pointer === 0) return { rvas: callbacks, tableBytes: (index + 1) * TLS_CALLBACK_ENTRY_SIZE32 };
    const rva = toRvaFromVa32(pointer, imageBase);
    if (rva != null) callbacks.push(rva);
  }
};

const readTlsCallbackRvas64 = async (
  file: File,
  rvaToOff: RvaToOffset,
  tableRva: number,
  imageBase: bigint
): Promise<{ rvas: number[]; tableBytes: number }> => {
  const callbacks: number[] = [];
  for (let index = 0; ; index += 1) {
    const entryRva = (tableRva + index * TLS_CALLBACK_ENTRY_SIZE64) >>> 0;
    const entryOff = rvaToOff(entryRva);
    if (entryOff == null || entryOff < 0 || entryOff + TLS_CALLBACK_ENTRY_SIZE64 > file.size) {
      return { rvas: callbacks, tableBytes: callbacks.length * TLS_CALLBACK_ENTRY_SIZE64 };
    }
    const dv = new DataView(
      await file.slice(entryOff, entryOff + TLS_CALLBACK_ENTRY_SIZE64).arrayBuffer()
    );
    if (dv.byteLength < TLS_CALLBACK_ENTRY_SIZE64) {
      return { rvas: callbacks, tableBytes: callbacks.length * TLS_CALLBACK_ENTRY_SIZE64 };
    }
    const pointer = dv.getBigUint64(0, true);
    if (pointer === 0n) return { rvas: callbacks, tableBytes: (index + 1) * TLS_CALLBACK_ENTRY_SIZE64 };
    const rva = toRvaFromVa64(pointer, imageBase);
    if (rva != null) callbacks.push(rva);
  }
};

const findTlsDirectoryBase = (
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset
): { base: number; dir: PeDataDirectory } | null => {
  const dir = dataDirs.find(d => d.name === "TLS");
  if (!dir?.rva) return null;
  const base = rvaToOff(dir.rva);
  return base == null ? null : { base, dir };
};

export const parseTlsDirectory32 = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion,
  imageBase: number
): Promise<PeTlsDirectory | null> => {
  const tls = findTlsDirectoryBase(dataDirs, rvaToOff);
  if (!tls || tls.dir.size < IMAGE_TLS_DIRECTORY32_SIZE) return null;
  addCoverageRegion("TLS directory", tls.base, Math.min(tls.dir.size || IMAGE_TLS_DIRECTORY32_SIZE, IMAGE_TLS_DIRECTORY32_SIZE));
  const buf = await file.slice(tls.base, tls.base + IMAGE_TLS_DIRECTORY32_SIZE).arrayBuffer();
  if (buf.byteLength < IMAGE_TLS_DIRECTORY32_SIZE) return null;
  const dv = new DataView(buf);
  const StartAddressOfRawData = dv.getUint32(0, true);
  const EndAddressOfRawData = dv.getUint32(4, true);
  const AddressOfIndex = dv.getUint32(8, true);
  const AddressOfCallBacks = dv.getUint32(12, true);
  const SizeOfZeroFill = dv.getUint32(16, true);
  const Characteristics = dv.getUint32(20, true);
  const callbackTableRva = toRvaFromVa32(AddressOfCallBacks, imageBase);
  const callbackTableOff = callbackTableRva != null ? rvaToOff(callbackTableRva) : null;
  const callbackInfo = callbackTableRva != null
    ? await readTlsCallbackRvas32(file, rvaToOff, callbackTableRva, imageBase)
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
    CallbackRvas: callbackInfo.rvas
  };
};

export const parseTlsDirectory64 = async (
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion,
  imageBase: number
): Promise<PeTlsDirectory | null> => {
  const tls = findTlsDirectoryBase(dataDirs, rvaToOff);
  if (!tls || tls.dir.size < IMAGE_TLS_DIRECTORY64_SIZE) return null;
  addCoverageRegion("TLS directory", tls.base, Math.min(tls.dir.size || IMAGE_TLS_DIRECTORY64_SIZE, IMAGE_TLS_DIRECTORY64_SIZE));
  const buf = await file.slice(tls.base, tls.base + IMAGE_TLS_DIRECTORY64_SIZE).arrayBuffer();
  if (buf.byteLength < IMAGE_TLS_DIRECTORY64_SIZE) return null;
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
  const callbackInfo = callbackTableRva != null
    ? await readTlsCallbackRvas64(file, rvaToOff, callbackTableRva, imageBaseBigint)
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
    StartAddressOfRawData: Number(StartAddressOfRawDataVa),
    EndAddressOfRawData: Number(EndAddressOfRawDataVa),
    AddressOfIndex: Number(AddressOfIndexVa),
    AddressOfCallBacks: Number(AddressOfCallBacksVa),
    SizeOfZeroFill,
    Characteristics,
    CallbackCount: callbackInfo.rvas.length,
    CallbackRvas: callbackInfo.rvas
  };
};

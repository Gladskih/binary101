"use strict";

import type { AddCoverageRegion, PeDataDirectory, PeTlsDirectory, RvaToOffset } from "./types.js";

const MAX_RVA_BIGINT = 0xffff_ffffn;
const TLS_CALLBACK_CHUNK_SIZE_32 = 4096;
const TLS_CALLBACK_CHUNK_SIZE_64 = 8192;

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

const readTlsCallbackRvas = async (
  file: File,
  offset: number,
  entrySize: number,
  readPointer: (dv: DataView, entryOffset: number) => number | bigint,
  toRva: (pointer: number | bigint) => number | null
): Promise<number[]> => {
  const start = offset >>> 0;
  const callbacks: number[] = [];
  const chunkSize = entrySize === 8 ? TLS_CALLBACK_CHUNK_SIZE_64 : TLS_CALLBACK_CHUNK_SIZE_32;

  for (let chunkStart = start; chunkStart < file.size; chunkStart += chunkSize) {
    const chunkEnd = Math.min(file.size, chunkStart + chunkSize);
    if (chunkEnd <= chunkStart) break;
    const dv = new DataView(await file.slice(chunkStart, chunkEnd).arrayBuffer());
    const available = Math.floor(dv.byteLength / entrySize);
    for (let index = 0; index < available; index += 1) {
      const pointer = readPointer(dv, index * entrySize);
      if (pointer === 0 || pointer === 0n) return callbacks;
      const rva = toRva(pointer);
      if (rva != null) callbacks.push(rva);
    }
  }
  return callbacks;
};

export async function parseTlsDirectory(
  file: File,
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion,
  isPlus: boolean,
  imageBase: number
): Promise<PeTlsDirectory | null> {
  const dir = dataDirs.find(d => d.name === "TLS");
  if (!dir?.rva) return null;
  const base = rvaToOff(dir.rva);
  if (base == null) return null;
  const size = dir.size || (isPlus ? 0x30 : 0x18);
  addCoverageRegion("TLS directory", base, Math.min(size, isPlus ? 0x30 : 0x18));
  if (isPlus) {
    const buf = await file.slice(base, base + 0x30).arrayBuffer();
    if (buf.byteLength < 0x30) return null;
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
    const CallbackRvas = callbackTableOff != null
      ? await readTlsCallbackRvas(
        file,
        callbackTableOff,
        8,
        (dv, entryOffset) => dv.getBigUint64(entryOffset, true),
        pointer => (typeof pointer === "bigint" ? toRvaFromVa64(pointer, imageBaseBigint) : null)
      )
      : [];
    if (callbackTableOff != null && callbackTableOff >= 0 && callbackTableOff < file.size) {
      addCoverageRegion("TLS callbacks", callbackTableOff, Math.max(0, file.size - callbackTableOff));
    }
    return {
      StartAddressOfRawData: Number(StartAddressOfRawDataVa),
      EndAddressOfRawData: Number(EndAddressOfRawDataVa),
      AddressOfIndex: Number(AddressOfIndexVa),
      AddressOfCallBacks: Number(AddressOfCallBacksVa),
      SizeOfZeroFill,
      Characteristics,
      CallbackCount: CallbackRvas.length,
      CallbackRvas
    };
  }
  const buf = await file.slice(base, base + 0x18).arrayBuffer();
  if (buf.byteLength < 0x18) return null;
  const dv = new DataView(buf);
  const StartAddressOfRawData = dv.getUint32(0, true);
  const EndAddressOfRawData = dv.getUint32(4, true);
  const AddressOfIndex = dv.getUint32(8, true);
  const AddressOfCallBacks = dv.getUint32(12, true);
  const SizeOfZeroFill = dv.getUint32(16, true);
  const Characteristics = dv.getUint32(20, true);
  const callbackTableRva = toRvaFromVa32(AddressOfCallBacks, imageBase);
  const callbackTableOff = callbackTableRva != null ? rvaToOff(callbackTableRva) : null;
  const CallbackRvas = callbackTableOff != null
    ? await readTlsCallbackRvas(
      file,
      callbackTableOff,
      4,
      (dv, entryOffset) => dv.getUint32(entryOffset, true),
      pointer => (typeof pointer === "number" ? toRvaFromVa32(pointer, imageBase) : null)
    )
    : [];
  if (callbackTableOff != null && callbackTableOff >= 0 && callbackTableOff < file.size) {
    addCoverageRegion("TLS callbacks", callbackTableOff, Math.max(0, file.size - callbackTableOff));
  }
  return {
    StartAddressOfRawData,
    EndAddressOfRawData,
    AddressOfIndex,
    AddressOfCallBacks,
    SizeOfZeroFill,
    Characteristics,
    CallbackCount: CallbackRvas.length,
    CallbackRvas
  };
}

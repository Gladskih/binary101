"use strict";

import type { AddCoverageRegion, PeDataDirectory, PeTlsDirectory, RvaToOffset } from "./types.js";

const MAX_RVA_BIGINT = 0xffff_ffffn;

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
  rvaToOff: RvaToOffset,
  tableRva: number,
  entrySize: number,
  readPointer: (dv: DataView, entryOffset: number) => number | bigint,
  toRva: (pointer: number | bigint) => number | null
): Promise<number[]> => {
  const callbacks: number[] = [];
  for (let index = 0; ; index += 1) {
    const entryRva = (tableRva + index * entrySize) >>> 0;
    const entryOff = rvaToOff(entryRva);
    if (entryOff == null || entryOff < 0 || entryOff + entrySize > file.size) break;
    const dv = new DataView(await file.slice(entryOff, entryOff + entrySize).arrayBuffer());
    if (dv.byteLength < entrySize) break;
    const pointer = readPointer(dv, 0);
    if (pointer === 0 || pointer === 0n) return callbacks;
    const rva = toRva(pointer);
    if (rva != null) callbacks.push(rva);
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
  const minSize = isPlus ? 0x30 : 0x18;
  if (dir.size < minSize) return null;
  const size = dir.size || minSize;
  addCoverageRegion("TLS directory", base, Math.min(size, minSize));
  if (isPlus) {
    const buf = await file.slice(base, base + minSize).arrayBuffer();
    if (buf.byteLength < minSize) return null;
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
    const CallbackRvas = callbackTableRva != null
      ? await readTlsCallbackRvas(
        file,
        rvaToOff,
        callbackTableRva,
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
  const buf = await file.slice(base, base + minSize).arrayBuffer();
  if (buf.byteLength < minSize) return null;
  const dv = new DataView(buf);
  const StartAddressOfRawData = dv.getUint32(0, true);
  const EndAddressOfRawData = dv.getUint32(4, true);
  const AddressOfIndex = dv.getUint32(8, true);
  const AddressOfCallBacks = dv.getUint32(12, true);
  const SizeOfZeroFill = dv.getUint32(16, true);
  const Characteristics = dv.getUint32(20, true);
  const callbackTableRva = toRvaFromVa32(AddressOfCallBacks, imageBase);
  const callbackTableOff = callbackTableRva != null ? rvaToOff(callbackTableRva) : null;
  const CallbackRvas = callbackTableRva != null
    ? await readTlsCallbackRvas(
      file,
      rvaToOff,
      callbackTableRva,
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

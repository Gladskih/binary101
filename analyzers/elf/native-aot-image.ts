"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { NativeAotVirtualImage } from "../native-aot/virtual-image-types.js";
import type { ElfProgramHeader } from "./types.js";

const PT_LOAD = 1;

export interface ElfNativeAotImage extends NativeAotVirtualImage {
  imageBase: bigint;
  toImageAddress: (virtualAddress: bigint) => number | null;
}

export const getElfImageBase = (programHeaders: ElfProgramHeader[]): bigint | null => {
  const loadBases = programHeaders
    .filter(header => header.type === PT_LOAD && header.vaddr >= header.offset)
    .map(header => header.vaddr - header.offset);
  return loadBases.length
    ? loadBases.reduce((lowest, value) => value < lowest ? value : lowest)
    : null;
};

const findLoadRange = (
  programHeaders: ElfProgramHeader[],
  virtualAddress: bigint,
  size: number,
  rangeKind: "file" | "memory"
): ElfProgramHeader | null => programHeaders.find(header => {
  if (header.type !== PT_LOAD || size <= 0) return false;
  const span = rangeKind === "file" ? header.filesz : header.memsz;
  const delta = virtualAddress - header.vaddr;
  return delta >= 0n && BigInt(size) <= span - delta;
}) ?? null;

export const createElfNativeAotImage = (
  reader: FileRangeReader,
  programHeaders: ElfProgramHeader[],
  relocationTargets: ReadonlyMap<number, number>
): ElfNativeAotImage | null => {
  const imageBase = getElfImageBase(programHeaders);
  if (imageBase == null) return null;
  const toImageAddress = (virtualAddress: bigint): number | null => {
    const relative = virtualAddress - imageBase;
    const value = Number(relative);
    return relative >= 0n && Number.isSafeInteger(value) ? value : null;
  };
  const toVirtualAddress = (address: number): bigint | null =>
    Number.isSafeInteger(address) && address >= 0 ? imageBase + BigInt(address) : null;
  const isMappedRange = (address: number, size: number): boolean => {
    const virtualAddress = toVirtualAddress(address);
    return virtualAddress != null && Number.isSafeInteger(size) &&
      findLoadRange(programHeaders, virtualAddress, size, "memory") != null;
  };
  const isDataRange = (address: number, size: number, alignment: number): boolean => {
    const virtualAddress = toVirtualAddress(address);
    if (virtualAddress == null || !Number.isSafeInteger(size) ||
      !Number.isSafeInteger(alignment) || alignment <= 0 || virtualAddress % BigInt(alignment)) {
      return false;
    }
    const segment = findLoadRange(programHeaders, virtualAddress, size, "file");
    if (!segment) return false;
    const offset = segment.offset + virtualAddress - segment.vaddr;
    return offset + BigInt(size) <= BigInt(reader.size);
  };
  const readData = async (
    address: number,
    size: number,
    alignment: number
  ): Promise<DataView | null> => {
    if (!isDataRange(address, size, alignment)) return null;
    const virtualAddress = imageBase + BigInt(address);
    const segment = findLoadRange(programHeaders, virtualAddress, size, "file");
    if (!segment) return null;
    const offset = Number(segment.offset + virtualAddress - segment.vaddr);
    const view = await reader.read(offset, size);
    return view.byteLength === size ? view : null;
  };
  const readPointerValue = async (address: number): Promise<bigint | null> => {
    const view = await readData(address, 8, 8);
    if (!view) return null;
    return view.getBigUint64(0, true);
  };
  const readPointerTarget = async (address: number): Promise<number | null> => {
    const relocated = relocationTargets.get(address);
    if (relocated != null) return relocated;
    const value = await readPointerValue(address);
    return value == null ? null : toImageAddress(value);
  };
  return {
    pointerSize: 8,
    imageBase,
    toImageAddress,
    isDataRange,
    isMappedRange,
    readData,
    readPointerValue,
    readPointerTarget
  };
};

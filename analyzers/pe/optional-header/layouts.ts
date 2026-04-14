"use strict";

export type ParsedOptionalHeaderTail = {
  nextPosition: number;
  BaseOfData?: number;
  ImageBase: bigint;
  SectionAlignment: number;
  FileAlignment: number;
  OSVersionMajor: number;
  OSVersionMinor: number;
  ImageVersionMajor: number;
  ImageVersionMinor: number;
  SubsystemVersionMajor: number;
  SubsystemVersionMinor: number;
  Win32VersionValue: number;
  SizeOfImage: number;
  SizeOfHeaders: number;
  CheckSum: number;
  Subsystem: number;
  DllCharacteristics: number;
  SizeOfStackReserve: bigint;
  SizeOfStackCommit: bigint;
  SizeOfHeapReserve: bigint;
  SizeOfHeapCommit: bigint;
  LoaderFlags: number;
  NumberOfRvaAndSizes: number;
};

export type ParsedRomOptionalHeaderTail = {
  nextPosition: number;
  BaseOfData: number;
  BaseOfBss: number;
  GprMask: number;
  CprMask: [number, number, number, number];
  GpValue: number;
};

const readVersionPair = (
  optionalHeaderView: DataView,
  position: number
): [number, number] =>
  position + 4 <= optionalHeaderView.byteLength
    ? [
        optionalHeaderView.getUint16(position, true),
        optionalHeaderView.getUint16(position + 2, true)
      ]
    : [0, 0];

export const parseOptionalHeaderTail32 = (
  optionalHeaderView: DataView,
  start: number
): ParsedOptionalHeaderTail => {
  let position = start;
  const readAt = <T>(length: number, fn: () => T, fallback: T): T =>
    position + length <= optionalHeaderView.byteLength ? fn() : fallback;
  const BaseOfData = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const ImageBase = readAt(4, () => BigInt(optionalHeaderView.getUint32(position, true)), 0n);
  position += 4;
  const SectionAlignment = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const FileAlignment = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const [OSVersionMajor, OSVersionMinor] = readVersionPair(optionalHeaderView, position);
  position += 4;
  const [ImageVersionMajor, ImageVersionMinor] = readVersionPair(optionalHeaderView, position);
  position += 4;
  const [SubsystemVersionMajor, SubsystemVersionMinor] = readVersionPair(optionalHeaderView, position);
  position += 4;
  const Win32VersionValue = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const SizeOfImage = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const SizeOfHeaders = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const CheckSum = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const Subsystem = readAt(2, () => optionalHeaderView.getUint16(position, true), 0);
  position += 2;
  const DllCharacteristics = readAt(2, () => optionalHeaderView.getUint16(position, true), 0);
  position += 2;
  const SizeOfStackReserve = readAt(4, () => BigInt(optionalHeaderView.getUint32(position, true)), 0n);
  position += 4;
  const SizeOfStackCommit = readAt(4, () => BigInt(optionalHeaderView.getUint32(position, true)), 0n);
  position += 4;
  const SizeOfHeapReserve = readAt(4, () => BigInt(optionalHeaderView.getUint32(position, true)), 0n);
  position += 4;
  const SizeOfHeapCommit = readAt(4, () => BigInt(optionalHeaderView.getUint32(position, true)), 0n);
  position += 4;
  const LoaderFlags = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const NumberOfRvaAndSizes = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  return {
    nextPosition: position,
    BaseOfData,
    ImageBase,
    SectionAlignment,
    FileAlignment,
    OSVersionMajor,
    OSVersionMinor,
    ImageVersionMajor,
    ImageVersionMinor,
    SubsystemVersionMajor,
    SubsystemVersionMinor,
    Win32VersionValue,
    SizeOfImage,
    SizeOfHeaders,
    CheckSum,
    Subsystem,
    DllCharacteristics,
    SizeOfStackReserve,
    SizeOfStackCommit,
    SizeOfHeapReserve,
    SizeOfHeapCommit,
    LoaderFlags,
    NumberOfRvaAndSizes
  };
};

export const parseOptionalHeaderTailRom = (
  optionalHeaderView: DataView,
  start: number
): ParsedRomOptionalHeaderTail => {
  let position = start;
  const readAt = <T>(length: number, fn: () => T, fallback: T): T =>
    position + length <= optionalHeaderView.byteLength ? fn() : fallback;
  const readU32 = (): number => readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  const BaseOfData = readU32();
  position += 4;
  const BaseOfBss = readU32();
  position += 4;
  const GprMask = readU32();
  position += 4;
  const cprMask = Array.from({ length: 4 }, () => {
    const value = readU32();
    position += 4;
    return value;
  }) as ParsedRomOptionalHeaderTail["CprMask"];
  const GpValue = readU32();
  position += 4;
  return {
    nextPosition: position,
    BaseOfData,
    BaseOfBss,
    GprMask,
    CprMask: cprMask,
    GpValue
  };
};

export const parseOptionalHeaderTail64 = (
  optionalHeaderView: DataView,
  start: number
): ParsedOptionalHeaderTail => {
  let position = start;
  const readAt = <T>(length: number, fn: () => T, fallback: T): T =>
    position + length <= optionalHeaderView.byteLength ? fn() : fallback;
  const ImageBase = readAt(8, () => optionalHeaderView.getBigUint64(position, true), 0n);
  position += 8;
  const SectionAlignment = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const FileAlignment = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const [OSVersionMajor, OSVersionMinor] = readVersionPair(optionalHeaderView, position);
  position += 4;
  const [ImageVersionMajor, ImageVersionMinor] = readVersionPair(optionalHeaderView, position);
  position += 4;
  const [SubsystemVersionMajor, SubsystemVersionMinor] = readVersionPair(optionalHeaderView, position);
  position += 4;
  const Win32VersionValue = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const SizeOfImage = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const SizeOfHeaders = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const CheckSum = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const Subsystem = readAt(2, () => optionalHeaderView.getUint16(position, true), 0);
  position += 2;
  const DllCharacteristics = readAt(2, () => optionalHeaderView.getUint16(position, true), 0);
  position += 2;
  const SizeOfStackReserve = readAt(8, () => optionalHeaderView.getBigUint64(position, true), 0n);
  position += 8;
  const SizeOfStackCommit = readAt(8, () => optionalHeaderView.getBigUint64(position, true), 0n);
  position += 8;
  const SizeOfHeapReserve = readAt(8, () => optionalHeaderView.getBigUint64(position, true), 0n);
  position += 8;
  const SizeOfHeapCommit = readAt(8, () => optionalHeaderView.getBigUint64(position, true), 0n);
  position += 8;
  const LoaderFlags = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const NumberOfRvaAndSizes = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  return {
    nextPosition: position,
    ImageBase,
    SectionAlignment,
    FileAlignment,
    OSVersionMajor,
    OSVersionMinor,
    ImageVersionMajor,
    ImageVersionMinor,
    SubsystemVersionMajor,
    SubsystemVersionMinor,
    Win32VersionValue,
    SizeOfImage,
    SizeOfHeaders,
    CheckSum,
    Subsystem,
    DllCharacteristics,
    SizeOfStackReserve,
    SizeOfStackCommit,
    SizeOfHeapReserve,
    SizeOfHeapCommit,
    LoaderFlags,
    NumberOfRvaAndSizes
  };
};

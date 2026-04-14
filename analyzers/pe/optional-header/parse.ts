"use strict";

import { DD_NAMES } from "../constants.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import {
  parseOptionalHeaderTailRom,
  parseOptionalHeaderTail32,
  parseOptionalHeaderTail64
} from "./layouts.js";
import {
  PE32_OPTIONAL_HEADER_MAGIC,
  PE32_PLUS_OPTIONAL_HEADER_MAGIC,
  ROM_OPTIONAL_HEADER_MAGIC
} from "./magic.js";
import type { PeDataDirectory, PeOptionalHeader } from "../types.js";

const MINIMUM_OPTIONAL_HEADER_PROBE_SIZE = 0x80;

export type OptionalHeaderParseResult = {
  optOff: number;
  optSize: number;
  ddStartRel: number;
  ddCount: number;
  dataDirs: PeDataDirectory[];
  opt: PeOptionalHeader | null;
  warnings?: string[];
};

type OptionalHeaderViewInfo = {
  optionalHeaderOffset: number;
  declaredSize: number;
  optionalHeaderView: DataView;
};

type ParsedOptionalHeaderStandardFields = {
  Magic: number;
  LinkerMajor: number;
  LinkerMinor: number;
  SizeOfCode: number;
  SizeOfInitializedData: number;
  SizeOfUninitializedData: number;
  AddressOfEntryPoint: number;
  BaseOfCode: number;
  nextPosition: number;
};

export async function parseOptionalHeaderAndDirectories(
  reader: FileRangeReader,
  peHeaderOffset: number,
  sizeOfOptionalHeader: number
): Promise<OptionalHeaderParseResult> {
  const warnings: string[] = [];
  if (sizeOfOptionalHeader === 0) return createAbsentOptionalHeaderResult(peHeaderOffset + 24);
  const viewInfo = await readOptionalHeaderView(
    reader,
    peHeaderOffset + 24,
    sizeOfOptionalHeader,
    warnings
  );
  const standardFields = parseOptionalHeaderStandardFields(viewInfo.optionalHeaderView);
  if (!isKnownOptionalHeaderMagic(standardFields.Magic)) {
    return createUnrecognizedOptionalHeaderResult(
      viewInfo.optionalHeaderOffset,
      viewInfo.declaredSize,
      standardFields.Magic,
      warnings
    );
  }
  return standardFields.Magic === ROM_OPTIONAL_HEADER_MAGIC
    ? createRomOptionalHeaderResult(viewInfo, standardFields, warnings)
    : createWindowsOptionalHeaderResult(viewInfo, standardFields, warnings);
}

function createAbsentOptionalHeaderResult(optionalHeaderOffset: number): OptionalHeaderParseResult {
  return {
    optOff: optionalHeaderOffset,
    optSize: 0,
    ddStartRel: 0,
    ddCount: 0,
    dataDirs: [],
    opt: null,
    warnings: ["COFF SizeOfOptionalHeader is 0, so the optional header is absent."]
  };
}

async function readOptionalHeaderView(
  reader: FileRangeReader,
  optionalHeaderOffset: number,
  sizeOfOptionalHeader: number,
  warnings: string[]
): Promise<OptionalHeaderViewInfo> {
  const maxReadable = Math.max(0, reader.size - optionalHeaderOffset);
  if (maxReadable < sizeOfOptionalHeader) warnings.push("Optional header is truncated by end of file.");
  const declaredSize = Math.min(sizeOfOptionalHeader, maxReadable);
  const viewSize = declaredSize || Math.min(MINIMUM_OPTIONAL_HEADER_PROBE_SIZE, maxReadable);
  return {
    optionalHeaderOffset,
    declaredSize,
    optionalHeaderView: await reader.read(optionalHeaderOffset, viewSize)
  };
}

function parseOptionalHeaderStandardFields(
  optionalHeaderView: DataView
): ParsedOptionalHeaderStandardFields {
  let position = 0;
  const readAt = <T>(length: number, fn: () => T, fallback: T): T =>
    position + length <= optionalHeaderView.byteLength ? fn() : fallback;
  const Magic = readAt(2, () => optionalHeaderView.getUint16(position, true), 0);
  position += 2;
  const [LinkerMajor, LinkerMinor] = readAt<[number, number]>(2, () => [
    optionalHeaderView.getUint8(position),
    optionalHeaderView.getUint8(position + 1)
  ], [0, 0]);
  position += 2;
  const SizeOfCode = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const SizeOfInitializedData = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const SizeOfUninitializedData = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const AddressOfEntryPoint = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  const BaseOfCode = readAt(4, () => optionalHeaderView.getUint32(position, true), 0);
  position += 4;
  return {
    Magic,
    LinkerMajor,
    LinkerMinor,
    SizeOfCode,
    SizeOfInitializedData,
    SizeOfUninitializedData,
    AddressOfEntryPoint,
    BaseOfCode,
    nextPosition: position
  };
}

function isKnownOptionalHeaderMagic(magic: number): boolean {
  return magic === PE32_OPTIONAL_HEADER_MAGIC ||
    magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ||
    magic === ROM_OPTIONAL_HEADER_MAGIC;
}

function createUnrecognizedOptionalHeaderResult(
  optionalHeaderOffset: number,
  declaredSize: number,
  magic: number,
  warnings: string[]
): OptionalHeaderParseResult {
  return {
    optOff: optionalHeaderOffset,
    optSize: declaredSize,
    ddStartRel: 0,
    ddCount: 0,
    dataDirs: [],
    opt: null,
    warnings: [
      ...warnings,
      `Optional header Magic ${`0x${(magic >>> 0).toString(16)}`} is not PE32, PE32+, or ROM.`
    ]
  };
}

function createRomOptionalHeaderResult(
  viewInfo: OptionalHeaderViewInfo,
  standardFields: ParsedOptionalHeaderStandardFields,
  warnings: string[]
): OptionalHeaderParseResult {
  const rom = parseOptionalHeaderTailRom(viewInfo.optionalHeaderView, standardFields.nextPosition);
  return {
    optOff: viewInfo.optionalHeaderOffset,
    optSize: Math.max(viewInfo.declaredSize, Math.min(viewInfo.optionalHeaderView.byteLength, rom.nextPosition)),
    ddStartRel: 0,
    ddCount: 0,
    dataDirs: [],
    opt: {
      Magic: ROM_OPTIONAL_HEADER_MAGIC,
      LinkerMajor: standardFields.LinkerMajor,
      LinkerMinor: standardFields.LinkerMinor,
      SizeOfCode: standardFields.SizeOfCode,
      SizeOfInitializedData: standardFields.SizeOfInitializedData,
      SizeOfUninitializedData: standardFields.SizeOfUninitializedData,
      AddressOfEntryPoint: standardFields.AddressOfEntryPoint,
      BaseOfCode: standardFields.BaseOfCode,
      BaseOfData: rom.BaseOfData,
      rom: {
        BaseOfBss: rom.BaseOfBss,
        GprMask: rom.GprMask,
        CprMask: rom.CprMask,
        GpValue: rom.GpValue
      }
    },
    ...(warnings.length ? { warnings } : {})
  };
}

function createWindowsOptionalHeaderResult(
  viewInfo: OptionalHeaderViewInfo,
  standardFields: ParsedOptionalHeaderStandardFields,
  warnings: string[]
): OptionalHeaderParseResult {
  const tail = standardFields.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC
    ? parseOptionalHeaderTail64(viewInfo.optionalHeaderView, standardFields.nextPosition)
    : parseOptionalHeaderTail32(viewInfo.optionalHeaderView, standardFields.nextPosition);
  const ddStartRel = tail.nextPosition;
  const ddCount = Math.min(
    tail.NumberOfRvaAndSizes,
    Math.max(0, Math.floor((viewInfo.optionalHeaderView.byteLength - ddStartRel) / 8))
  );
  const optSize = Math.max(
    viewInfo.declaredSize,
    Math.min(viewInfo.optionalHeaderView.byteLength, ddStartRel + ddCount * 8)
  );
  return {
    optOff: viewInfo.optionalHeaderOffset,
    optSize,
    ddStartRel,
    ddCount,
    dataDirs: readDataDirectories(viewInfo.optionalHeaderView, ddStartRel, ddCount),
    opt: createWindowsOptionalHeader(standardFields, tail),
    ...(warnings.length ? { warnings } : {})
  };
}

function readDataDirectories(
  optionalHeaderView: DataView,
  ddStartRel: number,
  ddCount: number
): PeDataDirectory[] {
  return Array.from({ length: ddCount }, (_, index) => {
    const entryOffset = ddStartRel + index * 8;
    return {
      index,
      name: DD_NAMES[index] || "",
      rva: optionalHeaderView.getUint32(entryOffset, true),
      size: optionalHeaderView.getUint32(entryOffset + 4, true)
    };
  });
}

function createWindowsOptionalHeader(
  standardFields: ParsedOptionalHeaderStandardFields,
  tail: ReturnType<typeof parseOptionalHeaderTail32> | ReturnType<typeof parseOptionalHeaderTail64>
): PeOptionalHeader {
  const common = {
    LinkerMajor: standardFields.LinkerMajor,
    LinkerMinor: standardFields.LinkerMinor,
    SizeOfCode: standardFields.SizeOfCode,
    SizeOfInitializedData: standardFields.SizeOfInitializedData,
    SizeOfUninitializedData: standardFields.SizeOfUninitializedData,
    AddressOfEntryPoint: standardFields.AddressOfEntryPoint,
    BaseOfCode: standardFields.BaseOfCode,
    ImageBase: tail.ImageBase,
    SectionAlignment: tail.SectionAlignment,
    FileAlignment: tail.FileAlignment,
    OSVersionMajor: tail.OSVersionMajor,
    OSVersionMinor: tail.OSVersionMinor,
    ImageVersionMajor: tail.ImageVersionMajor,
    ImageVersionMinor: tail.ImageVersionMinor,
    SubsystemVersionMajor: tail.SubsystemVersionMajor,
    SubsystemVersionMinor: tail.SubsystemVersionMinor,
    Win32VersionValue: tail.Win32VersionValue,
    SizeOfImage: tail.SizeOfImage,
    SizeOfHeaders: tail.SizeOfHeaders,
    CheckSum: tail.CheckSum,
    Subsystem: tail.Subsystem,
    DllCharacteristics: tail.DllCharacteristics,
    SizeOfStackReserve: tail.SizeOfStackReserve,
    SizeOfStackCommit: tail.SizeOfStackCommit,
    SizeOfHeapReserve: tail.SizeOfHeapReserve,
    SizeOfHeapCommit: tail.SizeOfHeapCommit,
    LoaderFlags: tail.LoaderFlags,
    NumberOfRvaAndSizes: tail.NumberOfRvaAndSizes
  };
  return standardFields.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC
    ? { Magic: PE32_PLUS_OPTIONAL_HEADER_MAGIC, ...common }
    : { Magic: PE32_OPTIONAL_HEADER_MAGIC, BaseOfData: tail.BaseOfData ?? 0, ...common };
}

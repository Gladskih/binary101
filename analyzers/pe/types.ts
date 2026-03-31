"use strict";

import type { PeSectionName } from "./section-name.js";

export type RvaToOffset = (rva: number) => number | null;

export interface PeDataDirectory {
  index?: number;
  name: string;
  rva: number;
  size: number;
}

export interface PeSection {
  name: PeSectionName;
  virtualSize: number;
  virtualAddress: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  characteristics: number;
  entropy?: number | null;
}

export interface PeDosStub {
  kind: string;
  note: string;
  strings?: string[];
}

export interface PeRichHeaderEntry {
  productId: number;
  buildNumber: number;
  count: number;
}

export interface PeRichHeader {
  xorKey: number;
  checksum: number | null;
  entries: PeRichHeaderEntry[];
  warnings?: string[];
}

export interface PeDosHeader {
  e_magic: string;
  e_cblp: number;
  e_cp: number;
  e_crlc: number;
  e_cparhdr: number;
  e_minalloc: number;
  e_maxalloc: number;
  e_ss: number;
  e_sp: number;
  e_csum: number;
  e_ip: number;
  e_cs: number;
  e_lfarlc: number;
  e_ovno: number;
  e_res: number[];
  e_oemid: number;
  e_oeminfo: number;
  e_res2: number[];
  e_lfanew: number;
  stub: PeDosStub;
  rich?: PeRichHeader | null;
}

export interface PeCoffHeader {
  Machine: number;
  NumberOfSections: number;
  TimeDateStamp: number;
  PointerToSymbolTable: number;
  NumberOfSymbols: number;
  SizeOfOptionalHeader: number;
  Characteristics: number;
}

export interface PeRomOptionalFields {
  BaseOfBss: number;
  GprMask: number;
  CprMask: [number, number, number, number];
  GpValue: number;
}

export type PeOptionalHeaderKind = "pe32" | "pe32+" | "rom" | "unknown";

interface PeOptionalHeaderBase {
  Magic: number;
  LinkerMajor: number;
  LinkerMinor: number;
  SizeOfCode: number;
  SizeOfInitializedData: number;
  SizeOfUninitializedData: number;
  AddressOfEntryPoint: number;
  BaseOfCode: number;
}

interface PeWindowsOptionalHeaderBase extends PeOptionalHeaderBase {
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
}

export interface Pe32OptionalHeader extends PeWindowsOptionalHeaderBase {
  Magic: 0x10b;
  BaseOfData: number;
}

export interface PePlusOptionalHeader extends PeWindowsOptionalHeaderBase {
  Magic: 0x20b;
}

export type PeWindowsOptionalHeader = Pe32OptionalHeader | PePlusOptionalHeader;

export interface PeRomOptionalHeader extends PeOptionalHeaderBase {
  Magic: 0x107;
  BaseOfData: number;
  rom: PeRomOptionalFields;
}

export interface PeUnknownOptionalHeader extends PeOptionalHeaderBase {}

export type PeOptionalHeader =
  | Pe32OptionalHeader
  | PePlusOptionalHeader
  | PeRomOptionalHeader
  | PeUnknownOptionalHeader;

export interface PeCore {
  dos: PeDosHeader;
  coff: PeCoffHeader;
  coffStringTableSize?: number;
  trailingAlignmentPaddingSize?: number;
  opt: PeOptionalHeader;
  warnings?: string[];
  optOff: number;
  ddStartRel: number;
  ddCount: number;
  dataDirs: PeDataDirectory[];
  sections: PeSection[];
  entrySection: { name: string; index: number } | null;
  rvaToOff: RvaToOffset;
  overlaySize: number;
  imageEnd: number;
  imageSizeMismatch: boolean;
}

export interface PeTlsDirectory {
  StartAddressOfRawData: bigint;
  EndAddressOfRawData: bigint;
  AddressOfIndex: bigint;
  AddressOfCallBacks: bigint;
  SizeOfZeroFill: number;
  Characteristics: number;
  CallbackCount: number;
  CallbackRvas?: number[];
  warnings?: string[];
  parsed?: boolean;
}

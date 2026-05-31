"use strict";

import type { PeSectionName } from "./sections/name.js";

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
  pointerToRelocations?: number;
  pointerToLinenumbers?: number;
  numberOfRelocations?: number;
  numberOfLinenumbers?: number;
  characteristics: number;
  entropy?: number | null;
  rawTail?: PeSectionRawTail;
}

export interface PeSectionRawTail {
  zeroFilled: boolean | null;
  readableSize: number;
  warnings?: string[];
}

export interface PeDosStub {
  kind: string;
  note: string;
  strings?: string[];
  code?: PeDosStubCode;
}

export interface PeDosStubInstruction {
  offset: number;
  text: string;
}

export interface PeDosStubNestedPeSection {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  sizeOfRawData: number;
  pointerToRawData: number;
}

export interface PeDosStubMleHeader {
  offset: number;
  version: number;
  entryPoint: number;
  firstValidPage: number;
  mleStart: number;
  mleEnd: number;
  capabilities: number;
}

export interface PeDosStubNestedPe {
  offset: number;
  endOffset: number;
  peHeaderOffset: number;
  machine: number;
  optionalMagic: number | null;
  entrypointRva: number | null;
  subsystem: number | null;
  sizeOfImage: number | null;
  sizeOfHeaders: number | null;
  sections: PeDosStubNestedPeSection[];
  codeViewPath?: string;
  mle?: PeDosStubMleHeader;
  warnings?: string[];
}

export interface PeDosStubCode {
  kind: "standard-print-exit" | "custom-or-unrecognized" | "unavailable";
  messageOffset?: number;
  message?: string;
  exitCode?: number;
  instructions: PeDosStubInstruction[];
  nestedPe?: PeDosStubNestedPe;
  notes?: string[];
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

export type PeOptionalHeader = Pe32OptionalHeader | PePlusOptionalHeader | PeRomOptionalHeader;

interface PeCoreBase {
  dos: PeDosHeader;
  coff: PeCoffHeader;
  coffStringTableSize?: number;
  trailingAlignmentPaddingSize?: number;
  warnings?: string[];
  optOff: number;
  ddStartRel: number;
  ddCount: number;
  sections: PeSection[];
  entrySection: { name: string; index: number } | null;
  rvaToOff: RvaToOffset;
  imageEnd: number;
  imageSizeMismatch: boolean;
}

export interface PeWindowsCore extends PeCoreBase {
  opt: PeWindowsOptionalHeader;
  dataDirs: PeDataDirectory[];
}

export interface PeHeaderCore extends PeCoreBase {
  opt: PeRomOptionalHeader | null;
  dataDirs: [];
}

export type PeCore = PeWindowsCore | PeHeaderCore;

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

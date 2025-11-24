"use strict";

export interface PeDataDirectory {
  index?: number;
  name: string;
  rva: number;
  size: number;
}

export type RvaToOffset = (rva: number) => number | null;
export type AddCoverageRegion = (label: string, offset: number, size: number) => void;

export interface PeSection {
  name: string;
  virtualSize: number;
  virtualAddress: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  characteristics: number;
  entropy?: number | null;
}

export interface PeCoverageEntry {
  label: string;
  off: number;
  end: number;
  size: number;
}

export interface PeDosStub {
  kind: string;
  note: string;
  strings?: string[];
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

export interface PeOptionalHeader {
  Magic: number;
  isPlus: boolean;
  is32: boolean;
  LinkerMajor: number;
  LinkerMinor: number;
  SizeOfCode: number;
  SizeOfInitializedData: number;
  SizeOfUninitializedData: number;
  AddressOfEntryPoint: number;
  BaseOfCode: number;
  BaseOfData?: number;
  ImageBase: number;
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
  SizeOfStackReserve: number;
  SizeOfStackCommit: number;
  SizeOfHeapReserve: number;
  SizeOfHeapCommit: number;
  LoaderFlags: number;
  NumberOfRvaAndSizes: number;
}

export interface PeCore {
  dos: PeDosHeader;
  coff: PeCoffHeader;
  opt: PeOptionalHeader;
  dataDirs: PeDataDirectory[];
  sections: PeSection[];
  entrySection: { name: string; index: number } | null;
  rvaToOff: RvaToOffset;
  coverage: PeCoverageEntry[];
  addCoverageRegion: AddCoverageRegion;
  overlaySize: number;
  imageEnd: number;
  imageSizeMismatch: boolean;
}

export interface PeTlsDirectory {
  StartAddressOfRawData: number;
  EndAddressOfRawData: number;
  AddressOfIndex: number;
  AddressOfCallBacks: number;
  SizeOfZeroFill: number;
  Characteristics: number;
  CallbackCount: number;
}

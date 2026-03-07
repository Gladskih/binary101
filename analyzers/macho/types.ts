"use strict";

export interface MachOFileHeader {
  magic: number;
  is64: boolean;
  littleEndian: boolean;
  cputype: number;
  cpusubtype: number;
  filetype: number;
  ncmds: number;
  sizeofcmds: number;
  flags: number;
  reserved: number | null;
}

export interface MachOLoadCommand {
  index: number;
  offset: number;
  cmd: number;
  cmdsize: number;
}

export interface MachOSection {
  index: number;
  segmentName: string;
  sectionName: string;
  addr: bigint;
  size: bigint;
  offset: number;
  align: number;
  reloff: number;
  nreloc: number;
  flags: number;
  reserved1: number;
  reserved2: number;
  reserved3: number | null;
}

export interface MachOSegment {
  loadCommandIndex: number;
  name: string;
  vmaddr: bigint;
  vmsize: bigint;
  fileoff: bigint;
  filesize: bigint;
  maxprot: number;
  initprot: number;
  nsects: number;
  flags: number;
  sections: MachOSection[];
}

export interface MachODylib {
  loadCommandIndex: number;
  command: number;
  name: string;
  timestamp: number;
  currentVersion: number;
  compatibilityVersion: number;
}

export interface MachORpath {
  loadCommandIndex: number;
  path: string;
}

export interface MachOStringCommand {
  loadCommandIndex: number;
  command: number;
  value: string;
}

export interface MachOBuildTool {
  tool: number;
  version: number;
}

export interface MachOBuildVersion {
  loadCommandIndex: number;
  platform: number;
  minos: number;
  sdk: number;
  tools: MachOBuildTool[];
}

export interface MachOVersionMin {
  loadCommandIndex: number;
  command: number;
  version: number;
  sdk: number;
}

export interface MachOSourceVersion {
  loadCommandIndex: number;
  value: bigint;
}

export interface MachOEntryPoint {
  loadCommandIndex: number;
  entryoff: bigint;
  stacksize: bigint;
}

export interface MachODyldInfo {
  loadCommandIndex: number;
  command: number;
  rebaseOff: number;
  rebaseSize: number;
  bindOff: number;
  bindSize: number;
  weakBindOff: number;
  weakBindSize: number;
  lazyBindOff: number;
  lazyBindSize: number;
  exportOff: number;
  exportSize: number;
}

export interface MachOLinkeditData {
  loadCommandIndex: number;
  command: number;
  dataoff: number;
  datasize: number;
}

export interface MachOEncryptionInfo {
  loadCommandIndex: number;
  command: number;
  cryptoff: number;
  cryptsize: number;
  cryptid: number;
}

export interface MachOFileSetEntry {
  loadCommandIndex: number;
  entryId: string;
  vmaddr: bigint;
  fileoff: bigint;
}

export interface MachOSymbol {
  index: number;
  name: string;
  stringIndex: number;
  type: number;
  sectionIndex: number;
  description: number;
  libraryOrdinal: number | null;
  value: bigint;
}

export interface MachOSymtabInfo {
  symoff: number;
  nsyms: number;
  stroff: number;
  strsize: number;
  symbols: MachOSymbol[];
  issues: string[];
}

export interface MachOCodeSignatureSlot {
  type: number;
  offset: number;
  magic: number | null;
  length: number | null;
}

export interface MachOCodeDirectory {
  version: number;
  flags: number;
  hashSize: number;
  hashType: number;
  platform: number | null;
  pageSizeShift: number;
  nSpecialSlots: number;
  nCodeSlots: number;
  codeLimit: bigint;
  identifier: string | null;
  teamIdentifier: string | null;
  execSegBase: bigint | null;
  execSegLimit: bigint | null;
  execSegFlags: bigint | null;
  runtime: number | null;
}

export interface MachOCodeSignature {
  loadCommandIndex: number;
  dataoff: number;
  datasize: number;
  magic: number | null;
  length: number | null;
  blobCount: number | null;
  slots: MachOCodeSignatureSlot[];
  codeDirectory: MachOCodeDirectory | null;
  issues: string[];
}

export interface MachOImage {
  offset: number;
  size: number;
  header: MachOFileHeader;
  loadCommands: MachOLoadCommand[];
  segments: MachOSegment[];
  dylibs: MachODylib[];
  idDylib: MachODylib | null;
  rpaths: MachORpath[];
  stringCommands: MachOStringCommand[];
  uuid: string | null;
  buildVersions: MachOBuildVersion[];
  minVersions: MachOVersionMin[];
  sourceVersion: MachOSourceVersion | null;
  entryPoint: MachOEntryPoint | null;
  dyldInfo: MachODyldInfo | null;
  linkeditData: MachOLinkeditData[];
  encryptionInfos: MachOEncryptionInfo[];
  fileSetEntries: MachOFileSetEntry[];
  symtab: MachOSymtabInfo | null;
  codeSignature: MachOCodeSignature | null;
  issues: string[];
}

export interface MachOFatHeader {
  magic: number;
  is64: boolean;
  littleEndian: boolean;
  nfatArch: number;
}

export interface MachOFatSlice {
  index: number;
  cputype: number;
  cpusubtype: number;
  offset: number;
  size: number;
  align: number;
  reserved: number | null;
  image: MachOImage | null;
  issues: string[];
}

export interface MachOParseResult {
  kind: "thin" | "fat";
  fileSize: number;
  image: MachOImage | null;
  fatHeader: MachOFatHeader | null;
  slices: MachOFatSlice[];
  issues: string[];
}

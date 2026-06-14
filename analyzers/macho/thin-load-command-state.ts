"use strict";

import type {
  MachOBuildVersion,
  MachOCodeSignature,
  MachODyldInfo,
  MachODylib,
  MachOEncryptionInfo,
  MachOEntryPoint,
  MachOFileHeader,
  MachOFileSetEntry,
  MachOImage,
  MachOLinkeditData,
  MachOLoadCommand,
  MachORpath,
  MachOSegment,
  MachOSourceVersion,
  MachOStringCommand,
  MachOSymtabInfo,
  MachOVersionMin
} from "./types.js";

export type SymtabCommand = {
  loadCommandIndex: number;
  symoff: number;
  nsyms: number;
  stroff: number;
  strsize: number;
};

export type CodeSignatureCommand = {
  loadCommandIndex: number;
  dataoff: number;
  datasize: number;
};

export type EntryPointCommand = {
  loadCommandIndex: number;
  entryoff: bigint;
  stacksize: bigint;
};

export type ThinExternalData = {
  symtab: MachOSymtabInfo | null;
  codeSignature: MachOCodeSignature | null;
};

export type ThinLoadCommandState = {
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
  entryPoint: EntryPointCommand | MachOEntryPoint | null;
  symtabCommand: SymtabCommand | null;
  dyldInfo: MachODyldInfo | null;
  linkeditData: MachOLinkeditData[];
  encryptionInfos: MachOEncryptionInfo[];
  fileSetEntries: MachOFileSetEntry[];
  codeSignatureCommand: CodeSignatureCommand | null;
  nextSectionIndex: { value: number };
  seenSingletonCommands: Map<number | symbol, number>;
};

export const createThinLoadCommandState = (): ThinLoadCommandState => ({
  loadCommands: [],
  segments: [],
  dylibs: [],
  idDylib: null,
  rpaths: [],
  stringCommands: [],
  uuid: null,
  buildVersions: [],
  minVersions: [],
  sourceVersion: null,
  entryPoint: null,
  symtabCommand: null,
  dyldInfo: null,
  linkeditData: [],
  encryptionInfos: [],
  fileSetEntries: [],
  codeSignatureCommand: null,
  nextSectionIndex: { value: 1 },
  seenSingletonCommands: new Map<number | symbol, number>()
});

export const buildThinImage = (
  imageOffset: number,
  imageSize: number,
  header: MachOFileHeader,
  state: ThinLoadCommandState,
  externalData: ThinExternalData,
  issues: string[]
): MachOImage => ({
  offset: imageOffset,
  size: imageSize,
  header,
  loadCommands: state.loadCommands,
  segments: state.segments,
  dylibs: state.dylibs,
  idDylib: state.idDylib,
  rpaths: state.rpaths,
  stringCommands: state.stringCommands,
  uuid: state.uuid,
  buildVersions: state.buildVersions,
  minVersions: state.minVersions,
  sourceVersion: state.sourceVersion,
  entryPoint: state.entryPoint,
  dyldInfo: state.dyldInfo,
  linkeditData: state.linkeditData,
  encryptionInfos: state.encryptionInfos,
  fileSetEntries: state.fileSetEntries,
  symtab: externalData.symtab,
  codeSignature: externalData.codeSignature,
  issues
});

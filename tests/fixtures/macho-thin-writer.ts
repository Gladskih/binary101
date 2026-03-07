"use strict";

import {
  LC_BUILD_VERSION,
  LC_CODE_SIGNATURE,
  LC_LOAD_DYLIB,
  LC_LOAD_DYLINKER,
  LC_MAIN,
  LC_SOURCE_VERSION,
  LC_SYMTAB,
  LC_UUID,
  N_EXT,
  N_UNDF
} from "../../analyzers/macho/commands.js";
import {
  THIN_MACHO_FIXTURE_CONSTANTS,
  type ThinMachOFixturePlan,
  type ThinMachOFixtureState
} from "./macho-thin-state.js";
import {
  writeCommandHeader,
  writeMachHeader,
  writeSection64,
  writeSegment64
} from "./macho-thin-record-writers.js";

type ThinMachOSymbol = {
  description: number;
  sectionIndex: number;
  stringIndex: number;
  type: number;
  value: bigint;
};

const writeTextSegment = (
  state: ThinMachOFixtureState,
  plan: ThinMachOFixturePlan,
  cursor: number
): number => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  const commandSize = constants.segment64Size + constants.section64Size * 2;
  const textSectionCursor = cursor + constants.segment64Size;
  const cstringSectionCursor = textSectionCursor + constants.section64Size;
  state.layout.textSegmentCommandOffset = cursor;
  state.layout.textSectionOffsetFieldOffset = textSectionCursor + constants.section64OffsetField;
  state.layout.textSectionFlagsOffset = textSectionCursor + constants.section64FlagsField;
  writeSegment64(state, cursor, commandSize, {
    fileoff: 0n,
    filesize: constants.textSegmentFileSize,
    flags: 0,
    initprot: constants.vmProtReadExecute,
    maxprot: constants.vmProtReadWriteExecute,
    name: "__TEXT",
    nsects: 2,
    vmsize: constants.segmentVmSize,
    vmaddr: constants.textSegmentVmaddr
  });
  writeSection64(state, textSectionCursor, {
    addr: constants.textSectionVmaddr,
    flags: constants.textSectionFlags,
    name: "__text",
    offset: plan.textOffset,
    segmentName: "__TEXT",
    size: BigInt(plan.textBytes.length)
  });
  writeSection64(state, cstringSectionCursor, {
    addr: constants.textSectionVmaddr + BigInt(plan.textBytes.length),
    flags: constants.cstringSectionFlags,
    name: "__cstring",
    offset: plan.cstringOffset,
    segmentName: "__TEXT",
    size: BigInt(plan.cstringBytes.length)
  });
  return cursor + commandSize;
};

const writeLinkeditSegment = (
  state: ThinMachOFixtureState,
  plan: ThinMachOFixturePlan,
  cursor: number
): number => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  state.layout.linkeditSegmentCommandOffset = cursor;
  writeSegment64(state, cursor, constants.linkeditSegmentSize, {
    fileoff: BigInt(plan.symoff),
    filesize: BigInt(state.bytes.length - plan.symoff),
    flags: 0,
    initprot: 1,
    maxprot: 1,
    name: "__LINKEDIT",
    nsects: 0,
    vmsize: constants.segmentVmSize,
    vmaddr: constants.textSegmentVmaddr + constants.segmentVmSize
  });
  return cursor + constants.linkeditSegmentSize;
};

const writeBuildVersionCommand = (state: ThinMachOFixtureState, cursor: number): number => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  state.layout.buildVersionCommandOffset = cursor;
  writeCommandHeader(state.view, cursor, LC_BUILD_VERSION, constants.buildVersionCommandSize);
  state.view.setUint32(cursor + 8, constants.platformMacOs, true);
  state.view.setUint32(cursor + 12, constants.buildMinVersion, true);
  state.view.setUint32(cursor + 16, constants.buildSdkVersion, true);
  state.view.setUint32(cursor + 20, 1, true);
  state.view.setUint32(cursor + 24, constants.toolClang, true);
  state.view.setUint32(cursor + 28, 1500, true);
  return cursor + constants.buildVersionCommandSize;
};

const writeDylinkerCommand = (state: ThinMachOFixtureState, plan: ThinMachOFixturePlan, cursor: number): number => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  state.layout.dyldCommandOffset = cursor;
  writeCommandHeader(state.view, cursor, LC_LOAD_DYLINKER, plan.dyldCommandSize);
  state.view.setUint32(cursor + 8, constants.dylinkerCommandBaseSize, true);
  state.bytes.set(plan.dyldBytes, cursor + constants.dylinkerCommandBaseSize);
  return cursor + plan.dyldCommandSize;
};

const writeDylibCommand = (state: ThinMachOFixtureState, plan: ThinMachOFixturePlan, cursor: number): number => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  state.layout.dylibCommandOffset = cursor;
  writeCommandHeader(state.view, cursor, LC_LOAD_DYLIB, plan.dylibCommandSize);
  state.view.setUint32(cursor + 8, constants.dylibCommandBaseSize, true);
  state.view.setUint32(cursor + 12, 2, true);
  state.view.setUint32(cursor + 16, 0x00010000, true);
  state.view.setUint32(cursor + 20, 0x00010000, true);
  state.bytes.set(plan.dylibBytes, cursor + constants.dylibCommandBaseSize);
  return cursor + plan.dylibCommandSize;
};

const writeEntryPointCommand = (
  state: ThinMachOFixtureState,
  plan: ThinMachOFixturePlan,
  cursor: number
): number => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  state.layout.mainCommandOffset = cursor;
  writeCommandHeader(state.view, cursor, LC_MAIN, constants.entryPointCommandSize);
  state.view.setBigUint64(cursor + 8, BigInt(plan.textOffset), true);
  state.view.setBigUint64(cursor + 16, 0n, true);
  return cursor + constants.entryPointCommandSize;
};

const writeUuidCommand = (
  state: ThinMachOFixtureState,
  cursor: number,
  uuidTail: number
): number => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  state.layout.uuidCommandOffset = cursor;
  writeCommandHeader(state.view, cursor, LC_UUID, constants.uuidCommandSize);
  for (let index = 0; index < 16; index += 1) {
    state.bytes[cursor + 8 + index] = (uuidTail + index) & 0xff;
  }
  return cursor + constants.uuidCommandSize;
};

const writeSourceVersionCommand = (state: ThinMachOFixtureState, cursor: number): number => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  state.layout.sourceVersionCommandOffset = cursor;
  writeCommandHeader(state.view, cursor, LC_SOURCE_VERSION, constants.sourceVersionCommandSize);
  state.view.setBigUint64(cursor + 8, constants.sourceVersion, true);
  return cursor + constants.sourceVersionCommandSize;
};

const writeSymtabCommand = (state: ThinMachOFixtureState, plan: ThinMachOFixturePlan, cursor: number): number => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  state.layout.symtabCommandOffset = cursor;
  writeCommandHeader(state.view, cursor, LC_SYMTAB, constants.symtabCommandSize);
  state.view.setUint32(cursor + 8, plan.symoff, true);
  state.view.setUint32(cursor + 12, 3, true);
  state.view.setUint32(cursor + 16, plan.stroff, true);
  state.view.setUint32(cursor + 20, plan.stringTable.length, true);
  return cursor + constants.symtabCommandSize;
};

const writeCodeSignatureCommand = (state: ThinMachOFixtureState, plan: ThinMachOFixturePlan, cursor: number): void => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  state.layout.codeSignatureCommandOffset = cursor;
  writeCommandHeader(state.view, cursor, LC_CODE_SIGNATURE, constants.codeSignatureCommandSize);
  state.view.setUint32(cursor + 8, plan.codeSignatureOffset, true);
  state.view.setUint32(cursor + 12, plan.codeSignature.length, true);
};

const writeSymbolEntry = (state: ThinMachOFixtureState, cursor: number, symbol: ThinMachOSymbol): number => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  state.view.setUint32(cursor, symbol.stringIndex, true);
  state.bytes[cursor + 4] = symbol.type;
  state.bytes[cursor + 5] = symbol.sectionIndex;
  state.view.setUint16(cursor + 6, symbol.description, true);
  state.view.setBigUint64(cursor + 8, symbol.value, true);
  return cursor + constants.nlist64Size;
};

const writeSymbolTable = (state: ThinMachOFixtureState, plan: ThinMachOFixturePlan): void => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  let cursor = plan.symoff;
  cursor = writeSymbolEntry(state, cursor, {
    description: 0,
    sectionIndex: 1,
    stringIndex: 1,
    type: constants.nSect | N_EXT,
    value: constants.textSegmentVmaddr
  });
  cursor = writeSymbolEntry(state, cursor, {
    description: 0,
    sectionIndex: 1,
    stringIndex: 21,
    type: constants.nSect | N_EXT,
    value: constants.textSectionVmaddr
  });
  writeSymbolEntry(state, cursor, {
    description: constants.referenceFlagUndefinedLazy,
    sectionIndex: 0,
    stringIndex: 27,
    type: N_EXT | N_UNDF,
    value: 0n
  });
};

const writePayloads = (state: ThinMachOFixtureState, plan: ThinMachOFixturePlan): void => {
  state.bytes.set(plan.textBytes, plan.textOffset);
  state.bytes.set(plan.cstringBytes, plan.cstringOffset);
  state.bytes.set(plan.stringTable, plan.stroff);
  state.bytes.set(plan.codeSignature, plan.codeSignatureOffset);
};

export const writeThinMachOFixture = (
  state: ThinMachOFixtureState,
  plan: ThinMachOFixturePlan,
  cpuType: number,
  cpuSubtype: number,
  uuidTail: number
): void => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  writeMachHeader(state.view, cpuType, cpuSubtype, plan.sizeofcmds, plan.ncmds);
  let cursor: number = constants.headerSize;
  cursor = writeTextSegment(state, plan, cursor);
  cursor = writeLinkeditSegment(state, plan, cursor);
  cursor = writeBuildVersionCommand(state, cursor);
  cursor = writeDylinkerCommand(state, plan, cursor);
  cursor = writeDylibCommand(state, plan, cursor);
  cursor = writeEntryPointCommand(state, plan, cursor);
  cursor = writeUuidCommand(state, cursor, uuidTail);
  cursor = writeSourceVersionCommand(state, cursor);
  cursor = writeSymtabCommand(state, plan, cursor);
  writeCodeSignatureCommand(state, plan, cursor);
  writeSymbolTable(state, plan);
  writePayloads(state, plan);
};

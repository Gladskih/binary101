"use strict";

// Layouts and command IDs below are taken from Apple's Mach-O headers:
// https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/loader.h

import { LC_SEGMENT_64, MH_MAGIC_64 } from "../../analyzers/macho/commands.js";
import {
  THIN_MACHO_FIXTURE_CONSTANTS,
  type ThinMachOFixtureState
} from "./macho-thin-state.js";

const textEncoder = new TextEncoder();

export type ThinMachOSection = {
  addr: bigint;
  flags: number;
  name: string;
  offset: number;
  segmentName: string;
  size: bigint;
};

export type ThinMachOSegment = {
  fileoff: bigint;
  filesize: bigint;
  flags: number;
  initprot: number;
  maxprot: number;
  name: string;
  nsects: number;
  vmsize: bigint;
  vmaddr: bigint;
};

const writeAscii = (bytes: Uint8Array, offset: number, text: string): void => {
  bytes.set(textEncoder.encode(text), offset);
};

export const writeCommandHeader = (
  view: DataView,
  cursor: number,
  command: number,
  size: number
): void => {
  view.setUint32(cursor, command, true);
  view.setUint32(cursor + 4, size, true);
};

export const writeMachHeader = (
  view: DataView,
  cpuType: number,
  cpuSubtype: number,
  sizeofcmds: number,
  ncmds: number
): void => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  view.setUint32(0, MH_MAGIC_64, true);
  view.setUint32(4, cpuType, true);
  view.setUint32(8, cpuSubtype, true);
  view.setUint32(12, constants.machHeaderFileType, true);
  view.setUint32(constants.headerNcmdsOffset, ncmds, true);
  view.setUint32(constants.headerSizeofcmdsOffset, sizeofcmds, true);
  view.setUint32(constants.headerFlagsOffset, constants.machHeaderFlags, true);
  view.setUint32(28, 0, true);
};

export const writeSegment64 = (
  state: ThinMachOFixtureState,
  cursor: number,
  commandSize: number,
  segment: ThinMachOSegment
): void => {
  writeCommandHeader(state.view, cursor, LC_SEGMENT_64, commandSize);
  writeAscii(state.bytes, cursor + 8, segment.name);
  state.view.setBigUint64(cursor + 24, segment.vmaddr, true);
  state.view.setBigUint64(cursor + 32, segment.vmsize, true);
  state.view.setBigUint64(cursor + 40, segment.fileoff, true);
  state.view.setBigUint64(cursor + 48, segment.filesize, true);
  state.view.setUint32(cursor + 56, segment.maxprot, true);
  state.view.setUint32(cursor + 60, segment.initprot, true);
  state.view.setUint32(cursor + 64, segment.nsects, true);
  state.view.setUint32(cursor + 68, segment.flags, true);
};

export const writeSection64 = (
  state: ThinMachOFixtureState,
  cursor: number,
  section: ThinMachOSection
): void => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  writeAscii(state.bytes, cursor, section.name);
  writeAscii(state.bytes, cursor + 16, section.segmentName);
  state.view.setBigUint64(cursor + 32, section.addr, true);
  state.view.setBigUint64(cursor + 40, section.size, true);
  state.view.setUint32(cursor + constants.section64OffsetField, section.offset, true);
  state.view.setUint32(cursor + constants.section64FlagsField, section.flags, true);
};

"use strict";

import { buildCodeSignature } from "./macho-codesign-sample.js";
import type { ThinMachOFixtureLayout } from "./macho-thin-types.js";

const textEncoder = new TextEncoder();

export const THIN_MACHO_FIXTURE_CONSTANTS = {
  buildMinVersion: 0x000d0000,
  buildSdkVersion: 0x000f0000,
  buildVersionCommandSize: 32,
  codeSignatureCommandSize: 16,
  cstringSectionFlags: 0x2,
  dylibCommandBaseSize: 24,
  dylinkerCommandBaseSize: 12,
  entryPointCommandSize: 24,
  headerFlagsOffset: 24,
  headerNcmdsOffset: 16,
  headerSize: 32,
  headerSizeofcmdsOffset: 20,
  linkeditSegmentSize: 72,
  machHeaderFlags: 0x00200084,
  machHeaderFileType: 0x2,
  nSect: 0x0e,
  nlist64Size: 16,
  platformMacOs: 1,
  referenceFlagUndefinedLazy: 0x0100,
  section64FlagsField: 56,
  section64OffsetField: 40,
  section64Size: 80,
  segment64Size: 72,
  segmentVmSize: 0x1000n,
  sourceVersion: 0x00000d0000200405n,
  sourceVersionCommandSize: 16,
  symtabCommandSize: 24,
  symtabOffset: 0x400,
  textSectionFlags: 0x80000400,
  textSegmentFileSize: 0x300n,
  textSectionVmaddr: 0x100000200n,
  textSegmentVmaddr: 0x100000000n,
  toolClang: 1,
  uuidCommandSize: 24,
  vmProtReadExecute: 5,
  vmProtReadWriteExecute: 7
} as const;

export type ThinMachOFixturePlan = {
  codeSignature: Uint8Array;
  codeSignatureOffset: number;
  cstringBytes: Uint8Array;
  cstringOffset: number;
  dylibBytes: Uint8Array;
  dylibCommandSize: number;
  dyldBytes: Uint8Array;
  dyldCommandSize: number;
  ncmds: number;
  sizeofcmds: number;
  stringTable: Uint8Array;
  stroff: number;
  symoff: number;
  textBytes: Uint8Array;
  textOffset: number;
};

export type ThinMachOFixtureState = {
  bytes: Uint8Array;
  layout: ThinMachOFixtureLayout;
  view: DataView;
};

const alignUp = (value: number, alignment: number): number =>
  Math.ceil(value / alignment) * alignment;

// Synthetic section filler for fixture-only payload bytes. The Mach-O tests
// assert header/layout parsing, not instruction decoding, so __text only needs
// deterministic non-zero data with a stable length.
const createSectionNoise = (length: number, seed: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  let value = seed & 0xff;
  for (let index = 0; index < length; index += 1) {
    bytes[index] = value;
    value = (value * 73 + 41) & 0xff;
  }
  return bytes;
};

export const planThinMachOFixture = (
  cpuType: number,
  identifier: string
): ThinMachOFixturePlan => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  const dylibBytes = textEncoder.encode("/usr/lib/libSystem.B.dylib\0");
  const dyldBytes = textEncoder.encode("/usr/lib/dyld\0");
  const cstringBytes = textEncoder.encode("hello\0");
  const codeSignature = buildCodeSignature(identifier, "EXAMPLE");
  const dylibCommandSize = alignUp(constants.dylibCommandBaseSize + dylibBytes.length, 8);
  const dyldCommandSize = alignUp(constants.dylinkerCommandBaseSize + dyldBytes.length, 8);
  const textSegmentSize = constants.segment64Size + constants.section64Size * 2;
  const sizeofcmds =
    textSegmentSize +
    constants.linkeditSegmentSize +
    constants.buildVersionCommandSize +
    dyldCommandSize +
    dylibCommandSize +
    constants.entryPointCommandSize +
    constants.uuidCommandSize +
    constants.sourceVersionCommandSize +
    constants.symtabCommandSize +
    constants.codeSignatureCommandSize;
  const textOffset = constants.headerSize + sizeofcmds;
  const textBytes = createSectionNoise(8, cpuType);
  const cstringOffset = textOffset + textBytes.length;
  const stringTable = textEncoder.encode("\0__mh_execute_header\0_main\0_puts\0");
  const stroff = constants.symtabOffset + 3 * constants.nlist64Size;
  return {
    codeSignature,
    codeSignatureOffset: alignUp(stroff + stringTable.length, 16),
    cstringBytes,
    cstringOffset,
    dylibBytes,
    dylibCommandSize,
    dyldBytes,
    dyldCommandSize,
    ncmds: 10,
    sizeofcmds,
    stringTable,
    stroff,
    symoff: constants.symtabOffset,
    textBytes,
    textOffset
  };
};

export const createThinMachOFixtureState = (
  plan: ThinMachOFixturePlan
): ThinMachOFixtureState => {
  const constants = THIN_MACHO_FIXTURE_CONSTANTS;
  const bytes = new Uint8Array(plan.codeSignatureOffset + plan.codeSignature.length);
  return {
    bytes,
    layout: {
      buildVersionCommandOffset: 0,
      codeSignatureCommandOffset: 0,
      codeSignatureOffset: plan.codeSignatureOffset,
      dyldCommandOffset: 0,
      dylibCommandOffset: 0,
      headerFlagsOffset: constants.headerFlagsOffset,
      headerNcmdsOffset: constants.headerNcmdsOffset,
      headerSizeofcmdsOffset: constants.headerSizeofcmdsOffset,
      headerSize: constants.headerSize,
      linkeditSegmentCommandOffset: 0,
      mainCommandOffset: 0,
      sourceVersionCommandOffset: 0,
      stroff: plan.stroff,
      symoff: plan.symoff,
      symtabCommandOffset: 0,
      textOffset: plan.textOffset,
      textSectionFlagsOffset: 0,
      textSectionOffsetFieldOffset: 0,
      textSegmentCommandOffset: 0,
      uuidCommandOffset: 0
    },
    view: new DataView(bytes.buffer)
  };
};

"use strict";

// Universal-binary directory layout comes from mach-o/fat.h:
// https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/fat.h

import { FAT_MAGIC } from "../../analyzers/macho/commands.js";
import {
  CPU_SUBTYPE_ARM64E,
  CPU_SUBTYPE_X86_64_ALL,
  CPU_TYPE_ARM64,
  CPU_TYPE_X86_64,
  createThinMachOFixture
} from "./macho-thin-sample.js";

export type UniversalMachOFixture = {
  bytes: Uint8Array;
  slice0Offset: number;
  slice1Offset: number;
};

const alignUp = (value: number, alignment: number): number =>
  Math.ceil(value / alignment) * alignment;

export const createUniversalMachOFixture = (): UniversalMachOFixture => {
  const x64Slice = createThinMachOFixture(
    CPU_TYPE_X86_64,
    CPU_SUBTYPE_X86_64_ALL,
    0x20,
    "com.example.binary101.x86_64"
  );
  const arm64Slice = createThinMachOFixture(
    CPU_TYPE_ARM64,
    CPU_SUBTYPE_ARM64E,
    0x40,
    "com.example.binary101.arm64e"
  );
  const slice0Offset = 0x1000;
  const slice1Offset = alignUp(slice0Offset + x64Slice.bytes.length, 0x1000);
  const fileSize = slice1Offset + arm64Slice.bytes.length;
  const bytes = new Uint8Array(fileSize);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, FAT_MAGIC, false);
  view.setUint32(4, 2, false);
  view.setUint32(8, CPU_TYPE_X86_64, false);
  view.setUint32(12, CPU_SUBTYPE_X86_64_ALL, false);
  view.setUint32(16, slice0Offset, false);
  view.setUint32(20, x64Slice.bytes.length, false);
  view.setUint32(24, 12, false); // 2^12 byte alignment
  view.setUint32(28, CPU_TYPE_ARM64, false);
  view.setUint32(32, CPU_SUBTYPE_ARM64E, false);
  view.setUint32(36, slice1Offset, false);
  view.setUint32(40, arm64Slice.bytes.length, false);
  view.setUint32(44, 12, false);
  bytes.set(x64Slice.bytes, slice0Offset);
  bytes.set(arm64Slice.bytes, slice1Offset);
  return { bytes, slice0Offset, slice1Offset };
};

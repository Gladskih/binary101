"use strict";

import { toHex32 } from "../../binary-utils.js";

export type ImageFileMachineEntry = [number, string, string?];

// Microsoft PE/COFF, "Machine Types":
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
export const IMAGE_FILE_MACHINE_UNKNOWN = 0x0000;
export const IMAGE_FILE_MACHINE_I386 = 0x014c;
export const IMAGE_FILE_MACHINE_ARM = 0x01c0;
export const IMAGE_FILE_MACHINE_ARMNT = 0x01c4;
export const IMAGE_FILE_MACHINE_IA64 = 0x0200;
export const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
export const IMAGE_FILE_MACHINE_ARM64 = 0xaa64;
export const IMAGE_FILE_MACHINE_ARM64EC = 0xa641;
export const IMAGE_FILE_MACHINE_ARM64X = 0xa64e;

export const IMAGE_FILE_MACHINE_TYPES: ImageFileMachineEntry[] = [
  [IMAGE_FILE_MACHINE_UNKNOWN, "UNKNOWN", "Applies to any machine type"],
  [0x0184, "Alpha AXP", "Alpha AXP, 32-bit address space"],
  [0x0284, "Alpha 64", "Alpha 64, 64-bit address space"],
  [0x01d3, "Matsushita AM33", "Embedded 32-bit CPU family"],
  [IMAGE_FILE_MACHINE_AMD64, "x86-64 (AMD64)", "x64"],
  [IMAGE_FILE_MACHINE_ARM, "ARM little-endian", "Classic 32-bit ARM code"],
  [IMAGE_FILE_MACHINE_ARM64, "ARM64", "64-bit ARM code (AArch64), little-endian"],
  [IMAGE_FILE_MACHINE_ARM64EC, "ARM64EC", "Interoperates between native ARM64 and emulated x64 code"],
  [IMAGE_FILE_MACHINE_ARM64X, "ARM64X", "Allows native ARM64 and ARM64EC code to coexist in one file"],
  [IMAGE_FILE_MACHINE_ARMNT, "ARM Thumb-2 (ARMNT)", "ARM code using the more compact Thumb-2 instructions"],
  [0x0ebc, "EFI Byte Code", "Portable EFI/UEFI bytecode not tied to one CPU family"],
  [IMAGE_FILE_MACHINE_I386, "x86 (I386)", "Intel 386 or later processors and compatible processors"],
  [IMAGE_FILE_MACHINE_IA64, "Intel Itanium (IA-64)", "Intel Itanium processor family"],
  [0x6232, "LoongArch 32-bit", "LoongArch 32-bit processor family"],
  [0x6264, "LoongArch 64-bit", "LoongArch 64-bit processor family"],
  [0x9041, "M32R", "Mitsubishi embedded CPU family, little-endian"],
  [0x0266, "MIPS16", "MIPS variant with shorter instructions to save space"],
  [0x0366, "MIPS with FPU", "MIPS target with hardware floating-point support"],
  [0x0466, "MIPS16 with FPU", "Compact-instruction MIPS target with floating-point support"],
  [0x01f0, "Power PC little-endian", "PowerPC code stored in little-endian byte order"],
  [0x01f1, "Power PC with floating point support", "PowerPC target with hardware floating-point support"],
  [0x0160, "MIPS I big-endian", "MIPS I compatible 32-bit big endian"],
  [0x0162, "MIPS I little-endian", "MIPS I compatible 32-bit little endian"],
  [0x0166, "MIPS R4000", "MIPS III compatible 64-bit little endian"],
  [0x0168, "MIPS R10000", "MIPS IV compatible 64-bit little endian"],
  [0x5032, "RISC-V32", "RISC-V 32-bit address space"],
  [0x5064, "RISC-V64", "RISC-V 64-bit address space"],
  [0x5128, "RISC-V128", "RISC-V 128-bit address space"],
  [0x01a2, "SH3", "Hitachi SH3 embedded CPU family"],
  [0x01a3, "SH3 DSP", "SH3 variant with digital signal processing extensions"],
  [0x01a6, "SH4", "Hitachi SH4 embedded CPU family"],
  [0x01a8, "SH5", "Hitachi SH5 CPU family"],
  [0x01c2, "Thumb", "ARM Thumb code: compact instructions often used to save space"],
  [0x0169, "MIPS little-endian WCE v2", "Older Windows CE target for little-endian MIPS systems"]
];

export const isKnownCoffMachine = (machine: number): boolean =>
  machine !== IMAGE_FILE_MACHINE_UNKNOWN &&
  IMAGE_FILE_MACHINE_TYPES.some(([value]) => value === (machine & 0xffff));

export const formatCoffMachine = (machine: number): string =>
  IMAGE_FILE_MACHINE_TYPES.find(([value]) => value === (machine & 0xffff))?.[1] ??
  `machine=${toHex32(machine & 0xffff, 4)}`;

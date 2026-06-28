"use strict";

// Microsoft PE format, "The TLS Directory": Characteristics bits [23:20]
// use IMAGE_SCN_ALIGN_* values; the other 28 bits are reserved.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-directory
const TLS_CHARACTERISTICS_ALIGNMENT_MASK = 0x00f00000;

export const TLS_CHARACTERISTICS_ALIGNMENT_VALUES = [
  [0x00100000, "IMAGE_SCN_ALIGN_1BYTES", 1],
  [0x00200000, "IMAGE_SCN_ALIGN_2BYTES", 2],
  [0x00300000, "IMAGE_SCN_ALIGN_4BYTES", 4],
  [0x00400000, "IMAGE_SCN_ALIGN_8BYTES", 8],
  [0x00500000, "IMAGE_SCN_ALIGN_16BYTES", 16],
  [0x00600000, "IMAGE_SCN_ALIGN_32BYTES", 32],
  [0x00700000, "IMAGE_SCN_ALIGN_64BYTES", 64],
  [0x00800000, "IMAGE_SCN_ALIGN_128BYTES", 128],
  [0x00900000, "IMAGE_SCN_ALIGN_256BYTES", 256],
  [0x00a00000, "IMAGE_SCN_ALIGN_512BYTES", 512],
  [0x00b00000, "IMAGE_SCN_ALIGN_1024BYTES", 1024],
  [0x00c00000, "IMAGE_SCN_ALIGN_2048BYTES", 2048],
  [0x00d00000, "IMAGE_SCN_ALIGN_4096BYTES", 4096],
  [0x00e00000, "IMAGE_SCN_ALIGN_8192BYTES", 8192]
] satisfies readonly (readonly [value: number, name: string, byteBoundary: number])[];

const formatHex32 = (value: number): string =>
  `0x${(value >>> 0).toString(16).padStart(8, "0")}`;

export const tlsCharacteristicsAlignmentBits = (characteristics: number): number =>
  (characteristics >>> 0) & TLS_CHARACTERISTICS_ALIGNMENT_MASK;

export const tlsCharacteristicsReservedBits = (characteristics: number): number =>
  (characteristics >>> 0) & ~TLS_CHARACTERISTICS_ALIGNMENT_MASK;

export const isKnownTlsCharacteristicsAlignment = (characteristics: number): boolean => {
  const alignment = tlsCharacteristicsAlignmentBits(characteristics);
  return alignment === 0 ||
    TLS_CHARACTERISTICS_ALIGNMENT_VALUES.some(([value]) => value === alignment);
};

export const formatTlsCharacteristicsReservedBits = (characteristics: number): string =>
  formatHex32(tlsCharacteristicsReservedBits(characteristics));

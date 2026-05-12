"use strict";

import { probeElf } from "../elf/probe.js";
import { probeMachO } from "../macho/probe.js";
import { probeByMagic } from "../probes.js";

const DOS_SIGNATURE_MZ = 0x5a4d;
const DOS_E_LFANEW_OFFSET = 0x3c;
const PE_SIGNATURE = 0x50450000;
const NE_SIGNATURE = 0x4e45;
const LE_SIGNATURE = 0x4c45;
const LX_SIGNATURE = 0x4c58;
// RFC 1952 gzip header: ID1 ID2 CM FLG MTIME XFL OS; CM=8 is deflate and FLG bits 5-7 reserved.
// https://www.rfc-editor.org/rfc/rfc1952#section-2.3.1
const GZIP_SIGNATURE = 0x1f8b;
const GZIP_DEFLATE_METHOD = 8;
const GZIP_RESERVED_FLAGS_MASK = 0xe0;
// Microsoft BITMAPFILEHEADER: "BM", bfSize, reserved words, bfOffBits, then a DIB header.
// https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader
const BMP_SIGNATURE = 0x4d42;
const BMP_FILE_HEADER_BYTES = 14;
const BMP_MIN_DIB_HEADER_BYTES = 12;
const BMP_CORE_DIMENSIONS_BYTES = 26;
const BMP_INFO_DIMENSIONS_BYTES = 30;
// Standard MIDI Files 1.0: chunks use 4-byte ASCII IDs and big-endian lengths; the
// MThd header chunk has 6 data bytes, followed by one or more MTrk track chunks.
// https://midi.org/standard-midi-files-specification
const MIDI_HEADER_SIGNATURE = 0x4d546864;
const MIDI_TRACK_SIGNATURE = 0x4d54726b;
const MIDI_CHUNK_HEADER_BYTES = 8;
const MIDI_HEADER_DATA_BYTES = 6;
const MIDI_HEADER_CHUNK_BYTES = MIDI_CHUNK_HEADER_BYTES + MIDI_HEADER_DATA_BYTES;
const MIDI_MAX_FORMAT = 2;
export const EMBEDDED_BMP_LABEL = "BMP bitmap image";
export const EMBEDDED_EXECUTABLE_LABEL = "PE/NE/LX executable";
export const EMBEDDED_MIDI_LABEL = "MIDI audio";

const hasExecutableMzSignature = (view: DataView): boolean => {
  if (view.byteLength < 0x40 || view.getUint16(0, true) !== DOS_SIGNATURE_MZ) return false;
  const headerOffset = view.getUint32(DOS_E_LFANEW_OFFSET, true);
  if (headerOffset <= 0 || headerOffset + 2 > view.byteLength) return false;
  const signature = view.getUint16(headerOffset, false);
  if (signature === NE_SIGNATURE || signature === LE_SIGNATURE || signature === LX_SIGNATURE) return true;
  return headerOffset + 4 <= view.byteLength && view.getUint32(headerOffset, false) === PE_SIGNATURE;
};

const hasValidGzipHeader = (view: DataView): boolean =>
  view.byteLength >= 10 &&
  view.getUint16(0, false) === GZIP_SIGNATURE &&
  view.getUint8(2) === GZIP_DEFLATE_METHOD &&
  (view.getUint8(3) & GZIP_RESERVED_FLAGS_MASK) === 0;

const isKnownBmpBitDepth = (bitsPerPixel: number): boolean =>
  bitsPerPixel === 1 ||
  bitsPerPixel === 4 ||
  bitsPerPixel === 8 ||
  bitsPerPixel === 16 ||
  bitsPerPixel === 24 ||
  bitsPerPixel === 32;

const hasValidCoreDibFields = (view: DataView): boolean => {
  if (view.getUint16(18, true) === 0 || view.getUint16(20, true) === 0) return false;
  if (view.getUint16(22, true) !== 1) return false;
  return isKnownBmpBitDepth(view.getUint16(24, true));
};

const hasValidInfoDibFields = (view: DataView): boolean => {
  if (view.byteLength < BMP_INFO_DIMENSIONS_BYTES) return false;
  if (view.getInt32(18, true) <= 0 || view.getInt32(22, true) === 0) return false;
  if (view.getUint16(26, true) !== 1) return false;
  return isKnownBmpBitDepth(view.getUint16(28, true));
};

export const readEmbeddedBmpFileSize = (
  view: DataView,
  remainingBytes: number
): number | null => {
  if (view.byteLength < BMP_CORE_DIMENSIONS_BYTES || view.getUint16(0, true) !== BMP_SIGNATURE) return null;
  const declaredSize = view.getUint32(2, true);
  const pixelArrayOffset = view.getUint32(10, true);
  const dibHeaderSize = view.getUint32(BMP_FILE_HEADER_BYTES, true);
  if (declaredSize < BMP_FILE_HEADER_BYTES + BMP_MIN_DIB_HEADER_BYTES || declaredSize > remainingBytes) return null;
  if (view.getUint16(6, true) !== 0 || view.getUint16(8, true) !== 0) return null;
  if (dibHeaderSize < BMP_MIN_DIB_HEADER_BYTES || BMP_FILE_HEADER_BYTES + dibHeaderSize > declaredSize) return null;
  if (pixelArrayOffset < BMP_FILE_HEADER_BYTES + dibHeaderSize || pixelArrayOffset > declaredSize) return null;
  if (dibHeaderSize === BMP_MIN_DIB_HEADER_BYTES) return hasValidCoreDibFields(view) ? declaredSize : null;
  return hasValidInfoDibFields(view) ? declaredSize : null;
};

const hasValidMidiDivision = (division: number): boolean => {
  if ((division & 0x8000) === 0) return (division & 0x7fff) > 0;
  const framesPerSecond = division >>> 8;
  const ticksPerFrame = division & 0xff;
  return ticksPerFrame > 0 &&
    (framesPerSecond === 0xe8 || framesPerSecond === 0xe7 ||
      framesPerSecond === 0xe3 || framesPerSecond === 0xe2);
};

export const readEmbeddedMidiFileSize = (
  view: DataView,
  remainingBytes: number
): number | null => {
  if (view.byteLength < MIDI_HEADER_CHUNK_BYTES || view.getUint32(0, false) !== MIDI_HEADER_SIGNATURE) return null;
  if (view.getUint32(4, false) !== MIDI_HEADER_DATA_BYTES) return null;
  const format = view.getUint16(8, false);
  const trackCount = view.getUint16(10, false);
  if (format > MIDI_MAX_FORMAT || trackCount === 0 || (format === 0 && trackCount !== 1)) return null;
  if (!hasValidMidiDivision(view.getUint16(12, false))) return null;
  let offset = MIDI_HEADER_CHUNK_BYTES;
  for (let index = 0; index < trackCount; index += 1) {
    if (offset + MIDI_CHUNK_HEADER_BYTES > view.byteLength) return null;
    if (view.getUint32(offset, false) !== MIDI_TRACK_SIGNATURE) return null;
    const trackSize = view.getUint32(offset + 4, false);
    offset += MIDI_CHUNK_HEADER_BYTES;
    if (trackSize > remainingBytes - offset) return null;
    if (trackSize > view.byteLength - offset) return null;
    offset += trackSize;
  }
  return offset;
};

export const isEmbeddedCandidateStartByte = (byteValue: number): boolean =>
  byteValue === 0x04 ||
  byteValue === 0x1f ||
  byteValue === 0x25 ||
  byteValue === 0x28 ||
  byteValue === 0x37 ||
  byteValue === 0x42 ||
  byteValue === 0x47 ||
  byteValue === 0x4d ||
  byteValue === 0x50 ||
  byteValue === 0x52 ||
  byteValue === 0x7f ||
  byteValue === 0x89 ||
  byteValue === 0xca ||
  byteValue === 0xce ||
  byteValue === 0xcf ||
  byteValue === 0xd0 ||
  byteValue === 0xfd ||
  byteValue === 0xfe;

export const detectEmbeddedCandidateType = (
  view: DataView,
  remainingBytes: number
): string | null => {
  if (!view.byteLength || !isEmbeddedCandidateStartByte(view.getUint8(0))) return null;
  if (hasValidGzipHeader(view)) return "gzip compressed data";
  const label = probeByMagic(view) || probeElf(view) || probeMachO(view, remainingBytes);
  if (label === EMBEDDED_BMP_LABEL && readEmbeddedBmpFileSize(view, remainingBytes) == null) return null;
  if (label === EMBEDDED_MIDI_LABEL && readEmbeddedMidiFileSize(view, remainingBytes) == null) return null;
  if (label && label !== "gzip compressed data") return label;
  return hasExecutableMzSignature(view) ? EMBEDDED_EXECUTABLE_LABEL : null;
};

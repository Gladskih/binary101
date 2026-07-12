"use strict";

import {
  hasValidGzipDeflateHeaderView
} from "../gzip/signature.js";
import { crc32 } from "../crc32.js";
import { hasRarSignature } from "../rar/utils.js";

const DOS_SIGNATURE_MZ = 0x5a4d;
const DOS_E_LFANEW_OFFSET = 0x3c;
const PE_SIGNATURE = 0x50450000;
const NE_SIGNATURE = 0x4e45;
const LE_SIGNATURE = 0x4c45;
const LX_SIGNATURE = 0x4c58;
// PKWARE APPNOTE, "Local file header": local headers start with 0x04034b50.
// https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
const ZIP_LOCAL_FILE_HEADER_SIGNATURE = 0x504b0304;
const ZIP_LOCAL_FILE_HEADER_BYTES = 30;
// [MS-CAB] CFHEADER starts with "MSCF" and stores cbCabinet at byte offset 8.
// https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/[ms-cab].pdf
const CAB_SIGNATURE = 0x4d534346;
const CAB_CBCABINET_OFFSET = 8;
const CAB_SIZE_READ_BYTES = 12;
const CAB_MIN_CFHEADER_BYTES = 36;
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
export const EMBEDDED_CAB_LABEL = "Microsoft Cabinet archive (CAB)";
export const EMBEDDED_EXECUTABLE_LABEL = "PE/NE/LX executable";
export const EMBEDDED_GZIP_LABEL = "gzip compressed data";
export const EMBEDDED_MIDI_LABEL = "MIDI audio";
export const EMBEDDED_RAR_LABEL = "RAR archive";
export const EMBEDDED_SEVEN_ZIP_LABEL = "7z archive";
export const EMBEDDED_ZIP_LABEL = "ZIP archive";

// 7zFormat.txt from the official LZMA SDK defines a 32-byte SignatureHeader:
// Signature, ArchiveVersion, StartHeaderCRC, NextHeaderOffset, NextHeaderSize, NextHeaderCRC.
// https://www.7-zip.org/sdk.html
const SEVEN_ZIP_SIGNATURE_BYTES = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const SEVEN_ZIP_SIGNATURE_HEADER_BYTES = 32;

const hasExecutableMzSignature = (view: DataView): boolean => {
  if (view.byteLength < 0x40 || view.getUint16(0, true) !== DOS_SIGNATURE_MZ) return false;
  const headerOffset = view.getUint32(DOS_E_LFANEW_OFFSET, true);
  if (headerOffset <= 0 || headerOffset + 2 > view.byteLength) return false;
  const signature = view.getUint16(headerOffset, false);
  if (signature === NE_SIGNATURE || signature === LE_SIGNATURE || signature === LX_SIGNATURE) return true;
  return headerOffset + 4 <= view.byteLength && view.getUint32(headerOffset, false) === PE_SIGNATURE;
};

const hasZipLocalFileHeader = (view: DataView, remainingBytes: number): boolean => {
  if (view.byteLength < ZIP_LOCAL_FILE_HEADER_BYTES || remainingBytes < ZIP_LOCAL_FILE_HEADER_BYTES) return false;
  if (view.getUint32(0, false) !== ZIP_LOCAL_FILE_HEADER_SIGNATURE) return false;
  const fileNameLength = view.getUint16(26, true);
  const extraFieldLength = view.getUint16(28, true);
  return ZIP_LOCAL_FILE_HEADER_BYTES + fileNameLength + extraFieldLength <= remainingBytes;
};

const hasSevenZipSignature = (view: DataView): boolean => {
  if (view.byteLength < SEVEN_ZIP_SIGNATURE_BYTES.length) return false;
  for (let index = 0; index < SEVEN_ZIP_SIGNATURE_BYTES.length; index += 1) {
    if (view.getUint8(index) !== SEVEN_ZIP_SIGNATURE_BYTES[index]) return false;
  }
  return true;
};

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

export const readEmbeddedCabinetFileSize = (
  view: DataView,
  remainingBytes: number
): number | null => {
  if (view.byteLength < CAB_SIZE_READ_BYTES || view.getUint32(0, false) !== CAB_SIGNATURE) return null;
  const cabinetSize = view.getUint32(CAB_CBCABINET_OFFSET, true);
  if (cabinetSize < CAB_MIN_CFHEADER_BYTES || cabinetSize > remainingBytes) return null;
  return cabinetSize;
};

export const readEmbeddedSevenZipFileSize = (
  view: DataView,
  remainingBytes: number
): number | null => {
  if (view.byteLength < SEVEN_ZIP_SIGNATURE_HEADER_BYTES || !hasSevenZipSignature(view)) return null;
  const startHeaderBytes = new Uint8Array(view.buffer, view.byteOffset + 12, 20);
  if (crc32(startHeaderBytes) !== view.getUint32(8, true)) return null;
  const nextHeaderOffset = view.getBigUint64(12, true);
  const nextHeaderSize = view.getBigUint64(20, true);
  const archiveSize = BigInt(SEVEN_ZIP_SIGNATURE_HEADER_BYTES) + nextHeaderOffset + nextHeaderSize;
  if (archiveSize > BigInt(remainingBytes) || archiveSize > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(archiveSize);
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
  byteValue === 0x1f ||
  byteValue === 0x37 ||
  byteValue === 0x42 ||
  byteValue === 0x4d ||
  byteValue === 0x50 ||
  byteValue === "R".charCodeAt(0);

export const detectEmbeddedCandidateType = (
  view: DataView,
  remainingBytes: number
): string | null => {
  if (!view.byteLength || !isEmbeddedCandidateStartByte(view.getUint8(0))) return null;
  // Overlay scanning walks arbitrary installer tails, so keep this allowlist deliberately small.
  if (hasValidGzipDeflateHeaderView(view)) return EMBEDDED_GZIP_LABEL;
  if (hasZipLocalFileHeader(view, remainingBytes)) return EMBEDDED_ZIP_LABEL;
  if (readEmbeddedCabinetFileSize(view, remainingBytes) != null) return EMBEDDED_CAB_LABEL;
  if (readEmbeddedBmpFileSize(view, remainingBytes) != null) return EMBEDDED_BMP_LABEL;
  if (readEmbeddedMidiFileSize(view, remainingBytes) != null) return EMBEDDED_MIDI_LABEL;
  if (readEmbeddedSevenZipFileSize(view, remainingBytes) != null) return EMBEDDED_SEVEN_ZIP_LABEL;
  if (hasRarSignature(view)) return EMBEDDED_RAR_LABEL;
  return hasExecutableMzSignature(view) ? EMBEDDED_EXECUTABLE_LABEL : null;
};

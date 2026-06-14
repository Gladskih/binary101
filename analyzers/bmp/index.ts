"use strict";
import type { BmpFileHeader, BmpPaletteSummary, BmpParseResult, BmpPixelArraySummary } from "./types.js";
import {
  FILE_HEADER_SIZE,
  MAX_PREFIX_BYTES,
  computeRowStride,
  isUncompressedLayout,
  parseDibHeader,
  readUint16le,
  readUint32le
} from "./bmp-parsing.js";

const MAX_ISSUES = 200;

interface BmpParserState {
  file: File;
  bytes: Uint8Array;
  issues: string[];
}

const pushBmpIssue = (issues: string[], message: string): void => {
  if (issues.length >= MAX_ISSUES) return;
  issues.push(message);
};

const ensureBmpBytes = async (state: BmpParserState, required: number): Promise<Uint8Array> => {
  if (required > MAX_PREFIX_BYTES) return state.bytes;
  if (required <= state.bytes.length) return state.bytes;
  state.bytes = new Uint8Array(await state.file.slice(0, Math.min(state.file.size, required)).arrayBuffer());
  return state.bytes;
};

const readBmpFileHeader = (state: BmpParserState): BmpFileHeader => {
  const fileHeader: BmpFileHeader = {
    signature: "BM",
    declaredFileSize: readUint32le(state.bytes, 2),
    reserved1: readUint16le(state.bytes, 6),
    reserved2: readUint16le(state.bytes, 8),
    pixelArrayOffset: readUint32le(state.bytes, 10),
    truncated: state.file.size < FILE_HEADER_SIZE
  };
  if (fileHeader.truncated) pushBmpIssue(state.issues, "BMP file header truncated (expected 14 bytes).");
  if (fileHeader.declaredFileSize != null && fileHeader.declaredFileSize !== state.file.size) {
    pushBmpIssue(
      state.issues,
      `Declared file size (bfSize=${fileHeader.declaredFileSize}) does not match actual size (${state.file.size}).`
    );
  }
  if (fileHeader.reserved1 != null && fileHeader.reserved1 !== 0) {
    pushBmpIssue(state.issues, `bfReserved1 is non-zero (${fileHeader.reserved1}).`);
  }
  if (fileHeader.reserved2 != null && fileHeader.reserved2 !== 0) {
    pushBmpIssue(state.issues, `bfReserved2 is non-zero (${fileHeader.reserved2}).`);
  }
  return fileHeader;
};

const validatePixelArrayOffset = (
  state: BmpParserState,
  pixelArrayOffset: number | null,
  minPixelOffset: number
): void => {
  if (pixelArrayOffset == null) {
    pushBmpIssue(state.issues, "Pixel array offset (bfOffBits) missing (file header truncated).");
    return;
  }
  if (pixelArrayOffset < minPixelOffset) {
    pushBmpIssue(
      state.issues,
      `Pixel array offset (bfOffBits=${pixelArrayOffset}) overlaps headers (minimum ${minPixelOffset}).`
    );
  }
  if (pixelArrayOffset > state.file.size) {
    pushBmpIssue(state.issues, `Pixel array offset (bfOffBits=${pixelArrayOffset}) points past EOF.`);
  }
};

const computePaletteExpectedEntries = (
  dibHeader: BmpParseResult["dibHeader"],
  issues: string[]
): number | null => {
  if (dibHeader.bitsPerPixel == null) return null;
  if (dibHeader.bitsPerPixel > 0 && dibHeader.bitsPerPixel <= 8) {
    const maxEntries = 1 << dibHeader.bitsPerPixel;
    if (dibHeader.colorsUsed != null && dibHeader.colorsUsed > 0) {
      if (dibHeader.colorsUsed > maxEntries) {
        pushBmpIssue(issues, `biClrUsed (${dibHeader.colorsUsed}) exceeds max palette size (${maxEntries}).`);
        return maxEntries;
      }
      return dibHeader.colorsUsed;
    }
    return maxEntries;
  }
  if (dibHeader.colorsUsed != null && dibHeader.colorsUsed > 0) return dibHeader.colorsUsed;
  return 0;
};

const buildPaletteSummary = (
  state: BmpParserState,
  dibHeader: BmpParseResult["dibHeader"],
  dibSize: number | null,
  minPixelOffset: number,
  pixelArrayOffset: number | null
): BmpPaletteSummary | null => {
  const expectedEntries = computePaletteExpectedEntries(dibHeader, state.issues);
  if (expectedEntries == null || expectedEntries <= 0) return null;
  const entrySize = dibSize != null && dibSize < 40 ? 3 : 4;
  const expectedBytes = expectedEntries * entrySize;
  const paletteLimit =
    pixelArrayOffset != null && pixelArrayOffset > minPixelOffset ? pixelArrayOffset : state.file.size;
  const availableBytes = Math.max(0, paletteLimit - minPixelOffset);
  const presentEntries = Math.floor(availableBytes / entrySize);
  const truncated = presentEntries < expectedEntries;
  if (truncated) {
    pushBmpIssue(state.issues, `Palette truncated (expected ${expectedEntries} entries, found ${presentEntries}).`);
  }
  return {
    offset: minPixelOffset,
    entrySize,
    expectedEntries,
    expectedBytes,
    presentEntries,
    availableBytes,
    truncated
  };
};

const buildPixelArraySummary = (
  fileSize: number,
  dibHeader: BmpParseResult["dibHeader"],
  pixelArrayOffset: number | null,
  issues: string[]
): BmpPixelArraySummary => {
  const rowStride = computeRowStride(dibHeader.width, dibHeader.bitsPerPixel);
  const expectedBytes =
    isUncompressedLayout(dibHeader.compression) &&
    rowStride != null &&
    dibHeader.height != null &&
    dibHeader.height > 0
      ? BigInt(rowStride) * BigInt(dibHeader.height)
      : null;
  const availableBytes = pixelArrayOffset != null && pixelArrayOffset <= fileSize
    ? Math.max(0, fileSize - pixelArrayOffset)
    : null;
  const truncated = expectedBytes != null && availableBytes != null ? BigInt(availableBytes) < expectedBytes : false;
  if (truncated) pushBmpIssue(issues, "Pixel array appears truncated (not enough bytes for declared dimensions).");
  const extraBytes = expectedBytes != null && availableBytes != null ? BigInt(availableBytes) - expectedBytes : null;
  return { offset: pixelArrayOffset, availableBytes, rowStride, expectedBytes, truncated, extraBytes };
};

const decodeLatin1 = (chunk: Uint8Array): string => {
  let out = "";
  for (const byte of chunk) out += String.fromCharCode(byte);
  return out;
};

const readBmpProfile = async (
  state: BmpParserState,
  dibHeader: BmpParseResult["dibHeader"],
  dibSize: number | null,
  minPixelOffset: number
): Promise<void> => {
  if (dibHeader.colorSpaceType !== 0x4c494e4b && dibHeader.colorSpaceType !== 0x4d424544) return;
  if (dibHeader.profileDataOffset == null || dibHeader.profileSize == null) return;
  const fileOffset = FILE_HEADER_SIZE + dibHeader.profileDataOffset;
  const truncated = fileOffset + dibHeader.profileSize > state.file.size;
  if (dibHeader.profileDataOffset < (dibSize ?? 0)) {
    pushBmpIssue(state.issues, "Profile data offset overlaps the BITMAPV5HEADER.");
  }
  if (fileOffset > state.file.size) pushBmpIssue(state.issues, "Profile data offset points past EOF.");
  if (dibHeader.profileSize === 0) pushBmpIssue(state.issues, "Profile size is zero (PROFILE_LINKED/EMBEDDED expects data).");
  const profileEnd = Math.min(state.file.size, fileOffset + dibHeader.profileSize);
  const { fileName, embeddedSignature } = await readBmpProfilePreview(
    state.file,
    fileOffset,
    dibHeader.profileSize,
    dibHeader.colorSpaceType
  );
  dibHeader.profile = {
    kind: dibHeader.colorSpaceType === 0x4c494e4b ? "linked" : "embedded",
    offsetFromHeader: dibHeader.profileDataOffset,
    fileOffset,
    size: dibHeader.profileSize,
    truncated,
    fileName: fileName || null,
    embedded: embeddedSignature ? { signature: embeddedSignature } : null
  };
  if (truncated) pushBmpIssue(state.issues, "ICC profile data truncated (file ends early).");
  if (profileEnd < minPixelOffset) pushBmpIssue(state.issues, "ICC profile data overlaps headers/palette region.");
};

const readBmpProfilePreview = async (
  file: File,
  fileOffset: number,
  profileSize: number,
  colorSpaceType: number
): Promise<{ fileName: string | null; embeddedSignature: string | null }> => {
  if (profileSize <= 0 || fileOffset >= file.size) return { fileName: null, embeddedSignature: null };
  const chunk = new Uint8Array(await file.slice(fileOffset, fileOffset + Math.min(profileSize, 256)).arrayBuffer());
  if (colorSpaceType === 0x4c494e4b) {
    const raw = decodeLatin1(chunk);
    const nul = raw.indexOf("\u0000");
    return { fileName: (nul === -1 ? raw : raw.slice(0, nul)).trim(), embeddedSignature: null };
  }
  const embeddedSignature =
    colorSpaceType === 0x4d424544 && chunk.length >= 40 ? decodeLatin1(chunk.slice(36, 40)) : null;
  return { fileName: null, embeddedSignature };
};

export const parseBmp = async (file: File): Promise<BmpParseResult | null> => {
  const issues: string[] = [];
  const pushIssue = (message: string): void => {
    pushBmpIssue(issues, message);
  };
  const state: BmpParserState = {
    file,
    bytes: new Uint8Array(await file.slice(0, Math.min(file.size, 64)).arrayBuffer()),
    issues
  };
  if (state.bytes.length < 2) return null;
  if (state.bytes[0] !== 0x42 || state.bytes[1] !== 0x4d) return null;
  const fileHeader = readBmpFileHeader(state);
  const ensureBytes = async (required: number): Promise<Uint8Array> => ensureBmpBytes(state, required);
  const parsedDib = await parseDibHeader(state.bytes, file.size, ensureBytes, pushIssue);
  const { dibSize, dibHeader, masksAfterHeaderBytes } = parsedDib;
  const minPixelOffset = FILE_HEADER_SIZE + (dibSize ?? 0) + masksAfterHeaderBytes;
  validatePixelArrayOffset(state, fileHeader.pixelArrayOffset, minPixelOffset);
  const palette = buildPaletteSummary(state, dibHeader, dibSize, minPixelOffset, fileHeader.pixelArrayOffset);
  const pixelArray = buildPixelArraySummary(file.size, dibHeader, fileHeader.pixelArrayOffset, issues);
  await readBmpProfile(state, dibHeader, dibSize, minPixelOffset);
  return {
    isBmp: true,
    fileSize: file.size,
    fileHeader,
    dibHeader,
    palette,
    pixelArray,
    issues
  };
};

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
export const parseBmp = async (file: File): Promise<BmpParseResult | null> => {
  const issues: string[] = [];
  const pushIssue = (message: string): void => {
    if (issues.length >= MAX_ISSUES) return;
    issues.push(message);
  };
  let bytes = new Uint8Array(await file.slice(0, Math.min(file.size, 64)).arrayBuffer());
  if (bytes.length < 2) return null;
  if (bytes[0] !== 0x42 || bytes[1] !== 0x4d) return null;

  const ensureBytes = async (required: number): Promise<Uint8Array> => {
    if (required > MAX_PREFIX_BYTES) return bytes;
    if (required <= bytes.length) return bytes;
    const end = Math.min(file.size, required);
    bytes = new Uint8Array(await file.slice(0, end).arrayBuffer());
    return bytes;
  };

  const fileHeader: BmpFileHeader = {
    signature: "BM",
    declaredFileSize: null,
    reserved1: null,
    reserved2: null,
    pixelArrayOffset: null,
    truncated: false
  };

  if (file.size < FILE_HEADER_SIZE) {
    fileHeader.truncated = true;
    pushIssue("BMP file header truncated (expected 14 bytes).");
  }

  fileHeader.declaredFileSize = readUint32le(bytes, 2);
  fileHeader.reserved1 = readUint16le(bytes, 6);
  fileHeader.reserved2 = readUint16le(bytes, 8);
  fileHeader.pixelArrayOffset = readUint32le(bytes, 10);

  if (fileHeader.declaredFileSize != null && fileHeader.declaredFileSize !== file.size) {
    pushIssue(
      `Declared file size (bfSize=${fileHeader.declaredFileSize}) does not match actual size (${file.size}).`
    );
  }
  if (fileHeader.reserved1 != null && fileHeader.reserved1 !== 0) {
    pushIssue(`bfReserved1 is non-zero (${fileHeader.reserved1}).`);
  }
  if (fileHeader.reserved2 != null && fileHeader.reserved2 !== 0) {
    pushIssue(`bfReserved2 is non-zero (${fileHeader.reserved2}).`);
  }

  const { dibSize, dibHeader, masksAfterHeaderBytes } = await parseDibHeader(bytes, file.size, ensureBytes, pushIssue);

  const pixelArrayOffset = fileHeader.pixelArrayOffset;
  const minPixelOffset = FILE_HEADER_SIZE + (dibSize ?? 0) + masksAfterHeaderBytes;
  if (pixelArrayOffset != null) {
    if (pixelArrayOffset < minPixelOffset) {
      pushIssue(
        `Pixel array offset (bfOffBits=${pixelArrayOffset}) overlaps headers (minimum ${minPixelOffset}).`
      );
    }
    if (pixelArrayOffset > file.size) {
      pushIssue(`Pixel array offset (bfOffBits=${pixelArrayOffset}) points past EOF.`);
    }
  } else {
    pushIssue("Pixel array offset (bfOffBits) missing (file header truncated).");
  }

  let palette: BmpPaletteSummary | null = null;
  const paletteOffset = minPixelOffset;
  const paletteEntrySize = dibSize != null && dibSize < 40 ? 3 : 4;
  const paletteExpectedEntries = (() => {
    const bitsPerPixel = dibHeader.bitsPerPixel;
    const colorsUsed = dibHeader.colorsUsed;
    if (bitsPerPixel == null) return null;
    if (bitsPerPixel > 0 && bitsPerPixel <= 8) {
      const maxEntries = 1 << bitsPerPixel;
      if (colorsUsed != null && colorsUsed > 0) {
        if (colorsUsed > maxEntries) {
          pushIssue(`biClrUsed (${colorsUsed}) exceeds max palette size (${maxEntries}).`);
          return maxEntries;
        }
        return colorsUsed;
      }
      return maxEntries;
    }
    if (colorsUsed != null && colorsUsed > 0) return colorsUsed;
    return 0;
  })();

  if (paletteExpectedEntries != null && paletteExpectedEntries > 0) {
    const expectedBytes = paletteExpectedEntries * paletteEntrySize;
    const paletteLimit = pixelArrayOffset != null && pixelArrayOffset > paletteOffset
      ? pixelArrayOffset
      : file.size;
    const availableBytes = Math.max(0, paletteLimit - paletteOffset);
    const presentEntries = Math.floor(availableBytes / paletteEntrySize);
    const truncated = presentEntries < paletteExpectedEntries;
    if (truncated) {
      pushIssue(
        `Palette truncated (expected ${paletteExpectedEntries} entries, found ${presentEntries}).`
      );
    }
    palette = {
      offset: paletteOffset,
      entrySize: paletteEntrySize,
      expectedEntries: paletteExpectedEntries,
      expectedBytes,
      presentEntries,
      availableBytes,
      truncated
    };
  }

  const rowStride = computeRowStride(dibHeader.width, dibHeader.bitsPerPixel);
  const expectedPixelBytes =
    isUncompressedLayout(dibHeader.compression) &&
    rowStride != null &&
    dibHeader.height != null &&
    dibHeader.height > 0
      ? BigInt(rowStride) * BigInt(dibHeader.height)
      : null;

  const pixelAvailableBytes =
    pixelArrayOffset != null && pixelArrayOffset <= file.size
      ? Math.max(0, file.size - pixelArrayOffset)
      : null;

  const pixelTruncated =
    expectedPixelBytes != null && pixelAvailableBytes != null
      ? BigInt(pixelAvailableBytes) < expectedPixelBytes
      : false;

  if (pixelTruncated) pushIssue("Pixel array appears truncated (not enough bytes for declared dimensions).");

  const extraBytes =
    expectedPixelBytes != null && pixelAvailableBytes != null
      ? BigInt(pixelAvailableBytes) - expectedPixelBytes
      : null;

  const pixelArray: BmpPixelArraySummary | null = {
    offset: pixelArrayOffset,
    availableBytes: pixelAvailableBytes,
    rowStride,
    expectedBytes: expectedPixelBytes,
    truncated: pixelTruncated,
    extraBytes
  };

  const decodeLatin1 = (chunk: Uint8Array): string => {
    let out = "";
    for (const byte of chunk) out += String.fromCharCode(byte);
    return out;
  };

  const profileOffsetFromHeader = dibHeader.profileDataOffset;
  const profileSize = dibHeader.profileSize;
  const profileCSType = dibHeader.colorSpaceType;
  const wantsProfile =
    profileCSType === 0x4c494e4b || profileCSType === 0x4d424544;
  if (wantsProfile && profileOffsetFromHeader != null && profileSize != null) {
    const fileOffset = FILE_HEADER_SIZE + profileOffsetFromHeader;
    const truncated = fileOffset + profileSize > file.size;
    if (profileOffsetFromHeader < (dibSize ?? 0)) {
      pushIssue("Profile data offset overlaps the BITMAPV5HEADER.");
    }
    if (fileOffset > file.size) {
      pushIssue("Profile data offset points past EOF.");
    }
    if (profileSize === 0) pushIssue("Profile size is zero (PROFILE_LINKED/EMBEDDED expects data).");

    const profileEnd = Math.min(file.size, fileOffset + profileSize);
    let fileName: string | null = null;
    let embeddedSignature: string | null = null;
    if (profileSize > 0 && fileOffset < file.size) {
      const readSize = Math.min(profileSize, 256);
      const chunk = new Uint8Array(await file.slice(fileOffset, fileOffset + readSize).arrayBuffer());
      if (profileCSType === 0x4c494e4b) {
        const raw = decodeLatin1(chunk);
        const nul = raw.indexOf("\u0000");
        fileName = (nul === -1 ? raw : raw.slice(0, nul)).trim();
      } else if (profileCSType === 0x4d424544 && chunk.length >= 40) {
        embeddedSignature = chunk[36] != null && chunk[37] != null && chunk[38] != null && chunk[39] != null
          ? decodeLatin1(chunk.slice(36, 40))
          : null;
      }
    }

    dibHeader.profile = {
      kind: profileCSType === 0x4c494e4b ? "linked" : "embedded",
      offsetFromHeader: profileOffsetFromHeader,
      fileOffset,
      size: profileSize,
      truncated,
      fileName: fileName || null,
      embedded: embeddedSignature ? { signature: embeddedSignature } : null
    };
    if (truncated) pushIssue("ICC profile data truncated (file ends early).");
    if (profileEnd < minPixelOffset) pushIssue("ICC profile data overlaps headers/palette region.");
  }

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

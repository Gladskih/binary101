"use strict";
import type {
  BmpBitmaskChannel,
  BmpBitmasks,
  BmpDibHeader,
  BmpFileHeader,
  BmpPaletteSummary,
  BmpParseResult,
  BmpPixelArraySummary
} from "./types.js";
import {
  FILE_HEADER_SIZE,
  MAX_PREFIX_BYTES,
  buildBitmaskChannel,
  computeRowStride,
  describeCompression,
  describeDibKind,
  isUncompressedLayout,
  readInt32le,
  readUint16le,
  readUint32le
} from "./bmp-parsing.js";

const DIB_SIZE_OFFSET = FILE_HEADER_SIZE;
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

  const ensureBytes = async (required: number): Promise<boolean> => {
    if (required > MAX_PREFIX_BYTES) return false;
    if (required <= bytes.length) return true;
    const end = Math.min(file.size, required);
    bytes = new Uint8Array(await file.slice(0, end).arrayBuffer());
    return bytes.length >= required;
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

  let dibSize = readUint32le(bytes, DIB_SIZE_OFFSET);
  if (dibSize == null) {
    if (file.size >= FILE_HEADER_SIZE) {
      pushIssue("DIB header size field missing (file truncated).");
    }
    dibSize = null;
  } else if (dibSize < 12) {
    pushIssue(`DIB header size is too small (${dibSize}).`);
  } else if (dibSize > MAX_PREFIX_BYTES) {
    pushIssue(`DIB header size is unusually large (${dibSize}); refusing to read full prefix.`);
  }

  const dibEnd = dibSize != null ? FILE_HEADER_SIZE + dibSize : FILE_HEADER_SIZE;
  const haveDibBytes = dibSize != null ? await ensureBytes(dibEnd) : false;
  const dibTruncated = dibSize != null ? !haveDibBytes || dibEnd > file.size : true;
  if (dibSize != null && dibEnd > file.size) {
    pushIssue("DIB header truncated (not enough bytes in file).");
  }

  let width: number | null = null;
  let height: number | null = null;
  let signedHeight: number | null = null;
  let topDown: boolean | null = null;
  let planes: number | null = null;
  let bitsPerPixel: number | null = null;
  let compression: number | null = null;
  let imageSize: number | null = null;
  let xPixelsPerMeter: number | null = null;
  let yPixelsPerMeter: number | null = null;
  let colorsUsed: number | null = null;
  let importantColors: number | null = null;
  let masks: BmpBitmasks | null = null;
  let masksAfterHeaderBytes = 0;

  if (dibSize != null && dibSize >= 12 && dibSize < 40) {
    width = readUint16le(bytes, 18);
    height = readUint16le(bytes, 20);
    signedHeight = height;
    topDown = false;
    planes = readUint16le(bytes, 22);
    bitsPerPixel = readUint16le(bytes, 24);
  } else if (dibSize != null && dibSize >= 40) {
    width = readInt32le(bytes, 18);
    signedHeight = readInt32le(bytes, 22);
    if (signedHeight != null) {
      topDown = signedHeight < 0;
      height = Math.abs(signedHeight);
    }
    planes = readUint16le(bytes, 26);
    bitsPerPixel = readUint16le(bytes, 28);
    compression = readUint32le(bytes, 30);
    imageSize = readUint32le(bytes, 34);
    xPixelsPerMeter = readInt32le(bytes, 38);
    yPixelsPerMeter = readInt32le(bytes, 42);
    colorsUsed = readUint32le(bytes, 46);
    importantColors = readUint32le(bytes, 50);

    if (dibSize >= 52) {
      const redMask = readUint32le(bytes, 54);
      const greenMask = readUint32le(bytes, 58);
      const blueMask = readUint32le(bytes, 62);
      const alphaMask = dibSize >= 56 ? readUint32le(bytes, 66) : null;
      masks = {
        red: buildBitmaskChannel(redMask),
        green: buildBitmaskChannel(greenMask),
        blue: buildBitmaskChannel(blueMask),
        alpha: buildBitmaskChannel(alphaMask)
      };
    } else if (dibSize === 40 && (compression === 3 || compression === 6)) {
      masksAfterHeaderBytes = compression === 6 ? 16 : 12;
      const required = FILE_HEADER_SIZE + dibSize + masksAfterHeaderBytes;
      await ensureBytes(required);
      const redMask = readUint32le(bytes, 54);
      const greenMask = readUint32le(bytes, 58);
      const blueMask = readUint32le(bytes, 62);
      const alphaMask = compression === 6 ? readUint32le(bytes, 66) : null;
      masks = {
        red: buildBitmaskChannel(redMask),
        green: buildBitmaskChannel(greenMask),
        blue: buildBitmaskChannel(blueMask),
        alpha: buildBitmaskChannel(alphaMask)
      };
      if (required > file.size) pushIssue("BITFIELDS masks truncated (file ends early).");
    }
  }

  if (width != null && width <= 0) pushIssue(`Width is non-positive (${width}).`);
  if (height != null && height <= 0) pushIssue(`Height is non-positive (${height}).`);
  if (planes != null && planes !== 1) pushIssue(`Planes value is unusual (${planes}); expected 1.`);

  if (masks) {
    const channels: Array<[string, BmpBitmaskChannel | null]> = [
      ["Red", masks.red],
      ["Green", masks.green],
      ["Blue", masks.blue],
      ["Alpha", masks.alpha]
    ];
    for (const [name, channel] of channels) {
      if (channel && !channel.contiguous) {
        pushIssue(`${name} mask is not a contiguous run of bits (mask=${channel.mask.toString(16)}).`);
      }
    }
  }

  const dibHeader: BmpDibHeader = {
    headerSize: dibSize,
    headerKind: describeDibKind(dibSize),
    width,
    height,
    signedHeight,
    topDown,
    planes,
    bitsPerPixel,
    compression,
    compressionName: describeCompression(compression),
    imageSize,
    xPixelsPerMeter,
    yPixelsPerMeter,
    colorsUsed,
    importantColors,
    masks,
    truncated: dibTruncated
  };

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

  const rowStride = computeRowStride(width, bitsPerPixel);
  const expectedPixelBytes =
    isUncompressedLayout(compression) && rowStride != null && height != null && height > 0
      ? BigInt(rowStride) * BigInt(height)
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

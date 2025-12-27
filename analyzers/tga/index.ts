"use strict";

import type { TgaColorMapSummary, TgaHeader, TgaImageDataSummary, TgaImageId, TgaParseResult } from "./types.js";
import {
  TGA_FOOTER_SIZE,
  TGA_HEADER_SIZE,
  computeBytesPerPixel,
  decodeOrigin,
  decodePossiblyBinaryField,
  describeColorMapType,
  describeDescriptorReservedBits,
  describeImageType,
  readUint16le,
  readUint8
} from "./tga-parsing.js";
import { parseTgaDeveloperDirectory } from "./developer-directory.js";
import { parseTgaExtensionArea } from "./extension-area.js";
import { parseTgaFooter } from "./footer.js";

const MAX_ISSUES = 200;

export const isTgaFileName = (fileName: string): boolean => {
  const lower = (fileName || "").toLowerCase();
  return (
    lower.endsWith(".tga") ||
    lower.endsWith(".targa") ||
    lower.endsWith(".icb") ||
    lower.endsWith(".vda") ||
    lower.endsWith(".vst") ||
    lower.endsWith(".tpic")
  );
};

const computeExpectedDecodedBytes = (
  width: number | null,
  height: number | null,
  bytesPerPixel: number | null
): bigint | null => {
  if (width == null || height == null || bytesPerPixel == null) return null;
  if (width <= 0 || height <= 0 || bytesPerPixel <= 0) return null;
  return BigInt(width) * BigInt(height) * BigInt(bytesPerPixel);
};

export const parseTga = async (file: File): Promise<TgaParseResult | null> => {
  const issues: string[] = [];
  const pushIssue = (message: string): void => {
    if (issues.length >= MAX_ISSUES) return;
    issues.push(message);
  };

  const headerBytes = new Uint8Array(await file.slice(0, Math.min(file.size, TGA_HEADER_SIZE)).arrayBuffer());
  const headerTruncated = headerBytes.length < TGA_HEADER_SIZE;

  const idLength = readUint8(headerBytes, 0);
  const colorMapType = readUint8(headerBytes, 1);
  const imageType = readUint8(headerBytes, 2);
  const colorMapFirstEntryIndex = readUint16le(headerBytes, 3);
  const colorMapLength = readUint16le(headerBytes, 5);
  const colorMapEntryBits = readUint8(headerBytes, 7);
  const xOrigin = readUint16le(headerBytes, 8);
  const yOrigin = readUint16le(headerBytes, 10);
  const width = readUint16le(headerBytes, 12);
  const height = readUint16le(headerBytes, 14);
  const pixelDepth = readUint8(headerBytes, 16);
  const imageDescriptor = readUint8(headerBytes, 17);

  const pixelSizeBytes = computeBytesPerPixel(pixelDepth);
  const attributeBitsPerPixel = imageDescriptor != null ? imageDescriptor & 0x0f : null;
  const origin = decodeOrigin(imageDescriptor);
  const reservedDescriptorBits = imageDescriptor != null ? imageDescriptor & 0xc0 : null;

  const footer = await parseTgaFooter(file);
  const likelyByName = isTgaFileName(file.name);
  const hasFooterSignature = footer?.present === true;

  const knownType = imageType != null && [0, 1, 2, 3, 9, 10, 11].includes(imageType);
  const plausibleHeader =
    !headerTruncated &&
    knownType &&
    width != null &&
    height != null &&
    width > 0 &&
    height > 0 &&
    pixelDepth != null &&
    pixelDepth > 0;

  if (!likelyByName && !hasFooterSignature && !plausibleHeader) return null;

  if (headerTruncated) pushIssue("TGA header truncated (expected 18 bytes).");
  if (width != null && width === 0) pushIssue("Image width is zero.");
  if (height != null && height === 0) pushIssue("Image height is zero.");
  if (reservedDescriptorBits) {
    const hint = describeDescriptorReservedBits(imageDescriptor);
    if (hint) pushIssue(`ImageDescriptor reserved bits set: ${hint}.`);
  }

  const header: TgaHeader = {
    idLength,
    colorMapType,
    colorMapTypeName: describeColorMapType(colorMapType),
    imageType,
    imageTypeName: describeImageType(imageType),
    colorMapFirstEntryIndex,
    colorMapLength,
    colorMapEntryBits,
    xOrigin,
    yOrigin,
    width,
    height,
    pixelDepth,
    pixelSizeBytes,
    imageDescriptor,
    attributeBitsPerPixel,
    origin,
    reservedDescriptorBits,
    truncated: headerTruncated
  };

  const idFieldOffset = TGA_HEADER_SIZE;
  const idFieldLength = idLength ?? 0;

  let imageId: TgaImageId | null = null;
  if (idFieldLength > 0) {
    const idEnd = Math.min(file.size, idFieldOffset + idFieldLength);
    const idBytes = new Uint8Array(await file.slice(idFieldOffset, idEnd).arrayBuffer());
    const decoded = decodePossiblyBinaryField(idBytes);
    imageId = {
      offset: idFieldOffset,
      length: idFieldLength,
      presentBytes: idBytes.length,
      text: decoded.text,
      previewHex: decoded.previewHex,
      truncated: idBytes.length < idFieldLength
    };
    if (imageId.truncated) pushIssue("Image ID field truncated (file ends early).");
  }

  const paletteEntryBytes =
    colorMapEntryBits != null && colorMapEntryBits > 0 ? Math.ceil(colorMapEntryBits / 8) : null;
  const paletteExpectedBytes =
    colorMapLength != null && paletteEntryBytes != null ? colorMapLength * paletteEntryBytes : null;
  const paletteOffset = idFieldOffset + idFieldLength;
  const paletteLimit = paletteExpectedBytes != null ? paletteOffset + paletteExpectedBytes : null;

  let colorMap: TgaColorMapSummary | null = null;
  if (colorMapType != null && colorMapType !== 0) {
    const available = paletteLimit != null ? Math.max(0, Math.min(file.size, paletteLimit) - paletteOffset) : null;
    const truncated = paletteExpectedBytes != null ? paletteOffset + paletteExpectedBytes > file.size : false;
    colorMap = {
      offset: paletteOffset,
      firstEntryIndex: colorMapFirstEntryIndex,
      lengthEntries: colorMapLength,
      entryBits: colorMapEntryBits,
      entrySizeBytes: paletteEntryBytes,
      expectedBytes: paletteExpectedBytes,
      availableBytes: available,
      truncated
    };
    if (truncated) pushIssue("Color map data truncated (file ends early).");
  } else if (
    (colorMapLength != null && colorMapLength !== 0) ||
    (colorMapFirstEntryIndex != null && colorMapFirstEntryIndex !== 0) ||
    (colorMapEntryBits != null && colorMapEntryBits !== 0)
  ) {
    pushIssue("ColorMapType is 0 but Color Map Specification fields are non-zero.");
  }

  if ((imageType === 1 || imageType === 9) && colorMapType !== 1) {
    pushIssue("Color-mapped image types expect ColorMapType=1.");
  }

  const imageDataOffset =
    paletteExpectedBytes != null ? paletteOffset + paletteExpectedBytes : paletteOffset;
  if (imageDataOffset > file.size) pushIssue("Image data offset points past EOF.");

  const expectedDecodedBytes = computeExpectedDecodedBytes(width, height, pixelSizeBytes);
  const decodedBytesHint =
    width != null && height != null && pixelSizeBytes != null && expectedDecodedBytes != null
      ? `${width} * ${height} * ${pixelSizeBytes} bytes/pixel`
      : null;

  const offsetOk = imageDataOffset <= file.size ? imageDataOffset : null;
  const endCandidates: number[] = [];
  if (footer?.present) endCandidates.push(file.size - TGA_FOOTER_SIZE);
  if (footer?.present && footer.extensionOffset && footer.extensionOffset > imageDataOffset) {
    endCandidates.push(footer.extensionOffset);
  }
  if (footer?.present && footer.developerDirectoryOffset && footer.developerDirectoryOffset > imageDataOffset) {
    endCandidates.push(footer.developerDirectoryOffset);
  }
  const imageDataEnd = endCandidates.length ? Math.min(...endCandidates) : file.size;
  const availableBytes =
    offsetOk != null && imageDataEnd >= offsetOk ? Math.max(0, imageDataEnd - offsetOk) : null;

  const uncompressedTypes = imageType === 1 || imageType === 2 || imageType === 3;
  const imageTruncated =
    uncompressedTypes && expectedDecodedBytes != null && availableBytes != null
      ? BigInt(availableBytes) < expectedDecodedBytes
      : false;
  if (imageTruncated) pushIssue("Image data appears truncated for declared dimensions and pixel depth.");

  const imageData: TgaImageDataSummary = {
    offset: offsetOk,
    availableBytes,
    expectedDecodedBytes,
    decodedBytesHint,
    truncated: imageTruncated
  };

  const version: TgaParseResult["version"] = footer?.present ? "2.0" : headerTruncated ? "unknown" : "1.0";

  const extensionArea =
    footer?.present && footer.extensionOffset
      ? await parseTgaExtensionArea(file, footer.extensionOffset, pixelSizeBytes, height, pushIssue)
      : null;

  const developerDirectory =
    footer?.present && footer.developerDirectoryOffset
      ? await parseTgaDeveloperDirectory(file, footer.developerDirectoryOffset, pushIssue)
      : null;

  if (footer?.present) {
    if (footer.extensionOffset && footer.extensionOffset < imageDataOffset) {
      pushIssue("Extension area offset overlaps header/palette region.");
    }
    if (footer.developerDirectoryOffset && footer.developerDirectoryOffset < imageDataOffset) {
      pushIssue("Developer directory offset overlaps header/palette region.");
    }
  }

  if (extensionArea?.colorCorrectionTable?.offset && extensionArea.colorCorrectionTable.offset < imageDataOffset) {
    pushIssue("Color correction table offset overlaps header/palette region.");
  }
  if (extensionArea?.scanLineTable?.offset && extensionArea.scanLineTable.offset < imageDataOffset) {
    pushIssue("Scan-line table offset overlaps header/palette region.");
  }
  if (extensionArea?.postageStamp?.offset && extensionArea.postageStamp.offset < imageDataOffset) {
    pushIssue("Postage stamp offset overlaps header/palette region.");
  }
  if (developerDirectory?.tags.some(tag => tag.dataOffset < imageDataOffset)) {
    pushIssue("Some developer tag data offsets overlap header/palette region.");
  }

  return {
    isTga: true,
    fileSize: file.size,
    version,
    header,
    imageId,
    colorMap,
    imageData,
    footer: footer || null,
    extensionArea,
    developerDirectory,
    issues
  };
};


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

const pushTgaIssue = (issues: string[], message: string): void => {
  if (issues.length >= MAX_ISSUES) return;
  issues.push(message);
};

const readImageId = async (
  file: File,
  idFieldLength: number,
  issues: string[]
): Promise<TgaImageId | null> => {
  if (idFieldLength <= 0) return null;
  const idEnd = Math.min(file.size, TGA_HEADER_SIZE + idFieldLength);
  const idBytes = new Uint8Array(await file.slice(TGA_HEADER_SIZE, idEnd).arrayBuffer());
  const decoded = decodePossiblyBinaryField(idBytes);
  const imageId: TgaImageId = {
    offset: TGA_HEADER_SIZE,
    length: idFieldLength,
    presentBytes: idBytes.length,
    text: decoded.text,
    previewHex: decoded.previewHex,
    truncated: idBytes.length < idFieldLength
  };
  if (imageId.truncated) pushTgaIssue(issues, "Image ID field truncated (file ends early).");
  return imageId;
};

const readTgaHeader = (headerBytes: Uint8Array): TgaHeader => {
  const pixelDepth = readUint8(headerBytes, 16);
  const imageDescriptor = readUint8(headerBytes, 17);
  return {
    idLength: readUint8(headerBytes, 0),
    colorMapType: readUint8(headerBytes, 1),
    colorMapTypeName: describeColorMapType(readUint8(headerBytes, 1)),
    imageType: readUint8(headerBytes, 2),
    imageTypeName: describeImageType(readUint8(headerBytes, 2)),
    colorMapFirstEntryIndex: readUint16le(headerBytes, 3),
    colorMapLength: readUint16le(headerBytes, 5),
    colorMapEntryBits: readUint8(headerBytes, 7),
    xOrigin: readUint16le(headerBytes, 8),
    yOrigin: readUint16le(headerBytes, 10),
    width: readUint16le(headerBytes, 12),
    height: readUint16le(headerBytes, 14),
    pixelDepth,
    pixelSizeBytes: computeBytesPerPixel(pixelDepth),
    imageDescriptor,
    attributeBitsPerPixel: imageDescriptor != null ? imageDescriptor & 0x0f : null,
    origin: decodeOrigin(imageDescriptor),
    reservedDescriptorBits: imageDescriptor != null ? imageDescriptor & 0xc0 : null,
    truncated: headerBytes.length < TGA_HEADER_SIZE
  };
};

const buildColorMap = (
  fileSize: number,
  header: TgaHeader,
  paletteOffset: number,
  issues: string[]
): TgaColorMapSummary | null => {
  if (header.colorMapType == null || header.colorMapType === 0) {
    warnUnexpectedColorMapFields(header, issues);
    return null;
  }
  const entryBytes = header.colorMapEntryBits != null && header.colorMapEntryBits > 0
    ? Math.ceil(header.colorMapEntryBits / 8)
    : null;
  const expectedBytes = header.colorMapLength != null && entryBytes != null ? header.colorMapLength * entryBytes : null;
  const paletteLimit = expectedBytes != null ? paletteOffset + expectedBytes : null;
  const available = paletteLimit != null ? Math.max(0, Math.min(fileSize, paletteLimit) - paletteOffset) : null;
  const truncated = expectedBytes != null ? paletteOffset + expectedBytes > fileSize : false;
  if (truncated) pushTgaIssue(issues, "Color map data truncated (file ends early).");
  return {
    offset: paletteOffset,
    firstEntryIndex: header.colorMapFirstEntryIndex,
    lengthEntries: header.colorMapLength,
    entryBits: header.colorMapEntryBits,
    entrySizeBytes: entryBytes,
    expectedBytes,
    availableBytes: available,
    truncated
  };
};

const warnUnexpectedColorMapFields = (header: TgaHeader, issues: string[]): void => {
  if (
    (header.colorMapLength != null && header.colorMapLength !== 0) ||
    (header.colorMapFirstEntryIndex != null && header.colorMapFirstEntryIndex !== 0) ||
    (header.colorMapEntryBits != null && header.colorMapEntryBits !== 0)
  ) {
    pushTgaIssue(issues, "ColorMapType is 0 but Color Map Specification fields are non-zero.");
  }
};

const buildImageData = (
  fileSize: number,
  header: TgaHeader,
  footer: Awaited<ReturnType<typeof parseTgaFooter>> | null,
  imageDataOffset: number,
  issues: string[]
): TgaImageDataSummary => {
  if (imageDataOffset > fileSize) pushTgaIssue(issues, "Image data offset points past EOF.");
  const expectedDecodedBytes = computeExpectedDecodedBytes(header.width, header.height, header.pixelSizeBytes);
  const decodedBytesHint =
    header.width != null && header.height != null && header.pixelSizeBytes != null && expectedDecodedBytes != null
      ? `${header.width} * ${header.height} * ${header.pixelSizeBytes} bytes/pixel`
      : null;
  const imageDataEnd = computeImageDataEnd(fileSize, footer, imageDataOffset);
  const availableBytes = imageDataEnd >= imageDataOffset && imageDataOffset <= fileSize
    ? Math.max(0, imageDataEnd - imageDataOffset)
    : null;
  const uncompressedTypes = header.imageType === 1 || header.imageType === 2 || header.imageType === 3;
  const truncated = uncompressedTypes && expectedDecodedBytes != null && availableBytes != null
    ? BigInt(availableBytes) < expectedDecodedBytes
    : false;
  if (truncated) pushTgaIssue(issues, "Image data appears truncated for declared dimensions and pixel depth.");
  return {
    offset: imageDataOffset <= fileSize ? imageDataOffset : null,
    availableBytes,
    expectedDecodedBytes,
    decodedBytesHint,
    truncated
  };
};

const computeImageDataEnd = (
  fileSize: number,
  footer: Awaited<ReturnType<typeof parseTgaFooter>> | null,
  imageDataOffset: number
): number => {
  const endCandidates: number[] = [];
  if (footer?.present) endCandidates.push(fileSize - TGA_FOOTER_SIZE);
  if (footer?.present && footer.extensionOffset && footer.extensionOffset > imageDataOffset) {
    endCandidates.push(footer.extensionOffset);
  }
  if (footer?.present && footer.developerDirectoryOffset && footer.developerDirectoryOffset > imageDataOffset) {
    endCandidates.push(footer.developerDirectoryOffset);
  }
  return endCandidates.length ? Math.min(...endCandidates) : fileSize;
};

const warnTgaOverlapIssues = (
  footer: Awaited<ReturnType<typeof parseTgaFooter>> | null,
  extensionArea: TgaParseResult["extensionArea"],
  developerDirectory: TgaParseResult["developerDirectory"],
  imageDataOffset: number,
  issues: string[]
): void => {
  if (footer?.extensionOffset && footer.extensionOffset < imageDataOffset) {
    pushTgaIssue(issues, "Extension area offset overlaps header/palette region.");
  }
  if (footer?.developerDirectoryOffset && footer.developerDirectoryOffset < imageDataOffset) {
    pushTgaIssue(issues, "Developer directory offset overlaps header/palette region.");
  }
  if (
    extensionArea?.colorCorrectionTable?.offset &&
    extensionArea.colorCorrectionTable.offset < imageDataOffset
  ) {
    pushTgaIssue(issues, "Color correction table offset overlaps header/palette region.");
  }
  if (extensionArea?.scanLineTable?.offset && extensionArea.scanLineTable.offset < imageDataOffset) {
    pushTgaIssue(issues, "Scan-line table offset overlaps header/palette region.");
  }
  if (extensionArea?.postageStamp?.offset && extensionArea.postageStamp.offset < imageDataOffset) {
    pushTgaIssue(issues, "Postage stamp offset overlaps header/palette region.");
  }
  if (developerDirectory?.tags.some(tag => tag.dataOffset < imageDataOffset)) {
    pushTgaIssue(issues, "Some developer tag data offsets overlap header/palette region.");
  }
};

export const parseTga = async (file: File): Promise<TgaParseResult | null> => {
  const issues: string[] = [];
  const pushIssue = (message: string): void => {
    pushTgaIssue(issues, message);
  };

  const headerBytes = new Uint8Array(await file.slice(0, Math.min(file.size, TGA_HEADER_SIZE)).arrayBuffer());
  const headerTruncated = headerBytes.length < TGA_HEADER_SIZE;

  const header = readTgaHeader(headerBytes);
  const footer = await parseTgaFooter(file);
  const likelyByName = isTgaFileName(file.name);
  const hasFooterSignature = footer?.present === true;

  const knownType = header.imageType != null && [0, 1, 2, 3, 9, 10, 11].includes(header.imageType);
  const plausibleHeader =
    !headerTruncated &&
    knownType &&
    header.width != null &&
    header.height != null &&
    header.width > 0 &&
    header.height > 0 &&
    header.pixelDepth != null &&
    header.pixelDepth > 0;

  if (!likelyByName && !hasFooterSignature && !plausibleHeader) return null;

  if (headerTruncated) pushIssue("TGA header truncated (expected 18 bytes).");
  if (header.width != null && header.width === 0) pushIssue("Image width is zero.");
  if (header.height != null && header.height === 0) pushIssue("Image height is zero.");
  if (header.reservedDescriptorBits) {
    const hint = describeDescriptorReservedBits(header.imageDescriptor);
    if (hint) pushIssue(`ImageDescriptor reserved bits set: ${hint}.`);
  }

  const idFieldLength = header.idLength ?? 0;
  const imageId = await readImageId(file, idFieldLength, issues);
  const paletteEntryBytes =
    header.colorMapEntryBits != null && header.colorMapEntryBits > 0 ? Math.ceil(header.colorMapEntryBits / 8) : null;
  const paletteExpectedBytes =
    header.colorMapLength != null && paletteEntryBytes != null ? header.colorMapLength * paletteEntryBytes : null;
  const paletteOffset = TGA_HEADER_SIZE + idFieldLength;
  const colorMap = buildColorMap(file.size, header, paletteOffset, issues);

  if ((header.imageType === 1 || header.imageType === 9) && header.colorMapType !== 1) {
    pushIssue("Color-mapped image types expect ColorMapType=1.");
  }

  const imageDataOffset =
    paletteExpectedBytes != null ? paletteOffset + paletteExpectedBytes : paletteOffset;
  const imageData = buildImageData(file.size, header, footer, imageDataOffset, issues);

  const version: TgaParseResult["version"] = footer?.present ? "2.0" : headerTruncated ? "unknown" : "1.0";

  const extensionArea =
    footer?.present && footer.extensionOffset
      ? await parseTgaExtensionArea(file, footer.extensionOffset, header.pixelSizeBytes, header.height, pushIssue)
      : null;

  const developerDirectory =
    footer?.present && footer.developerDirectoryOffset
      ? await parseTgaDeveloperDirectory(file, footer.developerDirectoryOffset, pushIssue)
      : null;

  warnTgaOverlapIssues(footer, extensionArea, developerDirectory, imageDataOffset, issues);

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


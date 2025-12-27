"use strict";

export type TgaHeader = {
  idLength: number | null;
  colorMapType: number | null;
  colorMapTypeName: string | null;
  imageType: number | null;
  imageTypeName: string | null;
  colorMapFirstEntryIndex: number | null;
  colorMapLength: number | null;
  colorMapEntryBits: number | null;
  xOrigin: number | null;
  yOrigin: number | null;
  width: number | null;
  height: number | null;
  pixelDepth: number | null;
  pixelSizeBytes: number | null;
  imageDescriptor: number | null;
  attributeBitsPerPixel: number | null;
  origin: string | null;
  reservedDescriptorBits: number | null;
  truncated: boolean;
};

export type TgaImageId = {
  offset: number;
  length: number;
  presentBytes: number;
  text: string | null;
  previewHex: string | null;
  truncated: boolean;
};

export type TgaColorMapSummary = {
  offset: number;
  firstEntryIndex: number | null;
  lengthEntries: number | null;
  entryBits: number | null;
  entrySizeBytes: number | null;
  expectedBytes: number | null;
  availableBytes: number | null;
  truncated: boolean;
};

export type TgaImageDataSummary = {
  offset: number | null;
  availableBytes: number | null;
  expectedDecodedBytes: bigint | null;
  decodedBytesHint: string | null;
  truncated: boolean;
};

export type TgaFooter = {
  present: boolean;
  extensionOffset: number | null;
  developerDirectoryOffset: number | null;
  signature: string | null;
  truncated: boolean;
};

export type TgaScanLineTableSummary = {
  offset: number;
  expectedBytes: number | null;
  truncated: boolean;
};

export type TgaColorCorrectionTableSummary = {
  offset: number;
  expectedBytes: number;
  truncated: boolean;
};

export type TgaPostageStampSummary = {
  offset: number;
  width: number | null;
  height: number | null;
  expectedBytes: number | null;
  truncated: boolean;
};

export type TgaExtensionArea = {
  offset: number;
  size: number | null;
  authorName: string | null;
  authorComment: string | null;
  timestamp: string | null;
  jobName: string | null;
  jobTime: string | null;
  softwareId: string | null;
  softwareVersion: string | null;
  keyColor: number | null;
  pixelAspectRatio: number | null;
  gamma: number | null;
  colorCorrectionTable: TgaColorCorrectionTableSummary | null;
  postageStamp: TgaPostageStampSummary | null;
  scanLineTable: TgaScanLineTableSummary | null;
  attributesType: number | null;
  truncated: boolean;
};

export type TgaDeveloperTag = {
  tagNumber: number;
  dataOffset: number;
  dataSize: number;
  truncated: boolean;
};

export type TgaDeveloperDirectory = {
  offset: number;
  tagCount: number | null;
  tags: TgaDeveloperTag[];
  truncated: boolean;
};

export type TgaParseResult = {
  isTga: true;
  fileSize: number;
  version: "1.0" | "2.0" | "unknown";
  header: TgaHeader;
  imageId: TgaImageId | null;
  colorMap: TgaColorMapSummary | null;
  imageData: TgaImageDataSummary;
  footer: TgaFooter | null;
  extensionArea: TgaExtensionArea | null;
  developerDirectory: TgaDeveloperDirectory | null;
  issues: string[];
};


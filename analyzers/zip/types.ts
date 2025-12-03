"use strict";

export interface ZipEndOfCentralDirectory {
  offset: number;
  diskNumber: number;
  centralDirDisk: number;
  entriesThisDisk: number;
  totalEntries: number;
  centralDirSize: number;
  centralDirOffset: number;
  comment: string;
  commentLength: number;
}

export interface Zip64Locator {
  offset: number;
  diskWithEocd: number;
  zip64EocdOffset: bigint;
  totalDisks: number;
}

export interface Zip64EndOfCentralDirectory {
  offset: number;
  size: number;
  versionMadeBy: number;
  versionNeeded: number;
  diskNumber: number;
  centralDirDisk: number;
  entriesThisDisk: bigint;
  totalEntries: bigint;
  centralDirSize: bigint;
  centralDirOffset: bigint;
}

export interface ZipCentralDirectoryEntryLocalHeaderInfo {
  nameLength: number;
  extraLength: number;
  offset: number;
}

export interface ZipCentralDirectoryEntry {
  index: number;
  fileName: string;
  comment: string;
  compressionMethod: number;
  compressionName: string;
  flags: number;
  isUtf8: boolean;
  isEncrypted: boolean;
  usesDataDescriptor: boolean;
  modTimeIso: string | null;
  crc32: number;
  compressedSize: number | bigint;
  uncompressedSize: number | bigint;
  diskNumberStart: number;
  internalAttrs: number;
  externalAttrs: number;
  localHeaderOffset: number | bigint;
  localHeader?: ZipCentralDirectoryEntryLocalHeaderInfo;
  dataOffset?: number;
  dataLength?: number | null;
  dataEnd?: number | null;
  extractError?: string;
}

export interface ZipCentralDirectoryInfo {
  offset: number;
  size: number;
  parsedSize: number;
  truncated: boolean;
  entries: ZipCentralDirectoryEntry[];
}

export interface ZipParseResult {
  eocd: ZipEndOfCentralDirectory;
  zip64Locator: Zip64Locator | null;
  zip64: Zip64EndOfCentralDirectory | null;
  centralDirectory: ZipCentralDirectoryInfo | null;
  issues: string[];
}

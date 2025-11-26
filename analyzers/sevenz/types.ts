"use strict";

export interface SevenZipContext {
  dv: DataView;
  offset: number;
  issues: string[];
  // Additional helpers may attach scratch properties; keep them flexible.
  [key: string]: unknown;
}

export interface SevenZipDigest {
  index: number;
  crc: number;
}

export interface SevenZipDigestsInfo {
  digests: SevenZipDigest[];
  allDefined?: boolean;
  definedFlags?: boolean[];
}

export interface SevenZipCoder {
  id: string;
  methodId: string;
  numInStreams: number;
  numOutStreams: number;
  properties: unknown | null;
  archHint?: string;
  isEncryption: boolean;
}

export interface SevenZipFolderCoderRecord {
  methodId: string;
  inStreams: number;
  outStreams: number;
  propertiesSize: number;
  properties: unknown | null;
}

export interface SevenZipBindPair {
  inIndex: bigint | null;
  outIndex: bigint | null;
}

export interface SevenZipFolderParseResult {
  coders: SevenZipFolderCoderRecord[];
  totalInStreams: number;
  totalOutStreams: number;
  bindPairs: SevenZipBindPair[];
  packedStreams: Array<bigint | null>;
  numPackedStreams: number;
  numBindPairs: number;
  numOutStreams: number;
}

export interface SevenZipSubstream {
  size: bigint | null;
  crc: number | null;
}

export interface SevenZipFolderSummary {
  index: number;
  unpackSize: bigint | null;
  packedSize: bigint | null;
  coders: SevenZipCoder[];
  numUnpackStreams: number;
  substreams: SevenZipSubstream[];
  isEncrypted: boolean;
}

export interface SevenZipHeaderFolder {
  index: number;
  coders: SevenZipCoder[];
  isEncrypted: boolean;
}

export interface SevenZipFileSummary {
  index: number;
  name: string;
  folderIndex: number | null;
  uncompressedSize: bigint | number | null;
  packedSize: bigint | number | null;
  compressionRatio: number | null;
  crc32: number | null;
  modifiedTime: string | null;
  attributes: string | null;
  hasStream?: boolean;
  isEmptyStream?: boolean;
  isEmptyFile?: boolean;
  isDirectory?: boolean;
  isAnti?: boolean;
  isEncrypted?: boolean;
  isEmpty?: boolean;
}

export interface SevenZipArchiveFlags {
  isSolid: boolean;
  isHeaderEncrypted: boolean;
  hasEncryptedContent: boolean;
}

export interface SevenZipStructure {
  archiveFlags: SevenZipArchiveFlags;
  folders: SevenZipFolderSummary[];
  files: SevenZipFileSummary[];
}

export interface SevenZipArchiveProperties {
  count: number;
}

export interface SevenZipStartHeader {
  versionMajor: number;
  versionMinor: number;
  startHeaderCrc: number;
  nextHeaderOffset: bigint;
  nextHeaderSize: bigint;
  nextHeaderCrc: number;
  absoluteNextHeaderOffset: bigint;
}

export interface SevenZipNextHeaderInfo {
  offset: bigint;
  size: bigint;
  crc: number;
  parsed: SevenZipParsedNextHeader;
}

export interface SevenZipHeaderEncoding {
  coders: SevenZipHeaderFolder[];
  hasEncryptedHeader: boolean;
}

export interface SevenZipPackInfo {
  packPos: bigint | null;
  numPackStreams: bigint | null;
  packSizes: bigint[];
  packCrcs: SevenZipDigest[];
}

export interface SevenZipUnpackInfo {
  external: boolean;
  folders: SevenZipFolderParseResult[];
  unpackSizes?: Array<Array<bigint | null>>;
  folderCrcs?: SevenZipDigestsInfo;
}

export interface SevenZipSubStreamsInfo {
  numUnpackStreams: Array<bigint | number | null | undefined>;
  substreamSizes?: Array<bigint | null>;
  substreamCrcs?: SevenZipDigestsInfo;
}

export interface SevenZipStreamsInfo {
  packInfo?: SevenZipPackInfo;
  unpackInfo?: SevenZipUnpackInfo;
  subStreamsInfo?: SevenZipSubStreamsInfo;
}

export interface SevenZipFileInfoEntry {
  index: number;
  hasStream?: boolean;
  isEmptyStream?: boolean;
  isEmptyFile?: boolean;
  isAnti?: boolean;
  name?: string;
  modifiedTime?: string | null;
  attributes?: string;
  isDirectory?: boolean;
}

export interface SevenZipFilesInfo {
  fileCount: number | null;
  files: Array<SevenZipFileInfoEntry | SevenZipFileSummary>;
  hasNames?: boolean;
  hasModificationTimes?: boolean;
}

export interface SevenZipHeaderSections {
  archiveProperties?: SevenZipArchiveProperties;
  additionalStreamsInfo?: SevenZipStreamsInfo;
  mainStreamsInfo?: SevenZipStreamsInfo;
  filesInfo?: SevenZipFilesInfo;
}

export type SevenZipParsedNextHeader =
  | { kind: "header"; sections: SevenZipHeaderSections }
  | { kind: "encoded"; headerStreams: SevenZipStreamsInfo; headerCoders: SevenZipHeaderFolder[]; hasEncryptedHeader: boolean }
  | { kind: "empty" }
  | { kind: "unknown"; type?: number };

export interface SevenZipParseResult {
  is7z: boolean;
  startHeader?: SevenZipStartHeader;
  nextHeader?: SevenZipNextHeaderInfo;
  structure?: SevenZipStructure;
  headerEncoding?: SevenZipHeaderEncoding;
  issues: string[];
}

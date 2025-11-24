"use strict";

export interface TarEntry {
  index: number;
  name: string;
  rawName: string;
  prefix: string;
  typeFlag: string;
  typeLabel: string;
  size: number;
  mode: number | null;
  modeSymbolic: string | null;
  modeOctal: string | null;
  uid: number | null;
  gid: number | null;
  uname: string | null;
  gname: string | null;
  linkName: string | null;
  devMajor: number | null;
  devMinor: number | null;
  mtime: number | null;
  mtimeIso: string;
  checksum: number | null;
  checksumComputed: number | null;
  checksumValid: boolean | null;
  dataOffset: number;
  blocks: number;
  usesLongName?: boolean;
  usesLongLink?: boolean;
  usedPaxPath?: boolean;
  hasPax?: boolean;
  paxKeys?: string[];
}

export interface TarStats {
  totalEntries: number;
  regularFiles: number;
  directories: number;
  symlinks: number;
  metadataEntries: number;
  totalFileBytes: number;
  blocksConsumed: number;
  truncatedEntries: number;
}

export interface TarFeatures {
  usedLongNames: boolean;
  usedLongLinks: boolean;
  usedPaxHeaders: boolean;
  usedGlobalPax: boolean;
  checksumMismatches: number;
}

export interface TarFormatInfo {
  kind?: string;
  label?: string;
  magic?: string;
  version?: string;
}

export interface TarParseResult {
  isTar: boolean;
  blockSize: number;
  blockCount: number;
  fileSize: number;
  format: TarFormatInfo;
  entries: TarEntry[];
  stats: TarStats;
  features: TarFeatures;
  terminatorBlocks: number;
  issues: string[];
}


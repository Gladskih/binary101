"use strict";

import {
  isPeImportMetadataEntry,
  isPlainNumber,
  isPlainRecord,
  isPlainString,
  type PeImportMetadataEntry
} from "./pe-import-metadata-schema.js";

export const UCRT_METADATA_FORMAT_VERSION = 2;

export interface UcrtMetadataSource {
  headerPackageName: string;
  importLibraryPackageName: string;
  packageVersion: string;
  headerRoot: string;
  importLibraryPath: string;
  architecture: string;
}

export interface UcrtMetadataEntryCounts {
  dlls: number;
  entries: number;
}

export interface UcrtMetadataManifestChunk {
  dll: string;
  moduleKey: string;
  path: string;
  entries: number;
}

export interface UcrtMetadataManifest {
  formatVersion: typeof UCRT_METADATA_FORMAT_VERSION;
  generatedAt: string;
  source: UcrtMetadataSource;
  entryCounts: UcrtMetadataEntryCounts;
  chunks: UcrtMetadataManifestChunk[];
}

export type UcrtMetadataEntry = PeImportMetadataEntry & { sourceKind: "ucrt" };

export interface UcrtMetadataChunk {
  formatVersion: typeof UCRT_METADATA_FORMAT_VERSION;
  generatedAt: string;
  source: UcrtMetadataSource;
  dll: string;
  moduleKey: string;
  entryCount: number;
  entries: Record<string, UcrtMetadataEntry>;
}

const isRecord = isPlainRecord;
const isString = isPlainString;
const isNumber = isPlainNumber;

const hasFormatVersion = (value: Record<string, unknown>): boolean =>
  value["formatVersion"] === UCRT_METADATA_FORMAT_VERSION;

const isSource = (value: unknown): value is UcrtMetadataSource =>
  isRecord(value) &&
  isString(value["headerPackageName"]) &&
  isString(value["importLibraryPackageName"]) &&
  isString(value["packageVersion"]) &&
  isString(value["headerRoot"]) &&
  isString(value["importLibraryPath"]) &&
  isString(value["architecture"]);

const isEntryCounts = (value: unknown): value is UcrtMetadataEntryCounts =>
  isRecord(value) && isNumber(value["dlls"]) && isNumber(value["entries"]);

const isManifestChunk = (value: unknown): value is UcrtMetadataManifestChunk =>
  isRecord(value) &&
  isString(value["dll"]) &&
  isString(value["moduleKey"]) &&
  isString(value["path"]) &&
  isNumber(value["entries"]);

export const isUcrtMetadataManifest = (value: unknown): value is UcrtMetadataManifest =>
  isRecord(value) &&
  hasFormatVersion(value) &&
  isString(value["generatedAt"]) &&
  isSource(value["source"]) &&
  isEntryCounts(value["entryCounts"]) &&
  Array.isArray(value["chunks"]) &&
  value["chunks"].every(isManifestChunk);

const isEntry = (value: unknown): value is UcrtMetadataEntry =>
  isPeImportMetadataEntry(value) && value.sourceKind === "ucrt";

const isEntryRecord = (value: unknown): value is Record<string, UcrtMetadataEntry> =>
  isRecord(value) && Object.values(value).every(isEntry);

export const isUcrtMetadataChunk = (value: unknown): value is UcrtMetadataChunk =>
  isRecord(value) &&
  hasFormatVersion(value) &&
  isString(value["generatedAt"]) &&
  isSource(value["source"]) &&
  isString(value["dll"]) &&
  isString(value["moduleKey"]) &&
  isNumber(value["entryCount"]) &&
  isEntryRecord(value["entries"]);

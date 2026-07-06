"use strict";

import {
  isPeImportMetadataEntry,
  isPlainNumber as isNumber,
  isPlainRecord as isRecord,
  isPlainString as isString,
  isPlainStringArray as isStringArray,
  type PeImportMetadataEntry,
  type PeImportMetadataParameter
} from "./pe-import-metadata-schema.js";

export const WINAPI_METADATA_FORMAT_VERSION = 2;

export interface WinapiMetadataSource {
  packageName: string;
  packageVersion: string;
  fileName: string;
}

export interface WinapiMetadataEntryCounts {
  dlls: number;
  entries: number;
}

export interface WinapiMetadataEntrypointIndexInfo {
  path: string;
  entries: number;
  references: number;
}

export interface WinapiMetadataManifestChunk {
  dll: string;
  moduleKey: string;
  path: string;
  entries: number;
}

export interface WinapiMetadataManifest {
  formatVersion: typeof WINAPI_METADATA_FORMAT_VERSION;
  generatedAt: string;
  source: WinapiMetadataSource;
  entryCounts: WinapiMetadataEntryCounts;
  entrypointIndex: WinapiMetadataEntrypointIndexInfo;
  chunks: WinapiMetadataManifestChunk[];
}

export type WinapiMetadataParameter = PeImportMetadataParameter;

export type WinapiMetadataEntry = PeImportMetadataEntry & { sourceKind: "winapi" };

export interface WinapiMetadataChunk {
  formatVersion: typeof WINAPI_METADATA_FORMAT_VERSION;
  generatedAt: string;
  source: WinapiMetadataSource;
  dll: string;
  moduleKey: string;
  entryCount: number;
  entries: Record<string, WinapiMetadataEntry>;
}

export interface WinapiMetadataEntrypointIndex {
  formatVersion: typeof WINAPI_METADATA_FORMAT_VERSION;
  generatedAt: string;
  source: WinapiMetadataSource;
  entryCount: number;
  referenceCount: number;
  entries: Record<string, string[]>;
}

const isSource = (value: unknown): value is WinapiMetadataSource =>
  isRecord(value) &&
  isString(value["packageName"]) &&
  isString(value["packageVersion"]) &&
  isString(value["fileName"]);

const hasFormatVersion = (value: Record<string, unknown>): boolean =>
  value["formatVersion"] === WINAPI_METADATA_FORMAT_VERSION;

const isEntryCounts = (value: unknown): value is WinapiMetadataEntryCounts =>
  isRecord(value) && isNumber(value["dlls"]) && isNumber(value["entries"]);

const isManifestChunk = (value: unknown): value is WinapiMetadataManifestChunk =>
  isRecord(value) &&
  isString(value["dll"]) &&
  isString(value["moduleKey"]) &&
  isString(value["path"]) &&
  isNumber(value["entries"]);

const isEntrypointIndexInfo = (value: unknown): value is WinapiMetadataEntrypointIndexInfo =>
  isRecord(value) &&
  isString(value["path"]) &&
  isNumber(value["entries"]) &&
  isNumber(value["references"]);

export const isWinapiMetadataManifest = (value: unknown): value is WinapiMetadataManifest =>
  isRecord(value) &&
  hasFormatVersion(value) &&
  isString(value["generatedAt"]) &&
  isSource(value["source"]) &&
  isEntryCounts(value["entryCounts"]) &&
  isEntrypointIndexInfo(value["entrypointIndex"]) &&
  Array.isArray(value["chunks"]) &&
  value["chunks"].every(isManifestChunk);

const isEntry = (value: unknown): value is WinapiMetadataEntry =>
  isPeImportMetadataEntry(value) && value.sourceKind === "winapi";

const isEntryRecord = (value: unknown): value is Record<string, WinapiMetadataEntry> =>
  isRecord(value) && Object.values(value).every(isEntry);

export const isWinapiMetadataChunk = (value: unknown): value is WinapiMetadataChunk =>
  isRecord(value) &&
  hasFormatVersion(value) &&
  isString(value["generatedAt"]) &&
  isSource(value["source"]) &&
  isString(value["dll"]) &&
  isString(value["moduleKey"]) &&
  isNumber(value["entryCount"]) &&
  isEntryRecord(value["entries"]);

export const isWinapiMetadataEntrypointIndex = (
  value: unknown
): value is WinapiMetadataEntrypointIndex =>
  isRecord(value) &&
  hasFormatVersion(value) &&
  isString(value["generatedAt"]) &&
  isSource(value["source"]) &&
  isNumber(value["entryCount"]) &&
  isNumber(value["referenceCount"]) &&
  isRecord(value["entries"]) &&
  Object.values(value["entries"]).every(isStringArray);

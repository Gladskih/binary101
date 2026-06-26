"use strict";

export const WINAPI_METADATA_FORMAT_VERSION = 1;

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

export interface WinapiMetadataParameter {
  name: string | null;
  type: string;
  rawType: string | null;
  x86StackBytes: number | null;
}

export interface WinapiMetadataEntry {
  id: string;
  module: string;
  entrypoint: string;
  namespace: string | null;
  api: string;
  signature: string;
  returnType: string;
  rawReturnType: string | null;
  parameters: WinapiMetadataParameter[];
  callingConvention: string;
  x86StackBytes: number | null;
  variadic: boolean;
  setLastError: boolean;
  characterSet: string | null;
  architecture: string[];
  platform: string[];
}

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

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isString = (value: unknown): value is string => typeof value === "string";

const isStringOrNull = (value: unknown): value is string | null =>
  value === null || isString(value);

const isNumber = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value);

const isNumberOrNull = (value: unknown): value is number | null =>
  value === null || isNumber(value);

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every(isString);

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

const isParameter = (value: unknown): value is WinapiMetadataParameter =>
  isRecord(value) &&
  isStringOrNull(value["name"]) &&
  isString(value["type"]) &&
  isStringOrNull(value["rawType"]) &&
  isNumberOrNull(value["x86StackBytes"]);

const isEntry = (value: unknown): value is WinapiMetadataEntry =>
  isRecord(value) &&
  isString(value["id"]) &&
  isString(value["module"]) &&
  isString(value["entrypoint"]) &&
  isStringOrNull(value["namespace"]) &&
  isString(value["api"]) &&
  isString(value["signature"]) &&
  isString(value["returnType"]) &&
  isStringOrNull(value["rawReturnType"]) &&
  Array.isArray(value["parameters"]) &&
  value["parameters"].every(isParameter) &&
  isString(value["callingConvention"]) &&
  isNumberOrNull(value["x86StackBytes"]) &&
  typeof value["variadic"] === "boolean" &&
  typeof value["setLastError"] === "boolean" &&
  isStringOrNull(value["characterSet"]) &&
  isStringArray(value["architecture"]) &&
  isStringArray(value["platform"]);

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

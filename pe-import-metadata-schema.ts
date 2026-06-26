"use strict";

export type PeImportMetadataSourceKind = "winapi" | "ucrt";

export interface PeImportMetadataParameter {
  name: string | null;
  type: string;
  rawType: string | null;
  x86StackBytes: number | null;
}

export interface PeImportMetadataEntry {
  sourceKind: PeImportMetadataSourceKind;
  id: string;
  module: string;
  entrypoint: string;
  namespace: string | null;
  api: string;
  signature: string;
  returnType: string;
  rawReturnType: string | null;
  parameters: PeImportMetadataParameter[];
  callingConvention: string;
  x86StackBytes: number | null;
  variadic: boolean;
  setLastError: boolean;
  characterSet: string | null;
  architecture: string[];
  platform: string[];
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

const isSourceKind = (value: unknown): value is PeImportMetadataSourceKind =>
  value === "winapi" || value === "ucrt";

export const isPeImportMetadataParameter = (
  value: unknown
): value is PeImportMetadataParameter =>
  isRecord(value) &&
  isStringOrNull(value["name"]) &&
  isString(value["type"]) &&
  isStringOrNull(value["rawType"]) &&
  isNumberOrNull(value["x86StackBytes"]);

export const isPeImportMetadataEntry = (value: unknown): value is PeImportMetadataEntry =>
  isRecord(value) &&
  isSourceKind(value["sourceKind"]) &&
  isString(value["id"]) &&
  isString(value["module"]) &&
  isString(value["entrypoint"]) &&
  isStringOrNull(value["namespace"]) &&
  isString(value["api"]) &&
  isString(value["signature"]) &&
  isString(value["returnType"]) &&
  isStringOrNull(value["rawReturnType"]) &&
  Array.isArray(value["parameters"]) &&
  value["parameters"].every(isPeImportMetadataParameter) &&
  isString(value["callingConvention"]) &&
  isNumberOrNull(value["x86StackBytes"]) &&
  typeof value["variadic"] === "boolean" &&
  typeof value["setLastError"] === "boolean" &&
  isStringOrNull(value["characterSet"]) &&
  isStringArray(value["architecture"]) &&
  isStringArray(value["platform"]);

export const isPeImportMetadataEntryRecord = (
  value: unknown
): value is Record<string, PeImportMetadataEntry> =>
  isRecord(value) && Object.values(value).every(isPeImportMetadataEntry);

export const isPlainRecord = isRecord;
export const isPlainString = isString;
export const isPlainNumber = isNumber;
export const isPlainStringArray = isStringArray;

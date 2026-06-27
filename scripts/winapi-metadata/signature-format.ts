"use strict";

import type { PeClrMetadataTables, PeClrMethodDefinitionInfo } from "../../analyzers/pe/clr/types.js";
import type { WinapiMetadataParameter } from "../../winapi-metadata-schema.js";

const TYPE_REFERENCE_PATTERN = /\b(TypeDef|TypeRef)#(\d+)\b/g;
const VALUE_TYPE_PREFIX = "valuetype ";
const CLASS_PREFIX = "class ";
const PARAM_IN_FLAG = 0x0001;
const PARAM_OUT_FLAG = 0x0002;

const STACK_BYTES_BY_TYPE: Record<string, number> = {
  bool: 4,
  char: 4,
  i1: 4,
  u1: 4,
  i2: 4,
  u2: 4,
  i4: 4,
  u4: 4,
  i8: 8,
  u8: 8,
  r4: 4,
  r8: 8,
  string: 4,
  object: 4,
  "native int": 4,
  "native uint": 4
};

const resolveMetadataTypeReference = (
  kind: string,
  rowText: string,
  tables: PeClrMetadataTables
): string => {
  const row = Number(rowText);
  if (!Number.isInteger(row) || row <= 0) return `${kind}#${rowText}`;
  if (kind === "TypeRef") return tables.typeRefs[row - 1]?.fullName ?? `${kind}#${row}`;
  return tables.typeDefs[row - 1]?.fullName ?? `${kind}#${row}`;
};

export const resolveSignatureType = (
  rawType: string | null | undefined,
  tables: PeClrMetadataTables
): string => {
  if (!rawType) return "?";
  return rawType
    .replace(TYPE_REFERENCE_PATTERN, (_match, kind: string, rowText: string) =>
      resolveMetadataTypeReference(kind, rowText, tables))
    .replaceAll(VALUE_TYPE_PREFIX, "")
    .replaceAll(CLASS_PREFIX, "");
};

const x86StackBytesForType = (rawType: string | null | undefined): number | null => {
  if (!rawType) return null;
  if (rawType.includes("*") || rawType.includes("&") || rawType.startsWith(CLASS_PREFIX)) return 4;
  const withoutPrefixes = rawType.replaceAll(VALUE_TYPE_PREFIX, "").replaceAll(CLASS_PREFIX, "");
  if (withoutPrefixes.startsWith("TypeDef#") || withoutPrefixes.startsWith("TypeRef#")) return null;
  return STACK_BYTES_BY_TYPE[withoutPrefixes] ?? null;
};

const parameterName = (method: PeClrMethodDefinitionInfo, index: number): string | null =>
  method.parameters?.find(parameter => parameter.sequence === index + 1)?.name || null;

const parameterDirection = (
  method: PeClrMethodDefinitionInfo,
  index: number
): WinapiMetadataParameter["direction"] => {
  const flags = method.parameters?.find(parameter => parameter.sequence === index + 1)?.flags;
  if (flags == null) return null;
  const input = (flags & PARAM_IN_FLAG) !== 0;
  const output = (flags & PARAM_OUT_FLAG) !== 0;
  if (input && output) return "inout";
  if (input) return "in";
  if (output) return "out";
  return null;
};

export const buildWinapiParameters = (
  method: PeClrMethodDefinitionInfo,
  tables: PeClrMetadataTables
): WinapiMetadataParameter[] =>
  method.signature?.parameterTypes.map((rawType, index) => ({
    name: parameterName(method, index),
    type: resolveSignatureType(rawType, tables),
    rawType: rawType ?? null,
    direction: parameterDirection(method, index),
    x86StackBytes: x86StackBytesForType(rawType)
  })) ?? [];

const parameterSignatureText = (
  parameter: WinapiMetadataParameter,
  index: number
): string => `${parameter.type} ${parameter.name || `param${index + 1}`}`;

export const formatWinapiSignature = (
  method: PeClrMethodDefinitionInfo,
  apiName: string,
  tables: PeClrMetadataTables
): string => {
  const parameters = buildWinapiParameters(method, tables).map(parameterSignatureText);
  return `${resolveSignatureType(method.signature?.returnType, tables)} ${apiName}(${parameters.join(", ")})`;
};

export const x86StackBytesForParameters = (
  parameters: WinapiMetadataParameter[]
): number | null => {
  if (parameters.some(parameter => parameter.x86StackBytes == null)) return null;
  return parameters.reduce((total, parameter) => total + (parameter.x86StackBytes ?? 0), 0);
};

"use strict";

import type { UcrtMetadataEntry } from "../../ucrt-metadata-schema.js";
import type { ClangFunctionDecl } from "./clang-ast.js";

const normalizeTypeForStack = (type: string): string =>
  type
    .replaceAll(/\b(const|volatile|restrict|__restrict|__unaligned|_CONST_RETURN)\b/g, "")
    .replaceAll(/__attribute__\(\((cdecl|stdcall|fastcall|thiscall)\)\)/g, "__$1")
    .replaceAll(/\s+/g, " ")
    .replaceAll(/\s+\*/g, " *")
    .trim();

const formatDisplayType = (type: string): string =>
  type
    .replaceAll(/__attribute__\(\((cdecl|stdcall|fastcall|thiscall)\)\)/g, "__$1")
    .replaceAll(/\b(__restrict|__unaligned|_CONST_RETURN)\b/g, "")
    .replaceAll(/\s+/g, " ")
    .replaceAll(/\s+\*/g, " *")
    .trim();

const POINTER_TYPE_NAMES = new Set([
  "_beginthread_proc_type",
  "_beginthreadex_proc_type",
  "_CoreCrtNonSecureSearchSortCompareFunction",
  "_CoreCrtSecureSearchSortCompareFunction",
  "_crt_atexit_callback",
  "_crt_signal_t",
  "_invalid_parameter_handler",
  "_locale_t",
  "_onexit_t",
  "_PVFV",
  "_PIFV",
  "FILE *",
  "va_list"
]);

const STACK_BYTES_BY_TYPE = new Map<string, number>([
  ["bool", 4],
  ["char", 4],
  ["signed char", 4],
  ["unsigned char", 4],
  ["short", 4],
  ["short int", 4],
  ["unsigned short", 4],
  ["unsigned short int", 4],
  ["wchar_t", 4],
  ["int", 4],
  ["unsigned int", 4],
  ["long", 4],
  ["long int", 4],
  ["unsigned long", 4],
  ["unsigned long int", 4],
  ["float", 4],
  ["double", 8],
  ["long double", 8],
  ["long long", 8],
  ["long long int", 8],
  ["unsigned long long", 8],
  ["unsigned long long int", 8],
  ["__int64", 8],
  ["unsigned __int64", 8],
  ["intptr_t", 4],
  ["uintptr_t", 4],
  ["ptrdiff_t", 4],
  ["size_t", 4],
  ["rsize_t", 4],
  ["errno_t", 4],
  ["wint_t", 4],
  ["wctype_t", 4],
  ["time_t", 8],
  ["__time32_t", 4],
  ["__time64_t", 8],
  ["clock_t", 4],
  ["_Dcomplex", 16],
  ["_Fcomplex", 8],
  ["_Lcomplex", 16]
]);

const x86StackBytesForType = (type: string): number | null => {
  const normalized = normalizeTypeForStack(type);
  if (normalized.includes("*") || POINTER_TYPE_NAMES.has(normalized)) return 4;
  if (normalized.startsWith("struct ") || normalized.startsWith("union ")) return null;
  return STACK_BYTES_BY_TYPE.get(normalized) ?? null;
};

const parameterDirection = (
  type: string
): UcrtMetadataEntry["parameters"][number]["direction"] => {
  const normalized = normalizeTypeForStack(type);
  if (!normalized.includes("*") && !POINTER_TYPE_NAMES.has(normalized)) return "in";
  return /\bconst\b/.test(type) ? "in" : "inout";
};

const parameterSignatureText = (
  parameter: UcrtMetadataEntry["parameters"][number],
  index: number
): string => `${parameter.type} ${parameter.name || `param${index + 1}`}`;

export const namespaceForUcrtModule = (moduleName: string): string => {
  const key = moduleName.trim().toLowerCase();
  const match = key.match(/^api-ms-win-crt-([a-z0-9_]+)-/);
  return match ? `UCRT.${match[1]}` : "UCRT";
};

export const createUcrtEntry = (
  module: string,
  exportName: string,
  declaration: ClangFunctionDecl
): UcrtMetadataEntry => {
  const parameters = declaration.parameters.map(parameter => ({
    name: parameter.name,
    type: formatDisplayType(parameter.type),
    rawType: parameter.type,
    direction: parameterDirection(parameter.type),
    x86StackBytes: x86StackBytesForType(parameter.type)
  }));
  const signatureParameters = [
    ...parameters.map(parameterSignatureText),
    ...(declaration.variadic ? ["..."] : [])
  ];
  return {
    sourceKind: "ucrt",
    id: `UCRT:${module.trim().toLowerCase()}:${exportName}`,
    module,
    entrypoint: exportName,
    namespace: namespaceForUcrtModule(module),
    api: declaration.name,
    signature: `${formatDisplayType(declaration.returnType)} ${exportName}(${signatureParameters.join(", ")})`,
    returnType: formatDisplayType(declaration.returnType),
    rawReturnType: declaration.returnType,
    parameters,
    callingConvention: declaration.callingConvention,
    x86StackBytes: declaration.callingConvention === "cdecl" ? 0 : null,
    variadic: declaration.variadic,
    setLastError: false,
    characterSet: null,
    architecture: [],
    platform: []
  };
};

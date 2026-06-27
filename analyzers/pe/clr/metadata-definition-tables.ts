"use strict";

import type {
  PeClrFieldInfo,
  PeClrMetadataIndex,
  PeClrMethodDefinitionInfo,
  PeClrParameterInfo,
  PeClrTypeDefinitionInfo
} from "./types.js";
import type { ClrHeapReaders } from "./metadata-heaps.js";
import { parseMemberRefSignature, parseMethodSignature } from "./metadata-signatures.js";
import type { ClrMetadataRow } from "./metadata-table-reader.js";

const cellNumber = (row: ClrMetadataRow, name: string): number =>
  typeof row[name] === "number" ? row[name] : 0;

const cellIndex = (row: ClrMetadataRow, name: string): PeClrMetadataIndex =>
  typeof row[name] === "object"
    ? row[name] as PeClrMetadataIndex
    : { table: "null", tableId: -1, row: 0, raw: 0, valid: false };

const fullName = (namespaceName: string | null, name: string | null): string | null => {
  if (!name) return null;
  return namespaceName ? `${namespaceName}.${name}` : name;
};

const getString = (
  heaps: ClrHeapReaders,
  row: ClrMetadataRow,
  fieldName: string,
  context: string
): string | null => heaps.getString(cellNumber(row, fieldName), `${context}.${fieldName}`);

const rowEndForType = (
  rowStart: number,
  nextRowStart: number | null,
  rowCount: number
): number | null => {
  if (rowStart <= 0 || rowStart > rowCount) return null;
  if (nextRowStart != null) return nextRowStart > rowStart ? nextRowStart - 1 : null;
  return rowCount;
};

export const createTypeDefs = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders,
  fieldRowCount: number,
  methodRowCount: number
): PeClrTypeDefinitionInfo[] =>
  rows.map((row, index) => {
    const nextRow = rows[index + 1];
    const name = getString(heaps, row, "TypeName", `TypeDef row ${index + 1}`);
    const namespaceName = getString(heaps, row, "TypeNamespace", `TypeDef row ${index + 1}`);
    const fieldStart = cellIndex(row, "FieldList").row;
    const nextFieldStart = nextRow ? cellIndex(nextRow, "FieldList").row : null;
    const methodStart = cellIndex(row, "MethodList").row;
    const nextMethodStart = nextRow ? cellIndex(nextRow, "MethodList").row : null;
    return {
      row: index + 1,
      name,
      namespace: namespaceName,
      fullName: fullName(namespaceName, name),
      flags: cellNumber(row, "Flags"),
      extends: cellIndex(row, "Extends"),
      fieldStart,
      fieldEnd: rowEndForType(fieldStart, nextFieldStart, fieldRowCount),
      methodStart,
      methodEnd: rowEndForType(methodStart, nextMethodStart, methodRowCount)
    };
  });

const ownerForMethod = (
  methodRow: number,
  typeDefs: PeClrTypeDefinitionInfo[]
): string | null =>
  typeDefs.find(typeDef =>
    typeDef.methodEnd != null && methodRow >= typeDef.methodStart && methodRow <= typeDef.methodEnd
  )?.fullName ?? null;

export const createParameters = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders
): PeClrParameterInfo[] =>
  rows.map((row, index) => ({
    row: index + 1,
    flags: cellNumber(row, "Flags"),
    sequence: cellNumber(row, "Sequence"),
    name: getString(heaps, row, "Name", `Param row ${index + 1}`)
  }));

export const createFields = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders
): PeClrFieldInfo[] =>
  rows.map((row, index) => {
    const signatureBlobIndex = cellNumber(row, "Signature");
    const context = `Field row ${index + 1}.Signature`;
    const signature = parseMemberRefSignature(heaps.getBlob(signatureBlobIndex, context), context);
    return {
      row: index + 1,
      name: getString(heaps, row, "Name", `Field row ${index + 1}`),
      flags: cellNumber(row, "Flags"),
      signatureBlobIndex,
      ...(signature ? { signature } : {})
    };
  });

const parametersForMethod = (
  row: ClrMetadataRow,
  nextRow: ClrMetadataRow | undefined,
  parameters: PeClrParameterInfo[]
): PeClrParameterInfo[] => {
  const parameterStart = cellIndex(row, "ParamList").row;
  const nextParameterStart = nextRow ? cellIndex(nextRow, "ParamList").row : parameters.length + 1;
  if (parameterStart <= 0 || parameterStart > parameters.length || nextParameterStart <= parameterStart) return [];
  return parameters.slice(parameterStart - 1, Math.min(parameters.length, nextParameterStart - 1));
};

export const createMethodDefs = (
  rows: ClrMetadataRow[],
  heaps: ClrHeapReaders,
  typeDefs: PeClrTypeDefinitionInfo[],
  parameters: PeClrParameterInfo[]
): PeClrMethodDefinitionInfo[] =>
  rows.map((row, index) => {
    const methodParameters = parametersForMethod(row, rows[index + 1], parameters);
    const signatureBlobIndex = cellNumber(row, "Signature");
    const context = `MethodDef row ${index + 1}.Signature`;
    const signature = parseMethodSignature(heaps.getBlob(signatureBlobIndex, context), context);
    return {
      row: index + 1,
      name: getString(heaps, row, "Name", `MethodDef row ${index + 1}`),
      ownerType: ownerForMethod(index + 1, typeDefs),
      rva: cellNumber(row, "RVA"),
      implFlags: cellNumber(row, "ImplFlags"),
      flags: cellNumber(row, "Flags"),
      signatureBlobIndex,
      ...(signature ? { signature } : {}),
      ...(methodParameters.length ? { parameters: methodParameters } : {})
    };
  });

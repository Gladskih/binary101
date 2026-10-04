"use strict";

import type {
  PeClrFieldInfo, PeClrTypeDefinitionInfo, PeClrTypeReferenceInfo
} from "./types.js";

const enumBaseName = (
  type: PeClrTypeDefinitionInfo,
  definitions: PeClrTypeDefinitionInfo[],
  references: PeClrTypeReferenceInfo[]
): string | null => {
  if (!type.extends.valid || !type.extends.row) return null;
  if (type.extends.tableId === 1) return references[type.extends.row - 1]?.fullName ?? null;
  if (type.extends.tableId === 2) return definitions[type.extends.row - 1]?.fullName ?? null;
  return null;
};

const underlyingType = (type: PeClrTypeDefinitionInfo, fields: PeClrFieldInfo[]): string | null => {
  // ECMA-335 I.8.5.2, II.14.3: exactly one instance field, named value__, of an integer type.
  if (type.fieldEnd == null || type.fieldStart < 1 || type.fieldEnd > fields.length) return null;
  const instanceFields = fields.slice(type.fieldStart - 1, type.fieldEnd)
    .filter(field => (field.flags & 0x10) === 0); // II.23.1.5 FieldAttributes.Static.
  const field = instanceFields[0];
  if (instanceFields.length !== 1 || !field) return null;
  return enumFieldType(field);
};

const enumFieldType = (field: PeClrFieldInfo): string | null => {
  if (field.name !== "value__" || field.signature?.issues?.length) return null;
  const primitive = field.signature?.returnType;
  return primitive && /^[iu][1248]$/.test(primitive) ? primitive : null;
};

export const createEnumUnderlyingTypes = (
  definitions: PeClrTypeDefinitionInfo[],
  references: PeClrTypeReferenceInfo[],
  fields: PeClrFieldInfo[]
): ReadonlyMap<string, string> => {
  const result = new Map<string, string>();
  for (const definition of definitions) {
    if (!definition.fullName || enumBaseName(definition, definitions, references) !== "System.Enum") continue;
    const primitive = underlyingType(definition, fields);
    if (primitive) result.set(definition.fullName, primitive);
  }
  return result;
};

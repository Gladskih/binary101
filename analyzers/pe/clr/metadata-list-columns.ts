"use strict";

import type { ClrMetadataColumnSchema } from "./metadata-schema.js";

// CoreCLR MiniMd/#- list columns use the corresponding pointer table when it has rows.
// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Reflection.Metadata/src/System/Reflection/Metadata/MetadataReader.cs
export const LIST_POINTER_TABLES: Readonly<Record<string, number>> = {
  FieldList: 0x03, MethodList: 0x05, ParamList: 0x07, EventList: 0x13, PropertyList: 0x16
};

export const listColumnTable = (
  column: ClrMetadataColumnSchema,
  rowCounts: ReadonlyMap<number, number>
): number => {
  const pointerTable = LIST_POINTER_TABLES[column.name];
  return pointerTable != null && (rowCounts.get(pointerTable) ?? 0) > 0 ? pointerTable : column.table!;
};

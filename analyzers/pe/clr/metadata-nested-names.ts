"use strict";

import type { PeClrTypeDefinitionInfo, PeClrTypeReferenceInfo } from "./types.js";
import type { PeClrMetadataIndex } from "./types.js";
import type { ClrMetadataRow, ClrMetadataCell } from "./metadata-table-reader.js";

type NamedType = { row: number; name: string | null; fullName: string | null };

const validDefinitionIndex = (index: ClrMetadataCell | undefined, count: number): index is PeClrMetadataIndex =>
  !!index && typeof index === "object" && index.valid && index.tableId === 2 &&
  index.row >= 1 && index.row <= count;

const enclosingDefinitions = (rows: ClrMetadataRow[], count: number, issues: string[]): Map<number, number> => {
  const parents = new Map<number, number>();
  for (const row of rows) {
    const nested = row["NestedClass"];
    const enclosing = row["EnclosingClass"];
    if (!validDefinitionIndex(nested, count)) {
      issues.push("CLR NestedClass has an invalid nested type reference.");
      continue;
    }
    if (!validDefinitionIndex(enclosing, count) || parents.has(nested.row)) {
      issues.push(`CLR NestedClass row for type ${nested.row} has an invalid or duplicate enclosing type.`);
      parents.set(nested.row, 0);
    } else parents.set(nested.row, enclosing.row);
  }
  return parents;
};

const namePath = (
  start: number, types: NamedType[], parents: ReadonlyMap<number, number>,
  names: Map<number, string | null>, issues: string[]
): void => {
  const path: number[] = [];
  const seen = new Set<number>();
  let row = start;
  while (!names.has(row)) {
    if (seen.has(row) || row < 1 || row > types.length) {
      issues.push(`CLR enclosing type chain of row ${start} is cyclic or out of bounds.`);
      names.set(row, null);
      break;
    }
    seen.add(row);
    path.push(row);
    if (!parents.has(row)) { names.set(row, types[row - 1]!.fullName); break; }
    row = parents.get(row)!;
  }
  for (const nested of path.reverse()) {
    if (names.has(nested)) continue;
    const parent = names.get(parents.get(nested)!);
    names.set(nested, parent && types[nested - 1]!.name ? `${parent}+${types[nested - 1]!.name}` : null);
  }
};

const nestedNames = <Type extends NamedType>(
  types: Type[], parents: ReadonlyMap<number, number>, issues: string[]
): Type[] => {
  const names = new Map<number, string | null>();
  for (const type of types) namePath(type.row, types, parents, names, issues);
  return types.map(type => ({ ...type, fullName: names.get(type.row) ?? null }));
};

// ECMA-335 II.22.32 and II.22.38: nested definitions use NestedClass; nested references
// use a TypeRef ResolutionScope. Reflection names join enclosing names with '+'.
export const resolveDefinitionNames = (
  types: PeClrTypeDefinitionInfo[], rows: ClrMetadataRow[], issues: string[]
): PeClrTypeDefinitionInfo[] => nestedNames(types, enclosingDefinitions(rows, types.length, issues), issues);

export const resolveReferenceNames = (
  types: PeClrTypeReferenceInfo[], issues: string[]
): PeClrTypeReferenceInfo[] => nestedNames(types, new Map(types.filter(type => type.resolutionScope.tableId === 1)
  .map(type => [type.row, type.resolutionScope.valid ? type.resolutionScope.row : 0])), issues);

"use strict";

import type { ClrMetadataRow, ClrParsedTableStream } from "./metadata-table-reader.js";

// ECMA-335 II.22 list relationships; #- adds indirection through the CoreCLR pointer tables.
const MEMBER_LISTS = {
  fields: { ownerTable: 2, column: "FieldList", targetTable: 4, pointerTable: 3, pointerColumn: "Field" },
  methods: { ownerTable: 2, column: "MethodList", targetTable: 6, pointerTable: 5, pointerColumn: "Method" },
  parameters: { ownerTable: 6, column: "ParamList", targetTable: 8, pointerTable: 7, pointerColumn: "Param" },
  events: { ownerTable: 0x12, column: "EventList", targetTable: 0x14, pointerTable: 0x13, pointerColumn: "Event" },
  properties: { ownerTable: 0x15, column: "PropertyList", targetTable: 0x17, pointerTable: 0x16, pointerColumn: "Property" }
} as const;

export type ClrMetadataOwnership = {
  [List in keyof typeof MEMBER_LISTS]: ReadonlyMap<number, readonly number[]>
};

const indexRow = (row: ClrMetadataRow | undefined, column: string): number => {
  const value = row?.[column];
  return value && typeof value === "object" ? value.row : 0;
};

const targetRow = (
  pointer: ClrMetadataRow | undefined,
  column: string,
  targetTable: number,
  rowCount: number
): number => {
  const value = pointer?.[column];
  return value && typeof value === "object" && value.valid && value.tableId === targetTable &&
    value.row > 0 && value.row <= rowCount ? value.row : 0;
};

const resolveList = (
  parsed: ClrParsedTableStream,
  list: keyof typeof MEMBER_LISTS,
  issues: string[]
): ReadonlyMap<number, readonly number[]> => {
  const relation = MEMBER_LISTS[list];
  const owners = parsed.tables.get(relation.ownerTable)?.rows ?? [];
  const members = listMembers(parsed, relation, issues);
  const result = new Map<number, number[]>();
  owners.forEach((owner, index) => {
    const ownerRow = relation.ownerTable === 2 || relation.ownerTable === 6
      ? index + 1 : indexRow(owner, "Parent");
    const start = indexRow(owner, relation.column);
    const end = index + 1 < owners.length ? indexRow(owners[index + 1], relation.column)
      : members.length + 1;
    if (start < 1 || end < start || end > members.length + 1) {
      issues.push(`CLR ${list} list of row ${ownerRow} is out of bounds or not monotonic.`);
      result.set(ownerRow, []);
      return;
    }
    const rows = members.slice(start - 1, end - 1);
    if (rows.includes(0)) {
      issues.push(`CLR ${relation.column} of owner row ${ownerRow} contains an unresolved member.`);
      result.set(ownerRow, []);
    } else result.set(ownerRow, rows);
  });
  return result;
};

const listMembers = (
  parsed: ClrParsedTableStream,
  relation: typeof MEMBER_LISTS[keyof typeof MEMBER_LISTS],
  issues: string[]
): number[] => {
  const targetCount = parsed.tables.get(relation.targetTable)?.rows.length ?? 0;
  const pointers = parsed.tables.get(relation.pointerTable)?.rows ?? [];
  if (!pointers.length) return Array.from({ length: targetCount }, (_, index) => index + 1);
  const used = new Set<number>();
  const duplicates = new Set<number>();
  const rows = pointers.map(pointer => {
    const row = targetRow(pointer, relation.pointerColumn, relation.targetTable, targetCount);
    if (!row || used.has(row)) {
      issues.push(`CLR ${relation.column} has an invalid or duplicate pointer to row ${row}.`);
      duplicates.add(row);
    }
    used.add(row);
    return row;
  });
  return rows.map(row => duplicates.has(row) ? 0 : row);
};

export const createMetadataOwnership = (
  parsed: ClrParsedTableStream,
  issues: string[]
): ClrMetadataOwnership => ({
  fields: resolveList(parsed, "fields", issues), methods: resolveList(parsed, "methods", issues),
  parameters: resolveList(parsed, "parameters", issues), events: resolveList(parsed, "events", issues),
  properties: resolveList(parsed, "properties", issues)
});

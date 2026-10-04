"use strict";

import type { PeClrMetadataIndex } from "./types.js";

// ECMA-335 II.22.38 / II.22.14: nested TypeRef and ExportedType rows inherit their
// enclosing row's resolution scope. Cache chains, detect cycles, and never recurse.
export const createEnclosingTypeRoots = (
  indexes: PeClrMetadataIndex[], nestingTableId: number
): ReadonlyMap<number, number | null> => {
  const roots = new Map<number, number | null>();
  for (let start = 1; start <= indexes.length; start++) {
    const path = new Set<number>();
    let row = start;
    while (!roots.has(row)) {
      const index = indexes[row - 1];
      if (!index?.valid || path.has(row)) { roots.set(row, null); break; }
      path.add(row);
      if (index.tableId !== nestingTableId) { roots.set(row, row); break; }
      row = index.row;
    }
    for (const nested of path) roots.set(nested, roots.get(row) ?? null);
  }
  return roots;
};

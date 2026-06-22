"use strict";

import { getIatSlotRva } from "../../analyzers/pe/disassembly/import-references.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../../analyzers/pe/layout/rva-limits.js";
import { escapeHtml } from "../../html-utils.js";

const DIRECT_IAT_REFS_TOOLTIP =
  "Unique decoded near CALL/JMP instructions that directly address this IAT slot. " +
  "This is not a runtime call count and does not expand shared import thunks.";

export const directIatReferenceCounts = (
  pe: PeWindowsParseResult
): ReadonlyMap<number, number> => {
  const counts = new Map<number, number>();
  for (const entry of pe.disassembly?.directIatReferences ?? []) {
    if (
      !Number.isSafeInteger(entry.slotRva) ||
      entry.slotRva < 0 ||
      entry.slotRva >= PE_RVA_EXCLUSIVE_LIMIT ||
      !Number.isSafeInteger(entry.referenceCount) ||
      entry.referenceCount <= 0
    ) continue;
    counts.set(entry.slotRva >>> 0, entry.referenceCount);
  }
  return counts;
};

export const renderDirectIatRefsHeader = (): string =>
  `<th class="peNumeric" data-accessible-tooltip ` +
  `title="${escapeHtml(DIRECT_IAT_REFS_TOOLTIP)}">Direct IAT refs</th>`;

export const renderDirectIatRefsCell = (
  counts: ReadonlyMap<number, number>,
  startRva: unknown,
  functionIndex: number,
  entrySize: number
): string => {
  const slotRva = getIatSlotRva(startRva, functionIndex, entrySize);
  const count = slotRva == null ? 0 : counts.get(slotRva) ?? 0;
  return `<td class="peNumeric" data-sort-value="${count}">${count > 0 ? count : "—"}</td>`;
};

export const directIatEntrySize = (pe: PeWindowsParseResult): number =>
  pe.disassembly?.bitness === 64
    ? BigUint64Array.BYTES_PER_ELEMENT
    : pe.disassembly?.bitness === 32
      ? Uint32Array.BYTES_PER_ELEMENT
      : pe.imports?.thunkEntrySize ?? 0;

"use strict";

import { getIatSlotRva } from "../../analyzers/pe/disassembly/import-references.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../../analyzers/pe/layout/rva-limits.js";
import { escapeHtml } from "../../html-utils.js";

export type DirectIatReferenceKind = "call" | "jump";

export type DirectIatReferenceCounts = {
  callReferenceCount: number;
  jumpReferenceCount: number;
};

const DIRECT_IAT_REFERENCE_HEADINGS: Record<DirectIatReferenceKind, string> = {
  call: "Direct CALL refs",
  jump: "Direct JMP refs"
};

const DIRECT_IAT_REFERENCE_TOOLTIPS: Record<DirectIatReferenceKind, string> = {
  call:
    "Unique decoded near CALL instructions that directly address this IAT slot during ISA analysis. " +
    "This is a static count, not a runtime call count.",
  jump:
    "Unique decoded near JMP instructions that directly address this IAT slot during ISA analysis. " +
    "This is a static count; it can represent an import thunk or tail transfer."
};

const validReferenceCount = (value: unknown): number =>
  Number.isSafeInteger(value) && (value as number) > 0 ? value as number : 0;

export const directIatReferenceCounts = (
  pe: PeWindowsParseResult
): ReadonlyMap<number, DirectIatReferenceCounts> => {
  const counts = new Map<number, DirectIatReferenceCounts>();
  for (const entry of pe.disassembly?.directIatReferences ?? []) {
    if (
      !Number.isSafeInteger(entry.slotRva) ||
      entry.slotRva < 0 ||
      entry.slotRva >= PE_RVA_EXCLUSIVE_LIMIT
    ) continue;
    const callReferenceCount = validReferenceCount(entry.callReferenceCount);
    const jumpReferenceCount = validReferenceCount(entry.jumpReferenceCount);
    if (!callReferenceCount && !jumpReferenceCount) continue;
    counts.set(entry.slotRva >>> 0, { callReferenceCount, jumpReferenceCount });
  }
  return counts;
};

export const renderDirectIatRefsHeader = (kind: DirectIatReferenceKind): string =>
  `<th class="peNumeric" data-accessible-tooltip ` +
  `title="${escapeHtml(DIRECT_IAT_REFERENCE_TOOLTIPS[kind])}">` +
  `${DIRECT_IAT_REFERENCE_HEADINGS[kind]}</th>`;

export const renderDirectIatRefsHeaders = (): string =>
  `${renderDirectIatRefsHeader("call")}${renderDirectIatRefsHeader("jump")}`;

export const renderDirectIatRefsCell = (
  counts: ReadonlyMap<number, DirectIatReferenceCounts>,
  startRva: unknown,
  functionIndex: number,
  entrySize: number,
  kind: DirectIatReferenceKind
): string => {
  const slotRva = getIatSlotRva(startRva, functionIndex, entrySize);
  const reference = slotRva == null ? undefined : counts.get(slotRva);
  const count = kind === "call"
    ? reference?.callReferenceCount ?? 0
    : reference?.jumpReferenceCount ?? 0;
  return `<td class="peNumeric" data-sort-value="${count}">${count > 0 ? count : "—"}</td>`;
};

export const renderDirectIatRefsCells = (
  counts: ReadonlyMap<number, DirectIatReferenceCounts>,
  startRva: unknown,
  functionIndex: number,
  entrySize: number
): string =>
  `${renderDirectIatRefsCell(counts, startRva, functionIndex, entrySize, "call")}` +
  renderDirectIatRefsCell(counts, startRva, functionIndex, entrySize, "jump");

export const directIatEntrySize = (pe: PeWindowsParseResult): number =>
  pe.disassembly?.bitness === 64
    ? BigUint64Array.BYTES_PER_ELEMENT
    : pe.disassembly?.bitness === 32
      ? Uint32Array.BYTES_PER_ELEMENT
      : pe.imports?.thunkEntrySize ?? 0;

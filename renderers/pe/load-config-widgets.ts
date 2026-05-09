"use strict";

import { hex } from "../../binary-utils.js";
import { rowFlags, safe } from "../../html-utils.js";
import { GUARD_FLAGS } from "../../analyzers/pe/constants.js";
import type { PeLoadConfig, PeLoadConfigTable } from "../../analyzers/pe/load-config/index.js";
import { peSectionNameValue } from "../../analyzers/pe/sections/name.js";
import type { PeSection } from "../../analyzers/pe/types.js";

const ADDRESS_TABLE_RENDER_LIMIT = 512;
const DYNAMIC_RELOCATION_SYMBOLS = new Map<bigint, string>([
  [1n, "GUARD_RF_PROLOGUE"],
  [2n, "GUARD_RF_EPILOGUE"],
  [3n, "GUARD_IMPORT_CONTROL_TRANSFER"],
  [4n, "GUARD_INDIR_CONTROL_TRANSFER"],
  [5n, "GUARD_SWITCHTABLE_BRANCH"],
  [6n, "ARM64X"]
]);

const findSectionContainingRva = (sections: PeSection[], rva: number): PeSection | null => {
  const normalizedRva = rva >>> 0;
  for (const section of sections) {
    const start = section.virtualAddress >>> 0;
    const size = (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);
    if (normalizedRva >= start && normalizedRva < start + size) return section;
  }
  return null;
};

const formatPointerHex = (value: bigint, width: number): string =>
  `0x${value.toString(16).padStart(width, "0")}`;

const formatRvaAsVa = (imageBase: bigint, pointerWidth: number, rva: number): string => {
  if (!Number.isSafeInteger(rva) || rva <= 0) return "-";
  return formatPointerHex(imageBase + BigInt(rva >>> 0), pointerWidth);
};

const formatSectionForRva = (sections: PeSection[], rva: number): string => {
  const section = findSectionContainingRva(sections, rva);
  return section ? peSectionNameValue(section.name) || "(unnamed)" : "(outside sections)";
};

const getEntryNotes = (entry: PeLoadConfigTable["entries"][number]): string[] => [
  ...(entry.gfidsFlags?.length ? entry.gfidsFlags : []),
  ...((entry.unknownGfidsFlagBits ?? 0) ? [`UNKNOWN_GFIDS_FLAGS_${hex(entry.unknownGfidsFlagBits ?? 0, 2)}`] : [])
];

const hasEntryMetadata = (entry: PeLoadConfigTable["entries"][number]): boolean =>
  Boolean(entry.metadataBytes?.length || getEntryNotes(entry).length);

const shouldRenderAddressRows = (table: PeLoadConfigTable, sections: PeSection[]): boolean => {
  if (table.entries.some(hasEntryMetadata)) return true;
  const sectionNames = new Set(table.entries.map(entry => formatSectionForRva(sections, entry.rva)));
  return sectionNames.size > 1;
};

const renderAddressTableSummary = (
  table: PeLoadConfigTable,
  sections: PeSection[],
  hiddenCount: number
): string => {
  const sectionName = table.entries.length ? formatSectionForRva(sections, table.entries[0]?.rva ?? 0) : "-";
  return `<div class="smallNote" style="margin:.35rem 0 0 0">` +
    `${table.entries.length} decoded entr${table.entries.length === 1 ? "y" : "ies"}` +
    `; ${table.declaredCount} declared; section ${safe(sectionName)}.` +
    `${hiddenCount ? ` ${hiddenCount} entr${hiddenCount === 1 ? "y is" : "ies are"} beyond the render limit.` : ""}` +
    `</div>`;
};

export const getDynamicRelocationSymbolName = (symbol: bigint): string =>
  DYNAMIC_RELOCATION_SYMBOLS.get(symbol) ?? "UNKNOWN";

export const renderLoadConfigGuardFlags = (lc: PeLoadConfig): string => {
  const guardFlags = lc.GuardFlags >>> 0;
  const stride = (guardFlags >>> 28) & 0xf;
  const strideChip = stride
    ? `<span class="opt sel" title="CFG table entries are ${4 + stride} bytes">` +
      `CF_FUNCTION_TABLE_SIZE_${4 + stride}BYTES</span>`
    : `<span class="opt dim" title="CFG table entries are plain 4-byte RVAs">CF_FUNCTION_TABLE_SIZE_4BYTES</span>`;
  const notes = GUARD_FLAGS
    .filter(([bit]) => (guardFlags & bit) !== 0)
    .map(([, name, explanation]) => `${name}: ${explanation ?? "documented GuardFlags bit"}`);
  return `${guardFlags ? hex(guardFlags, 8) : "0"}` +
    `${rowFlags(guardFlags & 0x0fff_ffff, GUARD_FLAGS)}<div class="optionsRow">${strideChip}</div>` +
    `<div class="smallNote" style="margin:0">${safe(
      notes.length
        ? notes.join("; ")
        : "No CFG-related flags are set; high nibble still defines CFG table entry size."
    )}</div>`;
};

export const renderLoadConfigChecks = (lc: PeLoadConfig): string => {
  if (!lc.checks?.length) return "";
  const icon = (status: string): string => status === "pass" ? "&#10003;" : status === "fail" ? "X" : "i";
  const items = lc.checks.map(check => {
    const className = check.status === "pass"
      ? "manifestCheckItem manifestCheckItem--pass"
      : check.status === "fail"
        ? "manifestCheckItem manifestCheckItem--fail"
        : "manifestCheckItem";
    const detail = check.source ? `${check.detail} Source: ${check.source}.` : check.detail;
    return `<li class="${className}"><span class="manifestCheckIcon">${icon(check.status)}</span>` +
      `<span><b>${safe(check.title)}</b>: ${safe(detail)}</span></li>`;
  });
  return `<div class="loadConfigChecks"><div class="smallNote">Load Config cross-checks</div>` +
    `<ul class="manifestCheckList">${items.join("")}</ul></div>`;
};

export const renderLoadConfigAddressTable = (
  table: PeLoadConfigTable,
  sections: PeSection[],
  imageBase: bigint,
  pointerWidth: number,
  note?: string
): string => {
  const visibleEntries = table.entries.slice(0, ADDRESS_TABLE_RENDER_LIMIT);
  const hiddenCount = Math.max(0, table.entries.length - visibleEntries.length);
  const renderRows = shouldRenderAddressRows(table, sections);
  const rows = visibleEntries.map(entry => {
    const metadata = entry.metadataBytes?.length
      ? entry.metadataBytes.map(byte => byte.toString(16).padStart(2, "0")).join(" ")
      : "-";
    const notes = getEntryNotes(entry);
    return `<tr><td>${entry.index}</td><td>${hex(entry.rva, 8)}</td>` +
      `<td>${safe(formatRvaAsVa(imageBase, pointerWidth, entry.rva))}</td>` +
      `<td>${safe(formatSectionForRva(sections, entry.rva))}</td><td>${safe(metadata)}</td>` +
      `<td>${notes.length ? safe(notes.join(", ")) : "-"}</td></tr>`;
  });
  return `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">${safe(`${table.name} (${table.entries.length}/${table.declaredCount})`)}</summary>` +
    `${note ? `<div class="smallNote" style="margin:.35rem 0 0 0">${safe(note)}</div>` : ""}` +
    `${table.warnings?.length ? `<div class="smallNote" style="margin:.35rem 0 0 0;color:var(--warn-fg)">${safe(table.warnings.join("; "))}</div>` : ""}` +
    `<div class="smallNote" style="margin:.35rem 0 0 0">Entry size ${table.entrySize} bytes; table RVA ${table.tableRva == null ? "-" : safe(hex(table.tableRva, 8))}.` +
    `${hiddenCount ? ` Showing first ${ADDRESS_TABLE_RENDER_LIMIT} entries; ${hiddenCount} hidden.` : ""}</div>` +
    `${renderRows ? `<div class="tableWrap"><table class="table"><thead><tr><th>#</th><th>RVA</th><th>VA</th><th>Section</th><th>Metadata</th><th>Notes</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>` : renderAddressTableSummary(table, sections, hiddenCount)}</details>`;
};

"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import { renderFlagChips, escapeHtml } from "../../html-utils.js";
import { GUARD_FLAGS } from "../../analyzers/pe/constants.js";
import type { PeLoadConfig, PeLoadConfigTable } from "../../analyzers/pe/load-config/index.js";
import type {
  PeDynamicRelocationEntry,
  PeDynamicRelocations
} from "../../analyzers/pe/dynamic-relocations/index.js";
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
const compareWideInt = (left: bigint, right: bigint): number =>
  left === right ? 0 : left < right ? -1 : 1;
const formatWideHex = (value: bigint): string => `0x${value.toString(16)}`;
const formatDynamicRelocationSymbol = (entry: PeDynamicRelocationEntry): string =>
  entry.symbol === 0n ? "-" : formatWideHex(entry.symbol);
const formatDynamicRelocationSymbolName = (entry: PeDynamicRelocationEntry): string =>
  entry.symbol === 0n ? "-" : getDynamicRelocationSymbolName(entry.symbol);
const dynamicRelocationPayloadSize = (entry: PeDynamicRelocationEntry): number =>
  entry.kind === "v1" ? entry.baseRelocSize : entry.fixupInfoSize;
const dynamicRelocationIsComplete = (entry: PeDynamicRelocationEntry): boolean =>
  entry.availableBytes >= dynamicRelocationPayloadSize(entry);
const renderDynamicRelocationTitle = (dr: PeDynamicRelocations): string =>
  `DynamicRelocations (v${dr.version}, ${dr.entries.length} ` +
  `entr${dr.entries.length === 1 ? "y" : "ies"})`;
const formatDynamicRelocationTypes = (types: bigint[]): string =>
  types.length ? types.map(type => formatWideHex(type)).join(", ") : "-";

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

const renderAddressTableSummaryRow = (table: PeLoadConfigTable, sections: PeSection[]): string => {
  const sectionName = table.entries.length ? formatSectionForRva(sections, table.entries[0]?.rva ?? 0) : "-";
  return `<tr><th scope="row">${escapeHtml(table.name)}</th>` +
    `<td class="num">${table.entries.length}</td>` +
    `<td class="num">${table.declaredCount}</td>` +
    `<td>${escapeHtml(sectionName)}</td>` +
    `<td class="num">${table.entrySize} bytes</td>` +
    `<td>${table.tableRva == null ? "-" : escapeHtml(hex(table.tableRva, 8))}</td></tr>`;
};

const renderAddressTableAggregate = (
  tables: readonly PeLoadConfigTable[],
  sections: PeSection[],
  warningHtml: string[]
): string =>
  `<div class="tableWrap loadConfigSummaryTableWrap"><table ` +
  `class="table loadConfigSummaryTable" aria-label="Decoded Load Config address tables">` +
  `<thead><tr><th scope="col">Table</th><th scope="col" class="num">Decoded</th>` +
  `<th scope="col" class="num">Declared</th><th scope="col">Section</th>` +
  `<th scope="col" class="num">Entry size</th><th scope="col">Table RVA</th></tr></thead>` +
  `<tbody>${tables.map(table => renderAddressTableSummaryRow(table, sections)).join("")}</tbody>` +
  `</table></div>${warningHtml.join("")}`;

export const getDynamicRelocationSymbolName = (symbol: bigint): string =>
  DYNAMIC_RELOCATION_SYMBOLS.get(symbol) ?? "UNKNOWN";

const renderDynamicRelocationMeta = (dr: PeDynamicRelocations, types: bigint[]): string =>
  `<div class="loadConfigDynamicMeta">` +
  `<span><b>Version</b> ${escapeHtml(hex(dr.version, 8))}</span> ` +
  `<span><b>DataSize</b> ${escapeHtml(humanSize(dr.dataSize))}</span> ` +
  `<span><b>Symbols</b> ${escapeHtml(formatDynamicRelocationTypes(types))}</span>` +
  `</div>`;

const renderDynamicRelocationSummaryCells = (entry: PeDynamicRelocationEntry | null): string[] => {
  if (!entry) return ["-", "-"];
  return [formatDynamicRelocationSymbol(entry), formatDynamicRelocationSymbolName(entry)];
};

const renderDynamicRelocationTruncationCells = (entry: PeDynamicRelocationEntry | null): string[] => {
  if (!entry) return [];
  const payloadSize = dynamicRelocationPayloadSize(entry);
  const complete = dynamicRelocationIsComplete(entry);
  if (complete && entry.availableBytes === payloadSize) return [];
  return [humanSize(payloadSize), humanSize(entry.availableBytes), complete ? "complete" : "truncated"];
};

const renderDynamicRelocationFlatSummary = (
  dr: PeDynamicRelocations,
  warningHtml: string
): string => {
  const entry = dr.entries[0] ?? null;
  const truncationCells = renderDynamicRelocationTruncationCells(entry);
  const truncationHeaders = truncationCells.length
    ? `<th scope="col">Payload</th><th scope="col">Available</th><th scope="col">Status</th>`
    : "";
  const truncationStatusClass = entry && dynamicRelocationIsComplete(entry)
    ? "loadConfigStatusOk"
    : "loadConfigStatusWarn";
  const truncationRow = truncationCells.length
    ? `<td>${escapeHtml(truncationCells[0])}</td><td>${escapeHtml(truncationCells[1])}</td>` +
      `<td class="${truncationStatusClass}">${escapeHtml(truncationCells[2])}</td>`
    : "";
  return `<div class="tableWrap loadConfigSummaryTableWrap"><table ` +
    `class="table loadConfigSummaryTable loadConfigDynamicSummaryTable" ` +
    `aria-label="Dynamic Load Config relocations">` +
    `<thead><tr><th scope="col">Table</th><th scope="col">Version</th>` +
    `<th scope="col" class="num">Entries</th><th scope="col">Data size</th>` +
    `<th scope="col">Symbol</th><th scope="col">Name</th>` +
    `${truncationHeaders}</tr></thead><tbody><tr>` +
    `<th scope="row">DynamicRelocations</th><td>${dr.version}</td>` +
    `<td class="num">${dr.entries.length}</td><td>${escapeHtml(humanSize(dr.dataSize))}</td>` +
    `${renderDynamicRelocationSummaryCells(entry).map(value => `<td>${escapeHtml(value)}</td>`).join("")}` +
    `${truncationRow}</tr></tbody></table></div>${warningHtml}`;
};

const renderSingleDynamicRelocationEntry = (entry: PeDynamicRelocationEntry): string => {
  const status = dynamicRelocationIsComplete(entry) ? "complete" : "truncated";
  return `<div class="loadConfigDynamicEntrySummary">` +
    `<span><b>Entry</b> 1</span> ` +
    `<span><b>Kind</b> ${escapeHtml(entry.kind)}</span> ` +
    `<span><b>Symbol</b> ${escapeHtml(formatDynamicRelocationSymbol(entry))}</span> ` +
    `<span><b>Size</b> ${escapeHtml(humanSize(dynamicRelocationPayloadSize(entry)))}</span> ` +
    `<span><b>Available</b> ${escapeHtml(humanSize(entry.availableBytes))}</span> ` +
    `<span class="loadConfigDynamicStatus--${status}"><b>Status</b> ${status}</span>` +
    `</div>`;
};

const renderDynamicRelocationEntries = (entries: PeDynamicRelocationEntry[]): string => {
  if (!entries.length) return "";
  const firstEntry = entries[0];
  if (entries.length === 1 && firstEntry) return renderSingleDynamicRelocationEntry(firstEntry);
  const rows = entries.map((entry, index) => {
    const status = dynamicRelocationIsComplete(entry) ? "complete" : "truncated";
    return `<tr><td>${index + 1}</td><td>${escapeHtml(formatDynamicRelocationSymbol(entry))}</td>` +
      `<td>${escapeHtml(formatDynamicRelocationSymbolName(entry))}</td>` +
      `<td>${escapeHtml(humanSize(dynamicRelocationPayloadSize(entry)))}</td>` +
      `<td>${escapeHtml(humanSize(entry.availableBytes))}</td><td>${status}</td></tr>`;
  });
  return `<div class="tableWrap loadConfigDynamicTable"><table class="table">` +
    `<thead><tr><th>#</th><th>Symbol</th><th>Name</th><th>Payload</th>` +
    `<th>Available</th><th>Status</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
};

export const renderLoadConfigDynamicRelocations = (dr: PeDynamicRelocations): string => {
  const types = [
    ...new Set(dr.entries.map(entry => entry.symbol).filter(symbol => symbol !== 0n))
  ].sort(compareWideInt);
  const warningHtml = dr.warnings?.length
    ? `<div class="smallNote" style="margin:.35rem 0 0 0;color:var(--warn-fg)">` +
      `${escapeHtml(dr.warnings.join("; "))}</div>`
    : "";
  if (dr.entries.length <= 1) return renderDynamicRelocationFlatSummary(dr, warningHtml);
  return `<details class="loadConfigDynamicRelocations"><summary class="loadConfigNestedSummary">` +
    escapeHtml(renderDynamicRelocationTitle(dr)) +
    `</summary>${warningHtml}${renderDynamicRelocationMeta(dr, types)}` +
    `${renderDynamicRelocationEntries(dr.entries)}</details>`;
};

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
    `${renderFlagChips(guardFlags & 0x0fff_ffff, GUARD_FLAGS)}<div class="optionsRow">${strideChip}</div>` +
    `<div class="smallNote" style="margin:0">${escapeHtml(
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
      `<span><b>${escapeHtml(check.title)}</b>: ${escapeHtml(detail)}</span></li>`;
  });
  return `<div class="loadConfigChecks"><div class="smallNote">Load Config cross-checks</div>` +
    `<ul class="manifestCheckList">${items.join("")}</ul></div>`;
};

const renderAddressTableWarning = (table: PeLoadConfigTable): string =>
  table.warnings?.length
    ? `<div class="smallNote" style="margin:.25rem 0 0 0;color:var(--warn-fg)">` +
      `${escapeHtml(table.warnings.join("; "))}</div>`
    : "";

const renderAddressTableNote = (table: PeLoadConfigTable): string =>
  table.notes?.length
    ? `<div class="smallNote" style="margin:.25rem 0 0 0">` +
      `${escapeHtml(table.notes.join("; "))}</div>`
    : "";

const renderDetailedLoadConfigAddressTable = (
  table: PeLoadConfigTable,
  sections: PeSection[],
  imageBase: bigint,
  pointerWidth: number,
  note?: string
): string => {
  const visibleEntries = table.entries.slice(0, ADDRESS_TABLE_RENDER_LIMIT);
  const hiddenCount = Math.max(0, table.entries.length - visibleEntries.length);
  const rows = visibleEntries.map(entry => {
    const metadata = entry.metadataBytes?.length
      ? entry.metadataBytes.map(byte => byte.toString(16).padStart(2, "0")).join(" ")
      : "-";
    const notes = getEntryNotes(entry);
    return `<tr><td>${entry.index}</td><td>${hex(entry.rva, 8)}</td>` +
      `<td>${escapeHtml(formatRvaAsVa(imageBase, pointerWidth, entry.rva))}</td>` +
      `<td>${escapeHtml(formatSectionForRva(sections, entry.rva))}</td><td>${escapeHtml(metadata)}</td>` +
      `<td>${notes.length ? escapeHtml(notes.join(", ")) : "-"}</td></tr>`;
  });
  const details = [
    ...(note ? [escapeHtml(note)] : []),
    `Entry size ${table.entrySize} bytes`,
    `table RVA ${table.tableRva == null ? "-" : escapeHtml(hex(table.tableRva, 8))}`,
    ...(hiddenCount ? [`showing first ${ADDRESS_TABLE_RENDER_LIMIT}; ${hiddenCount} hidden`] : [])
  ];
  return `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">${escapeHtml(`${table.name} (${table.entries.length}/${table.declaredCount})`)}</summary>` +
    `<div class="loadConfigAddressTableBody"><div class="smallNote" style="margin:.35rem 0 0 0">${details.join("; ")}.</div>` +
    renderAddressTableNote(table) +
    renderAddressTableWarning(table) +
    `<div class="tableWrap"><table class="table"><thead><tr><th>#</th><th>RVA</th><th>VA</th><th>Section</th><th>Metadata</th><th>Notes</th></tr></thead><tbody>${rows.join("")}</tbody></table></div></div></details>`;
};

export const renderLoadConfigAddressTables = (
  tables: readonly (readonly [PeLoadConfigTable, string?])[],
  sections: PeSection[],
  imageBase: bigint,
  pointerWidth: number
): string => {
  const aggregateTables = tables.map(([table]) => table).filter(table => !shouldRenderAddressRows(table, sections));
  const detailedTables = tables.filter(([table]) => shouldRenderAddressRows(table, sections));
  return (aggregateTables.length ? renderAddressTableAggregate(
    aggregateTables,
    sections,
    aggregateTables.flatMap(table => [renderAddressTableNote(table), renderAddressTableWarning(table)])
  ) : "") +
    detailedTables.map(([table, note]) =>
      renderDetailedLoadConfigAddressTable(table, sections, imageBase, pointerWidth, note)
    ).join("");
};

export const renderLoadConfigAddressTable = (
  table: PeLoadConfigTable,
  sections: PeSection[],
  imageBase: bigint,
  pointerWidth: number,
  note?: string
): string => renderLoadConfigAddressTables(
  note === undefined ? [[table]] : [[table, note]],
  sections,
  imageBase,
  pointerWidth
);

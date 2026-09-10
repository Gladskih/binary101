import { escapeHtml } from "../../html-utils.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { ElfMipsMetadata, ElfMipsOption } from "../../analyzers/elf/mips-types.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";

const flagNames: Record<string, string> = { version: "Version", isaLevel: "ISA level",
  isaRevision: "ISA revision", gprSize: "GPR size code", cpr1Size: "CPR1 size code",
  cpr2Size: "CPR2 size code", fpAbi: "Floating point ABI", isaExtension: "ISA extension",
  ases: "Architecture extension flags", flags1: "Flags 1", flags2: "Flags 2" };

const optionCells = (option: ElfMipsOption): string[] => [String(option.kind), String(option.section),
  `0x${option.info.toString(16)}`, option.registerInfo?.gprMask.toString(16) ?? "-",
  option.registerInfo?.cprMasks.map(mask => mask.toString(16)).join(", ") ?? "-",
  option.registerInfo?.gpValue.toString(16) ?? "-"];

export const createElfMipsOptionModel = (metadata: ElfMipsMetadata, index: number): PagedSortableTableModel => ({
  id: `elf-mips-options-${index}`, pageSize: 100, rowCount: metadata.options?.length ?? 0,
  columns: ["Kind", "Section", "Info", "GPR mask (hex)", "CPR masks (hex)", "GP value (hex)"]
    .map(label => ({ label, className: "peNumeric" })),
  rowAt: row => metadata.options?.[row] ? { cells: optionCells(metadata.options[row]!).map(value =>
    ({ html: escapeHtml(value), sortValue: value, className: "peNumeric" })) } : null,
  sortValueAt: (row, column) => metadata.options?.[row] ? optionCells(metadata.options[row]!)[column] ?? "" : ""
});

const metadataFields = (metadata: ElfMipsMetadata): [string, string][] => {
  const flags = metadata.abiFlags;
  const registers = metadata.registerInfo;
  return [
    ...(flags ? Object.entries(flags).map(([name, value]): [string, string] =>
      [flagNames[name] ?? name, String(value)]) : []),
    ...(registers ? [["GPR mask", `0x${registers.gprMask.toString(16)}`],
      ["CPR masks", registers.cprMasks.map(mask => `0x${mask.toString(16)}`).join(", ")],
      ["GP value", `0x${registers.gpValue.toString(16)}`]] as [string, string][] : [])
  ];
};

export const renderElfMips = (elf: ElfParseResult, out: string[]): void => {
  for (const [index, metadata] of (elf.mips ?? []).entries()) {
    out.push(renderElfSectionStart(`MIPS ABI metadata (${metadata.source})`));
    const fields = metadataFields(metadata);
    if (fields.length) out.push(`<div class="tableWrap"><table class="table"><thead>` +
      `<tr><th>Field</th><th>Value</th></tr></thead><tbody>${fields.map(([name, value]) =>
        `<tr><td>${escapeHtml(name)}</td><td class="peNumeric">${escapeHtml(value)}</td></tr>`).join("")}` +
      `</tbody></table></div>`);
    if (metadata.options) out.push(renderAutoPagedSortableTable(createElfMipsOptionModel(metadata, index)));
    if (metadata.issues.length) out.push(`<ul>${metadata.issues.map(issue =>
      `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
    out.push(renderElfSectionEnd());
  }
};

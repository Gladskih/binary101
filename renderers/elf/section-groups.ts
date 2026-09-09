import { escapeHtml } from "../../html-utils.js";
import type { ElfParseResult, ElfSectionHeader } from "../../analyzers/elf/types.js";
import type { ElfSymbolTable } from "../../analyzers/elf/symbol-tables.js";
import type { ElfSectionGroup } from "../../analyzers/elf/section-groups.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";

const groupSignature = (
  header: ElfSectionHeader | undefined, sections: Map<number, ElfSectionHeader>,
  tables: Map<number, ElfSymbolTable>
): string => {
  const symbol = header ? tables.get(header.link)?.entries[header.info] : null;
  return symbol?.name || sections.get(symbol?.sectionIndex ?? -1)?.name || "Unresolved";
};

const groupFlags = (flags: number | null): string => flags == null ? "Unknown" :
  `${flags & 1 ? "COMDAT " : ""}0x${flags.toString(16)}`;

const groupRow = (
  group: ElfSectionGroup, sections: Map<number, ElfSectionHeader>, tables: Map<number, ElfSymbolTable>
): string => `<tr><td class="peNumeric">${group.sectionIndex}</td>` +
  `<td>${groupFlags(group.flags)}</td>` +
  `<td>${escapeHtml(groupSignature(sections.get(group.sectionIndex), sections, tables))}</td>` +
  `<td>${group.members.map(index =>
    escapeHtml(`#${index} ${sections.get(index)?.name ?? ""}`)).join(", ")}</td></tr>`;

export const renderElfSectionGroups = (elf: ElfParseResult, out: string[]): void => {
  if (!elf.sectionGroups?.length) return;
  const sections = new Map(elf.sections.map(section => [section.index, section]));
  const tables = new Map(elf.symbolTables?.map(table => [table.sectionIndex, table]));
  out.push(renderElfSectionStart("Section groups / COMDAT"));
  out.push(`<div class="tableWrap"><table class="table"><thead><tr>` +
    `<th>Group section</th><th>Flags</th><th>Signature</th><th>Member sections</th></tr></thead><tbody>`);
  for (const group of elf.sectionGroups) {
    out.push(groupRow(group, sections, tables));
  }
  out.push(`</tbody></table></div>`);
  const issues = elf.sectionGroups.flatMap(group => group.issues.map(issue =>
    `Group #${group.sectionIndex}: ${issue}`));
  if (issues.length) out.push(`<ul>${issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
  out.push(renderElfSectionEnd());
};

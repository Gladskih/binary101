import { escapeHtml } from "../../html-utils.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";

export const renderElfSectionGroups = (elf: ElfParseResult, out: string[]): void => {
  if (!elf.sectionGroups?.length) return;
  const sections = new Map(elf.sections.map(section => [section.index, section]));
  const tables = new Map(elf.symbolTables?.map(table => [table.sectionIndex, table]));
  out.push(renderElfSectionStart("Section groups / COMDAT"));
  out.push(`<div class="tableWrap"><table class="table"><thead><tr>` +
    `<th>Group section</th><th>Flags</th><th>Signature</th><th>Member sections</th></tr></thead><tbody>`);
  for (const group of elf.sectionGroups) {
    const header = sections.get(group.sectionIndex);
    const symbol = header ? tables.get(header.link)?.entries[header.info] : null;
    const signature = symbol?.name || sections.get(symbol?.sectionIndex ?? -1)?.name || "Unresolved";
    out.push(`<tr><td class="peNumeric">${group.sectionIndex}</td>` +
      `<td>${group.flags == null ? "Unknown" : `${group.flags & 1 ? "COMDAT " : ""}0x${group.flags.toString(16)}`}</td>` +
      `<td>${escapeHtml(signature)}</td><td>${group.members.map(index =>
        escapeHtml(`#${index} ${sections.get(index)?.name ?? ""}`)).join(", ")}</td></tr>`);
  }
  out.push(`</tbody></table></div>`);
  const issues = elf.sectionGroups.flatMap(group => group.issues.map(issue =>
    `Group #${group.sectionIndex}: ${issue}`));
  if (issues.length) out.push(`<ul>${issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
  out.push(renderElfSectionEnd());
};

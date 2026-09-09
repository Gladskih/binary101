import { escapeHtml } from "../../html-utils.js";
import type { ElfDynamicSymbol, ElfParseResult } from "../../analyzers/elf/types.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";

export const createElfVersionedSymbolName = (
  elf: ElfParseResult
): ((symbol: ElfDynamicSymbol) => string) => {
  const definitions = new Map(elf.symbolVersions?.definitions.map(item => [item.index, item.names[0]]));
  const requirements = new Map(elf.symbolVersions?.requirements.flatMap(item => item.versions)
    .map(item => [item.index & 0x7fff, item.name]));
  return symbol => {
  const raw = elf.symbolVersions?.symbols[symbol.index];
  if (raw == null) return symbol.name;
  // GNU versym: high bit marks a non-default version; low 15 bits are the index.
  // https://sourceware.org/binutils/docs/binutils/readelf.html (--symbols)
  const index = raw & 0x7fff;
  if (index <= 1) return symbol.name;
  const name = definitions.get(index) ?? requirements.get(index) ?? `#${index}`;
  return `${symbol.name}${definitions.has(index) && !(raw & 0x8000) && symbol.shndx !== 0 ? "@@" : "@"}${name}`;
  };
};

export const renderElfSymbolVersions = (elf: ElfParseResult, out: string[]): void => {
  const info = elf.symbolVersions;
  if (!info) return;
  out.push(renderElfSectionStart("Symbol versions"));
  const rows = [
    ...info.definitions.map(item => ["Definition", item.index, item.names[0] ?? "",
      item.names.slice(1).join(", "), item.flags]),
    ...info.requirements.flatMap(item => item.versions.map(version => [
      "Requirement", version.index & 0x7fff, version.name, item.file, version.flags
    ]))
  ];
  if (rows.length) {
    out.push(`<div class="tableWrap"><table class="table"><thead><tr>` +
      `<th>Kind</th><th>Index</th><th>Version</th><th>Library / parent versions</th><th>Flags</th>` +
      `</tr></thead><tbody>${rows.map(row => `<tr>${row.map((cell, index) =>
        `<td${index === 1 || index === 4 ? ' class="peNumeric"' : ""}>` +
        `${escapeHtml(String(cell))}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`);
  }
  out.push(`<p class="smallNote">${info.symbols.length} symbol version entries. ` +
    `Version suffixes appear in the imports and exports tables.</p>`);
  if (info.issues.length) {
    out.push(`<ul>${info.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
  }
  out.push(renderElfSectionEnd());
};

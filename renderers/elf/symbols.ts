"use strict";

import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";
import { escapeHtml } from "../../html-utils.js";
import type { ElfDynamicSymbol, ElfDynamicSymbolInfo, ElfParseResult } from "../../analyzers/elf/types.js";
import { formatElfHex } from "./value-format.js";
import { createElfVersionedSymbolName } from "./symbol-versions.js";
import { getElfSymbolDisplayName } from "../../analyzers/elf/symbol-names.js";
import { renderSymbolName } from "../symbol-name.js";
import { renderCountedCollection } from "../counted-collection.js";
import { elfSymbolValueHelp, elfSymbolVersionHelp, elfSymbolVisibilityText } from "./symbol-fields.js";

const renderSymbolTable = (title: string, symbols: ElfDynamicSymbol[], elf: ElfParseResult): string => {
  if (!symbols.length) return `<div class="smallNote dim">${escapeHtml(title)}: none.</div>`;
  const limit = 2000;
  const slice = symbols.slice(0, limit);
  const truncated = symbols.length > limit;
  const versionedName = createElfVersionedSymbolName(elf);
  const caption = truncated ? `${title} (showing ${limit} of ${symbols.length})` : `${title} (${symbols.length})`;

  const rows = slice
    .map(sym => {
      const name = sym.name ? renderSymbolName(versionedName(sym),
        versionedName(sym, getElfSymbolDisplayName(sym))) : "-";
      const bind = escapeHtml(sym.bindName);
      const type = escapeHtml(sym.typeName);
      const vis = escapeHtml(elfSymbolVisibilityText(sym.visibilityName,
        sym.other ?? sym.visibility, elf.header.machine));
      const value = sym.value ? escapeHtml(formatElfHex(sym.value)) : `<span class="dim">0</span>`;
      return `<tr><td>${name}</td><td>${bind}</td><td>${type}</td><td>${vis}</td>` +
        `<td class="peNumeric">${value}</td><td class="peNumeric">${sym.size}</td></tr>`;
    })
    .join("");

  return renderCountedCollection(escapeHtml(caption),
      `<div class="tableWrap"><table class="table" style="margin-top:.35rem"><thead><tr>` +
      `<th>Name</th><th>Bind</th><th>ELF type</th><th>Visibility</th>` +
      `<th title="${escapeHtml(elfSymbolValueHelp(elf.header.type))}">Value</th>` +
      `<th title="st_size is measured in bytes. Zero may mean unknown.">Size</th>` +
      `</tr></thead><tbody>${rows}</tbody></table></div>`, symbols.length
  );
};

const renderIssues = (info: ElfDynamicSymbolInfo): string => {
  if (!info.issues?.length) return "";
  const items = info.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return renderCountedCollection("Notes", `<ul>${items}</ul>`, info.issues.length);
};

export function renderElfSymbols(elf: ElfParseResult, out: string[]): void {
  const dyn = elf.dynSymbols;
  if (!dyn) return;

  const imports = dyn.importSymbols.length;
  const exports = dyn.exportSymbols.length;
  const total = dyn.total;

  out.push(renderElfSectionStart(`Imports / exports`));
  out.push(
    `<div class="smallNote">Dynamic symbols describe the interface exposed to (and required from) the dynamic loader. Imports are undefined symbols (SHN_UNDEF); exports are named, defined non-local symbols with external visibility.</div>`
  );
  out.push(
    `<div class="smallNote">Total dynamic symbols: ${escapeHtml(String(total))}; imports: ${escapeHtml(String(imports))}; exports: ${escapeHtml(
      String(exports)
    )}.</div>`
  );

  out.push(renderSymbolTable("Imported symbols", dyn.importSymbols, elf));
  out.push(renderSymbolTable("Exported symbols", dyn.exportSymbols, elf));
  if (elf.symbolVersions) out.push(`<p class="smallNote">${elfSymbolVersionHelp}</p>`);
  out.push(renderIssues(dyn));
  out.push(renderElfSectionEnd());
}

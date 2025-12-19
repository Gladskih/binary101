"use strict";

import { safe } from "../../html-utils.js";
import type { ElfDynamicSymbol, ElfDynamicSymbolInfo, ElfParseResult } from "../../analyzers/elf/types.js";
import { formatElfHex } from "./value-format.js";

const renderSymbolTable = (title: string, symbols: ElfDynamicSymbol[]): string => {
  if (!symbols.length) return `<div class="smallNote dim">${safe(title)}: none.</div>`;
  const limit = 2000;
  const slice = symbols.slice(0, limit);
  const truncated = symbols.length > limit;
  const caption = truncated ? `${title} (showing ${limit} of ${symbols.length})` : `${title} (${symbols.length})`;

  const rows = slice
    .map(sym => {
      const name = sym.name ? safe(sym.name) : "-";
      const bind = safe(sym.bindName);
      const type = safe(sym.typeName);
      const vis = safe(sym.visibilityName);
      const value = sym.value ? safe(formatElfHex(sym.value)) : `<span class="dim">0</span>`;
      return `<tr><td>${name}</td><td>${bind}</td><td>${type}</td><td>${vis}</td><td>${value}</td></tr>`;
    })
    .join("");

  return (
    `<details style="margin-top:.35rem"><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">${safe(
      caption
    )}</summary>` +
      `<div class="tableWrap"><table class="table" style="margin-top:.35rem"><thead><tr>` +
      `<th>Name</th><th>Bind</th><th>Type</th><th>Vis</th><th>Value</th>` +
      `</tr></thead><tbody>${rows}</tbody></table></div></details>`
  );
};

const renderIssues = (info: ElfDynamicSymbolInfo): string => {
  if (!info.issues?.length) return "";
  const items = info.issues.map(issue => `<li>${safe(issue)}</li>`).join("");
  return `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">Notes</summary><ul>${items}</ul></details>`;
};

export function renderElfSymbols(elf: ElfParseResult, out: string[]): void {
  const dyn = elf.dynSymbols;
  if (!dyn) return;

  const imports = dyn.importSymbols.length;
  const exports = dyn.exportSymbols.length;
  const total = dyn.total;

  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Imports / exports</h4>`);
  out.push(
    `<div class="smallNote">Dynamic symbols describe the interface exposed to (and required from) the dynamic loader. Imports are undefined symbols (SHN_UNDEF); exports are defined non-local symbols.</div>`
  );
  out.push(
    `<div class="smallNote">Total dynamic symbols: ${safe(String(total))}; imports: ${safe(String(imports))}; exports: ${safe(
      String(exports)
    )}.</div>`
  );

  out.push(renderSymbolTable("Imported symbols", dyn.importSymbols));
  out.push(renderSymbolTable("Exported symbols", dyn.exportSymbols));
  out.push(renderIssues(dyn));
  out.push(`</section>`);
}


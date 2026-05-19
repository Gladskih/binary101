"use strict";

import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import type { MachOImage, MachOSymbol } from "../../analyzers/macho/types.js";
import {
  sectionNameByIndex,
  summarizeSymbols,
  symbolBindingLabels,
  symbolDescriptionLabels,
  symbolTypeLabelFor
} from "./symbol-semantics.js";
import { formatByteSize, formatFileOffset, formatHex } from "./value-format.js";

const renderSymbols = (image: MachOImage, symbols: MachOSymbol[]): string => {
  if (!symbols.length) return "";
  const rows = symbols
    .map(symbol => {
      const binding = [...symbolBindingLabels(image, symbol), ...symbolDescriptionLabels(symbol)].join(", ");
      const sectionName = sectionNameByIndex(image, symbol.sectionIndex);
      return (
        `<tr><td>${symbol.index}</td><td><span class="mono">${escapeHtml(symbol.name || "")}</span></td>` +
        `<td>${escapeHtml(symbolTypeLabelFor(symbol))}</td>` +
        `<td><span class="mono">${escapeHtml(formatHex(symbol.value))}</span></td>` +
        `<td>${escapeHtml(sectionName || (symbol.sectionIndex ? `section ${symbol.sectionIndex}` : "-"))}</td>` +
        `<td>${escapeHtml(binding || "-")}</td></tr>`
      );
    })
    .join("");
  return (
    `<details><summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);border-radius:6px;background:var(--chip-bg)">` +
    `Show symbols (${symbols.length})</summary>` +
    `<div class="tableWrap"><table class="table"><thead><tr><th>#</th><th>Name</th><th>Type</th><th>Value</th><th>Section</th><th>Binding</th></tr></thead><tbody>` +
    `${rows}</tbody></table></div></details>`
  );
};

const renderSymtab = (image: MachOImage): string => {
  if (!image.symtab) return "";
  const counts = summarizeSymbols(image.symtab.symbols);
  return (
    `<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Symbols</h4><dl>` +
    renderDefinitionRow(
      "Symbol table",
      escapeHtml(`${image.symtab.nsyms} entries @ ${formatFileOffset(image.offset, image.symtab.symoff)}`)
    ) +
    renderDefinitionRow(
      "Strings",
      escapeHtml(`${formatByteSize(image.symtab.strsize)} @ ${formatFileOffset(image.offset, image.symtab.stroff)}`)
    ) +
    renderDefinitionRow("Local / defined / undefined", escapeHtml(`${counts.local} / ${counts.externalDefined} / ${counts.undefined}`)) +
    renderDefinitionRow("Debug / indirect", escapeHtml(`${counts.debug} / ${counts.indirect}`)) +
    `</dl>${renderSymbols(image, image.symtab.symbols)}</section>`
  );
};

export { renderSymtab };

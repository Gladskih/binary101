"use strict";

import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import { renderCoffDebugInfo } from "./debug-coff.js";

export const renderCoffSymbols = (pe: PeWindowsParseResult, out: string[]): void => {
  if (!pe.coffDebug) return;
  out.push(renderPeSectionStart(
    "COFF symbols",
    `${pe.coffDebug.symbols.length} symbol${pe.coffDebug.symbols.length === 1 ? "" : "s"}`
  ));
  out.push(
    `<div class="smallNote">Deprecated COFF symbol and line-number data referenced by ` +
      `PointerToSymbolTable/NumberOfSymbols in the COFF file header.</div>`
  );
  renderCoffDebugInfo(pe.coffDebug, out, "pe-coff-symbols");
  out.push(renderPeSectionEnd());
};

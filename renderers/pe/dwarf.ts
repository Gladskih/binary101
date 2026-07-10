"use strict";

import type { PeParseResult } from "../../analyzers/pe/index.js";
import { renderDwarfAnalysis } from "../dwarf.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";

export const renderPeDwarf = (pe: PeParseResult, out: string[]): void => {
  if (!pe.dwarf) return;
  out.push(renderPeSectionStart(
    "DWARF debug information",
    `${pe.dwarf.units.length} unit${pe.dwarf.units.length === 1 ? "" : "s"}`
  ));
  out.push(renderDwarfAnalysis(pe.dwarf));
  out.push(renderPeSectionEnd());
};

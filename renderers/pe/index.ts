"use strict";

import {
  isPeWindowsParseResult,
  type PeParseResult
} from "../../analyzers/pe/index.js";
import { renderHeaders } from "./headers.js";
import { renderInstructionSets } from "./disassembly.js";
import { renderLoadConfig } from "./load-config.js";
import {
  renderDebug,
  renderExports,
  renderTls,
  renderClr,
  renderSecurity,
  renderArchitectureDirectory,
  renderGlobalPtrDirectory
} from "./directories.js";
import {
  renderImportLinking,
  renderImports,
  renderBoundImports,
  renderDelayImports,
  renderIat
} from "./import-sections.js";
import { renderResources } from "./resources.js";
import {
  renderReloc,
  renderException,
  renderSanity
} from "./layout.js";

const renderIfPresent = <T>(
  value: T | null | undefined,
  render: (value: T, out: string[]) => void,
  out: string[]
): void => {
  if (value != null) render(value, out);
};

export function renderPe(pe: PeParseResult | null | undefined): string {
  if (!pe) return "";
  const out: string[] = [];
  renderHeaders(pe, out);
  if (isPeWindowsParseResult(pe)) {
    renderInstructionSets(pe.disassembly, out);
    renderLoadConfig(pe, out);
    renderIfPresent(pe.debug, renderDebug, out);
    renderImportLinking(pe, out);
    renderImports(pe, out);
    renderIfPresent(pe.resources, renderResources, out);
    renderIfPresent(pe.exports, renderExports, out);
    renderIfPresent(pe.tls, renderTls, out);
    renderIfPresent(pe.reloc, renderReloc, out);
    renderIfPresent(pe.exception, renderException, out);
    renderBoundImports(pe, out);
    renderDelayImports(pe, out);
    renderIfPresent(pe.clr, renderClr, out);
    renderIfPresent(pe.security, renderSecurity, out);
    renderIat(pe, out);
    renderArchitectureDirectory(pe, out);
    renderGlobalPtrDirectory(pe, out);
  }
  renderSanity(pe, out);
  return out.join("");
}

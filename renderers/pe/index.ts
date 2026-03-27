"use strict";

import type { PeParseResult } from "../../analyzers/pe/index.js";
import { renderHeaders } from "./headers.js";
import { renderInstructionSets } from "./disassembly.js";
import { renderLoadConfig } from "./load-config.js";
import {
  renderDebug,
  renderImports,
  renderExports,
  renderTls,
  renderClr,
  renderSecurity,
  renderIat
} from "./directories.js";
import { renderResources } from "./resources.js";
import {
  renderReloc,
  renderException,
  renderBoundImports,
  renderDelayImports,
  renderCoverage,
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
  renderInstructionSets(pe.disassembly, out);
  renderLoadConfig(pe, out);
  renderIfPresent(pe.debug, renderDebug, out);
  renderImports(pe.imports, out);
  renderIfPresent(pe.resources, renderResources, out);
  renderIfPresent(pe.exports, renderExports, out);
  renderIfPresent(pe.tls, renderTls, out);
  renderIfPresent(pe.reloc, renderReloc, out);
  renderIfPresent(pe.exception, renderException, out);
  renderIfPresent(pe.boundImports, renderBoundImports, out);
  renderIfPresent(pe.delayImports, renderDelayImports, out);
  renderIfPresent(pe.clr, renderClr, out);
  renderIfPresent(pe.security, renderSecurity, out);
  renderCoverage(pe.coverage, out);
  renderIfPresent(pe.iat, renderIat, out);
  renderSanity(pe, out);
  return out.join("");
}

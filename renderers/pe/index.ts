"use strict";

import {
  isPeWindowsParseResult,
  type PeParseResult
} from "../../analyzers/pe/index.js";
import { renderInstructionSets } from "./disassembly.js";
import { renderEntrypointDisassembly } from "./entrypoint-disassembly.js";
import { renderPeLazySectionShells } from "./lazy-section-shells.js";

export function renderPe(pe: PeParseResult | null | undefined): string {
  if (!pe) return "";
  const out: string[] = [];
  if (isPeWindowsParseResult(pe)) {
    renderInstructionSets(pe, out);
    renderEntrypointDisassembly(pe, out);
  }
  renderPeLazySectionShells(pe, out);
  return out.join("");
}

"use strict";

import { formatHumanSize, hex } from "../../binary-utils.js";
import { escapeHtml } from "../../html-utils.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { renderEntrypointExplorer } from "./entrypoint-disassembly-explorer.js";

const ENTRYPOINT_BUTTON_ID = "peEntrypointDisassembleButton";
const PROGRESS_WRAP_ID = "peEntrypointDisassemblyProgress";
const PROGRESS_STAGE_ID = "peEntrypointDisassemblyProgressStage";
const PROGRESS_DECODED_ID = "peEntrypointDisassemblyProgressDecoded";
const PROGRESS_BYTES_ID = "peEntrypointDisassemblyProgressBytes";
const PROGRESS_QUEUED_ID = "peEntrypointDisassemblyProgressQueued";

export const PE_ENTRYPOINT_DISASSEMBLY_PANEL_ID = "peEntrypointDisassemblyPanel";

const hasEntrypoint = (pe: PeWindowsParseResult): boolean =>
  Number.isSafeInteger(pe.opt.AddressOfEntryPoint) && pe.opt.AddressOfEntryPoint > 0;

const renderEntrypointActions = (pe: PeWindowsParseResult, out: string[]): void => {
  if (!hasEntrypoint(pe)) return;
  const label = pe.entrypointDisassembly
    ? "Re-disassemble entry point"
    : "Disassemble entry point";
  out.push(
    `<button type="button" class="actionButton" id="${ENTRYPOINT_BUTTON_ID}">` +
    `${escapeHtml(label)}</button>`
  );
};

const renderEntrypointReport = (pe: PeWindowsParseResult, out: string[]): void => {
  const report = pe.entrypointDisassembly;
  if (!report) {
    out.push(
      `<div class="smallNote dim" id="${PROGRESS_WRAP_ID}">` +
      `<div id="${PROGRESS_STAGE_ID}">Not disassembled yet.</div>` +
      `<div id="${PROGRESS_DECODED_ID}"></div>` +
      `<div id="${PROGRESS_BYTES_ID}"></div>` +
      `<div id="${PROGRESS_QUEUED_ID}"></div>` +
      `</div>`
    );
    return;
  }
  out.push(
    `<div class="smallNote">Entrypoint preview: ` +
    `${report.instructionCount} instruction(s), ${formatHumanSize(report.bytesDecoded)}, ` +
    `RVA ${hex(report.entrypointRva, 8)}.</div>`
  );
  out.push(renderEntrypointExplorer(report));
  if (!report.blocks.length && report.issues.length) {
    const items = report.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
    out.push(`<ul class="smallNote">${items}</ul>`);
  }
};

const renderEntrypointDisassemblyContent = (pe: PeWindowsParseResult, out: string[]): void => {
  if (!hasEntrypoint(pe) && !pe.entrypointDisassembly) return;
  out.push(
    `<details class="analysisPanel"><summary class="analysisPanelSummary">` +
    `<span class="detailsSummaryTitle">Entrypoint disassembly</span></summary>` +
    `<div class="analysisPanelBody"><div class="analysisPanelActions">`
  );
  renderEntrypointActions(pe, out);
  out.push(`</div>`);
  renderEntrypointReport(pe, out);
  out.push(`</div></details>`);
};

export const renderEntrypointDisassemblyPanel = (pe: PeWindowsParseResult): string => {
  const out: string[] = [];
  renderEntrypointDisassemblyContent(pe, out);
  return out.length ? `<section id="${PE_ENTRYPOINT_DISASSEMBLY_PANEL_ID}">${out.join("")}</section>` : "";
};

export const renderEntrypointDisassembly = (pe: PeWindowsParseResult, out: string[]): void => {
  out.push(renderEntrypointDisassemblyPanel(pe));
};

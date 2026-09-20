"use strict";

import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";
import { renderDefinitionRow, renderFlagChips, escapeHtml } from "../../html-utils.js";
import { DYNAMIC_FLAGS, DYNAMIC_FLAGS_1 } from "../../analyzers/elf/constants.js";
import type {
  ElfDynamicInfo,
  ElfInterpreterInfo,
  ElfOptionEntry,
  ElfParseResult
} from "../../analyzers/elf/types.js";
import { formatElfHex, formatElfList, formatElfMaybeHumanSize } from "./value-format.js";

const formatAddrOrDash = (value: bigint | null | undefined): string => (value != null ? escapeHtml(formatElfHex(value)) : "-");

const formatRangeOrDash = (range: { vaddr: bigint; size: bigint } | null | undefined): string => {
  if (!range) return "-";
  return `${escapeHtml(formatElfHex(range.vaddr))} (${formatElfMaybeHumanSize(range.size)})`;
};

const collectIssues = (interpreter?: ElfInterpreterInfo, dynamic?: ElfDynamicInfo): string[] => {
  const issues: string[] = [];
  interpreter?.issues?.forEach(issue => issues.push(`PT_INTERP: ${issue}`));
  dynamic?.issues?.forEach(issue => issues.push(`Dynamic: ${issue}`));
  return issues;
};

function formatDynamicFlags(value: number | null | undefined, knownFlags: ElfOptionEntry[]): string {
  if (value == null) return `<div class="dim">Tag absent</div>` + renderFlagChips(0, knownFlags);
  return `<div class="mono">${escapeHtml(formatElfHex(value >>> 0, 8))}</div>` +
    renderFlagChips(value, knownFlags);
}

export function renderElfLinking(elf: ElfParseResult, out: string[]): void {
  const interpreter = elf.interpreter;
  const dynamic = elf.dynamic;
  if (!interpreter && !dynamic) return;
  out.push(renderElfSectionStart(`Dynamic linking`));
  out.push(
    `<div class="smallNote">Interpreter and DT_* tags describe how the dynamic loader resolves shared libraries and startup routines.</div>`
  );
  out.push(`<dl>`);
  if (interpreter) {
    out.push(renderDefinitionRow("Interpreter (PT_INTERP)",
      interpreter.path ? `<span class="mono">${escapeHtml(interpreter.path)}</span>` : "-"));
  }
  if (dynamic) renderDynamic(dynamic, out);
  out.push(`</dl>`);
  const issues = collectIssues(interpreter, dynamic);
  if (issues.length) {
    out.push(
      `<details style="margin-top:.35rem"><summary class="dim" style="cursor:pointer">Notes</summary>` +
      `<ul>${issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul></details>`
    );
  }
  out.push(renderElfSectionEnd());
}

function renderDynamic(dynamic: ElfDynamicInfo, out: string[]): void {
  out.push(renderDefinitionRow("Needed (DT_NEEDED)", formatElfList(dynamic.needed)));
  out.push(renderDefinitionRow("SONAME (DT_SONAME)", dynamic.soname ? escapeHtml(dynamic.soname) : "-"));
  out.push(renderDefinitionRow("RPATH (DT_RPATH)", dynamic.rpath ? escapeHtml(dynamic.rpath) : "-"));
  out.push(renderDefinitionRow("RUNPATH (DT_RUNPATH)", dynamic.runpath ? escapeHtml(dynamic.runpath) : "-"));
  out.push(renderDefinitionRow("Init (DT_INIT)", formatAddrOrDash(dynamic.init)));
  out.push(renderDefinitionRow("Fini (DT_FINI)", formatAddrOrDash(dynamic.fini)));
  out.push(renderDefinitionRow("Preinit array", formatRangeOrDash(dynamic.preinitArray)));
  out.push(renderDefinitionRow("Init array", formatRangeOrDash(dynamic.initArray)));
  out.push(renderDefinitionRow("Fini array", formatRangeOrDash(dynamic.finiArray)));
  out.push(
    renderDefinitionRow(
      "Flags (DT_FLAGS)",
      formatDynamicFlags(dynamic.flags, DYNAMIC_FLAGS),
      "Base dynamic-loader behavior flags. Selected chips indicate set flags."
    )
  );
  out.push(
    renderDefinitionRow(
      "Flags_1 (DT_FLAGS_1)",
      formatDynamicFlags(dynamic.flags1, DYNAMIC_FLAGS_1),
      "Extended dynamic-loader behavior flags. Selected chips indicate set flags."
    )
  );
}

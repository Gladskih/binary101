import { escapeHtml } from "../../html-utils.js";
import type { ElfLsda } from "../../analyzers/elf/lsda-types.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";

const renderCounts = (
  lsdas: ElfLsda[], heading: string,
  metrics: ReadonlyArray<readonly [string, (lsda: ElfLsda) => number]>
): string =>
  `<h4>${heading}</h4><dl>` + metrics.map(([label, count]) =>
    `<dt>${label}</dt><dd>${lsdas.reduce((total, lsda) => total + count(lsda), 0)}</dd>`
  ).join("") + "</dl>";

// LLVM libcxxabi LSDA layout and scan_eh_tab:
// https://github.com/llvm/llvm-project/blob/main/libcxxabi/src/cxa_personality.cpp
// A nonzero landing pad with action zero is cleanup-only; otherwise it references
// an action chain, which can contain both catches and cleanup.
const renderCallSites = (lsdas: ElfLsda[]): string =>
  renderCounts(lsdas, "Code ranges", [
    ["Decoded code ranges", lsda => lsda.callSites.length],
    ["Ranges without a landing pad",
      lsda => lsda.callSites.filter(site => site.landingPad === 0n).length],
    ["Ranges with a landing pad",
      lsda => lsda.callSites.filter(site => site.landingPad > 0n).length],
    ["Ranges with direct cleanup only",
      lsda => lsda.callSites.filter(site => site.landingPad > 0n && site.action === 0n).length],
    ["Ranges referencing action chains",
      lsda => lsda.callSites.filter(site => site.landingPad > 0n && site.action > 0n).length]
  ]) + '<p class="smallNote">A landing pad is code used for exception handling or cleanup. ' +
    "Action chains may contain both catch and cleanup actions.</p>";

// In the same LLVM layout, filter zero means cleanup, positive means catch,
// negative means exception specification. Only a direct null type pointer
// establishes a catch-all here; indirect storage is not dereferenced by this parser.
const renderActions = (lsdas: ElfLsda[]): string =>
  renderCounts(lsdas, "Actions and types", [
    ["Decoded action records", lsda => lsda.actions.length],
    ["Cleanup action records", lsda => lsda.actions.filter(action => action.typeFilter === 0n).length],
    ["Catch action records", lsda => lsda.actions.filter(action => action.typeFilter > 0n).length],
    ["Exception specification action records",
      lsda => lsda.actions.filter(action => action.typeFilter < 0n).length],
    ["Referenced type entries", lsda => lsda.types.length],
    ["Catch-all type entries (direct null pointers)",
      lsda => lsda.types.filter(type =>
        type.pointer?.address === 0n && !type.pointer.indirect).length],
    ["Indirect type entries", lsda => lsda.types.filter(type => type.pointer?.indirect).length],
    ["Unreadable type entries", lsda => lsda.types.filter(type => type.pointer === null).length],
    ["Decoded exception specification lists", lsda => lsda.specifications.length]
  ]) + '<p class="smallNote">Type entries are counted per LSDA, not as unique C++ types. ' +
    "Indirect type references are not resolved to names or classified as catch-all.</p>";

const renderWarnings = (lsdas: ElfLsda[]): string => {
  const warnings = new Map<string, number>();
  for (const lsda of lsdas) {
    for (const issue of new Set(lsda.issues)) {
      warnings.set(issue, (warnings.get(issue) ?? 0) + 1);
    }
  }
  if (!warnings.size) return "";
  return '<h4>Warnings</h4><p class="smallNote">' +
    "Statistics may be partial because some exception data could not be fully decoded or validated." +
    '</p><div class="tableWrap"><table class="table"><thead><tr>' +
    '<th scope="col">Warning</th><th scope="col" class="peNumeric">Affected tables</th>' +
    "</tr></thead><tbody>" + [...warnings].map(([issue, count]) =>
      `<tr><td>${escapeHtml(issue)}</td><td class="peNumeric">${count}</td></tr>`
    ).join("") + "</tbody></table></div>";
};

export const renderElfLsda = (elf: ElfParseResult, out: string[]): void => {
  const lsdas = elf.lsdas ?? [];
  if (!lsdas.length) return;
  out.push(renderElfSectionStart("Exception tables (.gcc_except_table)"));
  out.push('<p class="smallNote">GCC/LLVM language-specific exception data (LSDA). ' +
    "These are counts of decoded metadata records, not counts of functions or source-level catch clauses.</p>");
  out.push(renderCounts(lsdas, "Tables", [
    ["Unique LSDA tables", () => 1],
    ["Tables with decoded call sites", lsda => Number(lsda.callSites.length > 0)],
    ["Tables with warnings", lsda => Number(lsda.issues.length > 0)]
  ]));
  out.push(renderWarnings(lsdas));
  out.push(renderCallSites(lsdas));
  out.push(renderActions(lsdas));
  out.push(renderElfSectionEnd());
};

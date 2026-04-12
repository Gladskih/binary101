"use strict";

import { safe } from "../../html-utils.js";

type PeDiagnosticGroup = {
  pattern: string;
  count: number;
  examples: string[];
};

const normalizeDiagnostic = (diagnostic: string): string =>
  diagnostic
    .replace(/0x[0-9a-f]+/gi, "0x...")
    .replace(/\bTYPE_\d+\b/g, "TYPE_#")
    .replace(/\b\d+\b/g, "#");

const collectDiagnosticGroups = (diagnostics: string[]): PeDiagnosticGroup[] => {
  const groups = new Map<string, PeDiagnosticGroup>();
  for (const diagnostic of diagnostics) {
    const pattern = normalizeDiagnostic(diagnostic);
    const existing = groups.get(pattern);
    if (existing) {
      existing.count += 1;
      if (existing.examples.length < 3) {
        existing.examples.push(diagnostic);
      }
      continue;
    }
    groups.set(pattern, {
      pattern,
      count: 1,
      examples: [diagnostic]
    });
  }
  return [...groups.values()].sort((left, right) => right.count - left.count);
};

const renderDiagnosticList = (diagnostics: string[]): string =>
  `<ul class="smallNote" style="color:var(--warning-text,#b45309)">` +
  diagnostics.map(diagnostic => `<li>${safe(diagnostic)}</li>`).join("") +
  `</ul>`;

const renderDiagnosticSummary = (
  summaryLabel: string,
  diagnostics: string[],
  groups: PeDiagnosticGroup[]
): string =>
  `<summary style="cursor:pointer;padding:.25rem .5rem;border:1px solid var(--border2);` +
  `border-radius:6px;background:var(--chip-bg);color:var(--warning-text,#b45309)">` +
  `<b>${safe(summaryLabel)}</b> - ${diagnostics.length} message${diagnostics.length === 1 ? "" : "s"}` +
  (diagnostics.length > 8
    ? ` grouped into ${groups.length} pattern${groups.length === 1 ? "" : "s"}`
    : "") +
  `</summary>`;

export const renderPeDiagnostics = (
  summaryLabel: string,
  diagnostics: string[]
): string => {
  if (!diagnostics.length) return "";
  const groups = diagnostics.length > 8 ? collectDiagnosticGroups(diagnostics) : [];
  if (diagnostics.length <= 8) {
    return (
      `<details style="margin-top:.5rem">` +
      renderDiagnosticSummary(summaryLabel, diagnostics, groups) +
      renderDiagnosticList(diagnostics) +
      `</details>`
    );
  }
  const rows = groups.map(group => {
    const examples = group.examples.map(example => `<div>${safe(example)}</div>`).join("");
    return (
      `<tr><td>${safe(group.pattern)}</td><td>${group.count}</td><td>${examples}</td></tr>`
    );
  }).join("");
  return (
    `<details style="margin-top:.5rem">` +
    renderDiagnosticSummary(summaryLabel, diagnostics, groups) +
    `<div class="smallNote" style="margin-top:.35rem">Patterns normalize offsets and other ` +
    `numeric fields so malformed files do not flood the UI with near-duplicate warnings.</div>` +
    `<table class="table" style="margin-top:.35rem"><thead><tr><th>Pattern</th><th>Count</th>` +
    `<th>Examples</th></tr></thead><tbody>${rows}</tbody></table></details>`
  );
};

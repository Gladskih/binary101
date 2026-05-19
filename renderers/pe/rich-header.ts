"use strict";

import { hex } from "../../binary-utils.js";
import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import type { PeRichHeader, PeRichHeaderEntry } from "../../analyzers/pe/types.js";
import { resolveRichBuildLabel } from "./rich-header-builds.js";
import { RICH_TOOL_TYPES } from "./rich-header-products.js";

const formatCompId = (entry: PeRichHeaderEntry): number =>
  (((entry.productId & 0xffff) << 16) | (entry.buildNumber & 0xffff)) >>> 0;

// Rich header mappings are community-sourced:
// - Product ID -> tool type: https://github.com/dishather/richprint/blob/master/comp_id.txt
// - Consolidated list as used by pe-parse: https://github.com/trailofbits/pe-parse/blob/master/pe-parser-library/src/parse.cpp
// Note: multiple Product IDs map to the same tool type (duplicates are expected).
const resolveToolLabel = (productId: number): string =>
  RICH_TOOL_TYPES[productId] ?? `Unrecognized product ${hex(productId, 4)}`;

const classifyTool = (toolLabel: string): string => {
  if (/LTCG|PGO/i.test(toolLabel)) return "Optimization";
  if (/CVTCIL|MSIL|IL assembler/i.test(toolLabel)) return "Managed/IL";
  if (/C\+\+|C$|C Std|C Book|Assembler|Basic|Visual Basic/i.test(toolLabel)) return "Compiler";
  if (/Linker|Import|Export|Alias object|CVTOMF|CVTPGD/i.test(toolLabel)) return "Link";
  if (/Resource/i.test(toolLabel)) return "Resource";
  return "Other";
};

const countBy = (
  entries: PeRichHeaderEntry[],
  labelForEntry: (entry: PeRichHeaderEntry) => string
): Map<string, number> => {
  const counts = new Map<string, number>();
  entries.forEach(entry => {
    const label = labelForEntry(entry);
    counts.set(label, (counts.get(label) ?? 0) + entry.count);
  });
  return counts;
};

const formatTopCounts = (counts: Map<string, number>, totalCount: number): string => {
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  return sorted.slice(0, 4).map(([label, count]) => {
    const share = totalCount > 0 ? `, ${((count / totalCount) * 100).toFixed(1)}%` : "";
    return `${escapeHtml(label)} <span class="mono">${count}${share}</span>`;
  }).join(" &middot; ");
};

const renderSignals = (entries: PeRichHeaderEntry[]): string => {
  const labels = entries.map(entry => resolveToolLabel(entry.productId));
  const signals = [
    labels.some(label => /LTCG/i.test(label)) ? "LTCG/link-time code generation" : null,
    labels.some(label => /PGO/i.test(label)) ? "PGO/profile-guided optimization" : null,
    labels.some(label => /CVTCIL|MSIL|IL assembler/i.test(label)) ? "Managed/IL inputs" : null,
    entries.some(entry => entry.productId === 0 || entry.productId === 1) ? "Unmarked objects" : null
  ].filter((signal): signal is string => signal != null);
  return signals.length
    ? signals.map(escapeHtml).join(" &middot; ")
    : "No LTCG/PGO/managed markers detected";
};

const renderCountCell = (count: number, maxCount: number, totalCount: number): string => {
  const barWidth = maxCount > 0 ? Math.round((count / maxCount) * 100) : 0;
  const share = totalCount > 0 ? (count / totalCount) * 100 : 0;
  const shareLabel = totalCount > 0 ? `${share.toFixed(1)}%` : "-";
  return `<div style="display:flex;align-items:center;gap:.45rem">
    <div style="flex:1;height:6px;background:var(--border2);border-radius:999px;overflow:hidden">
      <div data-rich-bar style="width:${barWidth}%;height:100%;background:var(--accent)"></div>
    </div>
    <span class="mono">${count} (${shareLabel})</span>
  </div>`;
};

export function renderRichHeader(rich: PeRichHeader, out: string[]): void {
  const entries = [...rich.entries].sort((a, b) => b.count - a.count);
  const totalCount = entries.reduce((sum, entry) => sum + entry.count, 0);
  const maxCount = entries.reduce((max, entry) => Math.max(max, entry.count), 0);

  out.push(`<section><h4 style="margin:0 0 .5rem 0;font-size:.9rem">Rich header</h4>`);
  out.push(
    `<div class="smallNote">A build fingerprint hidden in the DOS stub. It often lists tool components used to produce the binary (not security-critical, and sometimes stripped).</div>`
  );

  out.push(`<dl>`);
  out.push(renderDefinitionRow("Entries", String(entries.length), "Number of decoded tool records."));
  out.push(renderDefinitionRow("Total count", String(totalCount), "Sum of Rich header entry counts."));
  out.push(renderDefinitionRow("XOR key / checksum", hex(rich.xorKey, 8), "Stored Rich value used as the XOR key."));
  if (entries.length) {
    out.push(renderDefinitionRow("Tool mix", formatTopCounts(
      countBy(entries, entry => classifyTool(resolveToolLabel(entry.productId))),
      totalCount
    ), "Rich counts grouped by component role."));
    out.push(renderDefinitionRow("Toolsets", formatTopCounts(
      countBy(entries, entry => resolveRichBuildLabel(entry.buildNumber).replace(/ build .*/, "")),
      totalCount
    ), "Rich counts grouped by resolved or inferred toolset."));
    out.push(renderDefinitionRow("Signals", renderSignals(entries), "Best-effort hints derived from Rich product IDs."));
  }
  out.push(`</dl>`);

  if (rich.warnings?.length) {
    out.push(
      `<div class="smallNote" style="color:var(--warn-fg)">${escapeHtml(rich.warnings.join(" \u2022 "))}</div>`
    );
  }

  if (!entries.length) {
    out.push(`<div class="smallNote">No tool entries could be decoded.</div>`);
    out.push(`</section>`);
    return;
  }

  out.push(
    `<div class="smallNote">Tool and build names are best-effort (community Rich header research).</div>`
  );
  out.push(
    `<div class="tableWrap"><table class="table" style="margin-top:.35rem"><thead><tr><th>#</th><th>Tool</th><th>Toolchain</th><th>Count</th><th>CompID</th></tr></thead><tbody>`
  );
  entries.forEach((entry, index) => {
    const toolLabel = resolveToolLabel(entry.productId);
    const buildLabel = resolveRichBuildLabel(entry.buildNumber);
    const toolHtml = `<div>${escapeHtml(toolLabel)}</div><div class="smallNote">Product ${escapeHtml(
      hex(entry.productId, 4)
    )}</div>`;
    const buildHtml = `<div>${escapeHtml(buildLabel)}</div><div class="smallNote">Build ${escapeHtml(
      hex(entry.buildNumber, 4)
    )}</div>`;
    out.push(
      `<tr><td>${index + 1}</td><td>${toolHtml}</td><td>${buildHtml}</td><td>${renderCountCell(
        entry.count,
        maxCount,
        totalCount
      )}</td><td>${escapeHtml(hex(formatCompId(entry), 8))}</td></tr>`
    );
  });
  out.push(`</tbody></table></div>`);

  out.push(`</section>`);
}

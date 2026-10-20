import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug/directory.js";
import { humanSize } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";

export const renderFpoStatistics = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (!entry.fpo) return;
  const records = entry.fpo.records;
  out.push(`<dl>`);
  out.push(renderDefinitionRow("Record count", String(records.length)));
  out.push(renderDefinitionRow("Sum of procedure sizes", humanSize(records.reduce(
    (total, record) => total + record.procedureSize, 0)), "This is not unique code coverage."));
  out.push(renderDefinitionRow("Frames with SEH",
    String(records.filter(record => record.hasStructuredExceptionHandling).length)));
  out.push(renderDefinitionRow("Frames using a base pointer",
    String(records.filter(record => record.usesBasePointer).length)));
  out.push(renderDefinitionRow("Largest local stack allocation", humanSize(records.reduce(
    (largest, record) => Math.max(largest, record.localDwordCount * 4), 0))));
  out.push(renderDefinitionRow("Largest parameter area", humanSize(records.reduce(
    (largest, record) => Math.max(largest, record.parameterDwordCount * 4), 0))));
  out.push(`</dl><table class="table"><thead><tr><th>Frame kind</th>` +
    `<th class="peNumeric">Functions</th></tr></thead><tbody>`);
  // FRAME_FPO, FRAME_TRAP, FRAME_TSS, FRAME_NONFPO in Windows SDK winnt.h FPO_DATA.
  ["FPO", "Trap", "Task state segment", "Standard frame"].forEach((label, type) => {
    out.push(`<tr><td>${label}</td><td class="peNumeric">` +
      `${records.filter(record => record.frameType === type).length}</td></tr>`);
  });
  out.push(`</tbody></table>`);
};

export const renderPogoStatistics = (entry: PeDebugDirectoryEntry, out: string[]): void => {
  if (!entry.pogo) return;
  const entries = entry.pogo.entries;
  const largest = entries.reduce<(typeof entries)[number] | null>(
    (previous, region) => !previous || region.size > previous.size ? region : previous, null);
  out.push(`<p class="smallNote">POGO (profile-guided optimization) / ` +
    `LTCG (link-time code generation) records describe linker regions containing code or data. ` +
    `Their presence alone does not prove that profiling was used.</p><dl>`);
  out.push(renderDefinitionRow("Signature", escapeHtml(entry.pogo.signatureName)));
  out.push(renderDefinitionRow("Entry count", String(entries.length)));
  out.push(renderDefinitionRow("Sum of region sizes", humanSize(entries.reduce(
    (sum, region) => sum + region.size, 0)), "Regions may overlap; this is not unique code coverage."));
  out.push(renderDefinitionRow("Distinct region names", String(new Set(entries.map(region => region.name)).size)));
  out.push(renderDefinitionRow("Empty regions", String(entries.filter(region => region.size === 0).length)));
  if (largest) out.push(renderDefinitionRow("Largest region",
    `${escapeHtml(largest.name || "(unnamed)")} (${humanSize(largest.size)})`));
  out.push(`</dl>`);
};

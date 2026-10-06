import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import type { PeClrHeader } from "../../analyzers/pe/clr/types.js";

const metadataSummary = (clr: PeClrHeader): string => {
  const count = clr.meta?.tables?.rowCounts.reduce((sum, row) => sum + row.rows, 0) ?? 0;
  if (count > 0) return `CLR metadata: ${count >= 10_000 ? `${Math.round(count / 1000)}k` : count} rows`;
  return `runtime v${clr.MajorRuntimeVersion ?? 0}.${clr.MinorRuntimeVersion ?? 0}`;
};

export const getPeClrSectionDescriptor = (pe: PeWindowsParseResult):
{ key: "clr"; summary: string; title: string } | null => {
  if (pe.clr) return { key: "clr", title: "CLR (.NET) header", summary: metadataSummary(pe.clr) };
  return pe.readyToRun ? { key: "clr", title: "ReadyToRun composite header",
    summary: `${pe.readyToRun.sections.length} ReadyToRun sections` } : null;
};

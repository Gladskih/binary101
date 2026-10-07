import { escapeHtml } from "../../html-utils.js";
import { dwarfUnitRoot } from "../../analyzers/dwarf/attribute-values.js";
import { dwarfSplitFilename, dwarfSplitIdentity } from "../../analyzers/dwarf/external-files.js";
import type { DwarfAnalysis, DwarfUnit } from "../../analyzers/dwarf/types.js";

const fileRow = (filename: string, purpose: string, availability: string): string =>
  `<tr><td class="mono">${escapeHtml(filename)}</td><td>${escapeHtml(purpose)}</td>` +
  `<td>${escapeHtml(availability)}</td></tr>`;

const splitRows = (units: DwarfUnit[]): string[] => units.flatMap(unit => {
    const filename = dwarfSplitFilename(unit);
    if (!filename || unit.sectionName.endsWith(".dwo")) return [];
    const available = units.some(candidate => candidate.sectionName.endsWith(".dwo") &&
      dwarfSplitIdentity(candidate) != null && dwarfSplitIdentity(candidate) === dwarfSplitIdentity(unit));
    return [fileRow(filename, "Full debug information for " +
      (dwarfUnitRoot(unit)?.name ?? "this compilation unit"), available
      ? "Matching split unit decoded in this file" : "External file required")];
});

export const renderDwarfExternalFiles = (dwarf: DwarfAnalysis): string => {
  const rows = splitRows(dwarf.units);
  const supplementary = dwarf.supplementaryFile;
  if (supplementary) rows.push(fileRow(supplementary.filename || "This file", "Shared debug information",
    supplementary.isSupplementary ? "Supplementary object decoded locally" : "External file required"));
  if (dwarf.alternateFile) rows.push(fileRow(dwarf.alternateFile.filename, "Shared GNU debug information",
    "External file required"));
  return rows.length ? `<h5>Related debug files</h5><div class="tableWrap"><table class="table">` +
    `<thead><tr><th>File</th><th>Purpose</th><th>Availability</th></tr></thead>` +
    `<tbody>${rows.join("")}</tbody></table></div>` : "";
};

export const renderDwarfPackages = (dwarf: DwarfAnalysis): string => {
  const rows = dwarf.packageIndexes?.map(table => `<tr><td>${table.sectionName === ".debug_tu_index"
    ? "Shared types" : "Compilation units"}</td><td>DWARF package version ${table.version}</td>` +
    `<td class="dwarfTable__numeric">${table.rows.length}</td>` +
    `<td class="dwarfTable__numeric">${table.columns.length}</td></tr>`).join("");
  return rows ? `<h5>Packaged debug information</h5><div class="tableWrap"><table class="table">` +
    `<thead><tr><th>Contents</th><th>Encoding</th><th>Units</th><th>Contributing sections</th>` +
    `</tr></thead><tbody>${rows}</tbody></table></div>` : "";
};

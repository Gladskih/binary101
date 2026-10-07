"use strict";

import { escapeHtml } from "../html-utils.js";
import type { DwarfAnalysis, DwarfSectionSummary, DwarfSectionStatus, DwarfUnit } from "../analyzers/dwarf/types.js";
import { dwarfLanguageName, dwarfTagName, dwarfUnitTypeName } from "../analyzers/dwarf/constants.js";
import { dwarfUnitRoot } from "../analyzers/dwarf/attribute-values.js";
import { renderDwarfEntities } from "./dwarf/entities.js";
import { renderDwarfSourceLines } from "./dwarf/source-lines.js";
import { renderDwarfMacros } from "./dwarf/macros.js";
import { renderDwarfLookups } from "./dwarf/lookups.js";
import { renderDwarfFrames } from "./dwarf/frames.js";

const statusLabel = (status: DwarfSectionStatus): string => {
  if (status === "unavailable") return "unavailable; not decoded";
  if (status === "decoded") return "decoded";
  if (status === "referenced") return "used for references";
  if (status === "compressed-unsupported") return "compressed; not decoded";
  if (status === "relocations-unsupported") return "relocations required; not decoded";
  return "inventory only";
};

const sectionStatusLabel = (section: DwarfSectionSummary): string => {
  const label = statusLabel(section.status);
  return section.compressed && section.status !== "compressed-unsupported"
    ? `decompressed; ${label}` : label;
};

const renderSections = (dwarf: DwarfAnalysis): string => {
  const rows = dwarf.sections.map(section =>
    `<tr><td class="mono">${escapeHtml(section.name)}</td>` +
    `<td class="dwarfTable__numeric">${section.size}</td>` +
    `<td>${escapeHtml(sectionStatusLabel(section))}</td></tr>`
  ).join("");
  return `<h5>Sections</h5><div class="tableWrap"><table class="table">` +
    `<thead><tr><th>Name</th><th>Bytes</th><th>Analysis</th>` +
    `</tr></thead><tbody>${rows}</tbody></table></div>`;
};

const unitLanguage = (root: ReturnType<typeof dwarfUnitRoot>): string =>
  root?.language == null ? "-" : dwarfLanguageName(root.language);

const unitType = (unit: DwarfUnit, root: ReturnType<typeof dwarfUnitRoot>): string =>
  unit.unitType == null ? dwarfTagName(root?.tag ?? 0) : dwarfUnitTypeName(unit.unitType);

const renderUnitRow = (unit: DwarfUnit): string => {
  const root = dwarfUnitRoot(unit);
    const directory = root?.compilationDirectory
      ? `<div class="smallNote dim mono">${escapeHtml(root.compilationDirectory)}</div>` : "";
    return `<tr><td class="mono">${escapeHtml(root?.name ?? "(unnamed unit)")}${directory}</td>` +
      `<td>${escapeHtml(root?.producer ?? "-")}</td>` +
      `<td>${escapeHtml(unitLanguage(root))}</td>` +
      `<td>DWARF ${unit.version}; ${unit.format}-bit format; ${unit.addressSize}-byte addresses</td>` +
      `<td>${escapeHtml(unitType(unit, root))}</td>` +
      `<td class="dwarfTable__numeric">${unit.dies.length}</td></tr>`;
};

const renderUnits = (dwarf: DwarfAnalysis): string => {
  if (!dwarf.units.length) return "";
  const rows = dwarf.units.map(renderUnitRow).join("");
  return `<h5>Units</h5><div class="tableWrap"><table class="table"><thead><tr>` +
    `<th>Source</th><th>Producer</th><th>Language</th><th>Encoding</th><th>Type</th><th>DIEs</th>` +
    `</tr></thead><tbody>${rows}</tbody></table></div>`;
};

const renderTags = (dwarf: DwarfAnalysis): string => {
  const counts = new Map<number, number>();
  for (const unit of dwarf.units) {
    for (const die of unit.dies) counts.set(die.tag, (counts.get(die.tag) ?? 0) + 1);
  }
  if (!counts.size) return "";
  const rows = [...counts].sort((left, right) => right[1] - left[1]).map(([tag, count]) =>
    `<tr><td class="mono">${escapeHtml(dwarfTagName(tag))}</td>` +
    `<td class="dwarfTable__numeric">${count}</td></tr>`
  ).join("");
  return `<details><summary>DIE tag statistics (${counts.size} kinds)</summary>` +
    `<div class="tableWrap"><table class="table"><thead><tr>` +
    `<th>Tag</th><th>Count</th></tr></thead><tbody>${rows}</tbody></table></div></details>`;
};

const renderIssues = (dwarf: DwarfAnalysis): string => {
  if (!dwarf.issues.length) return "";
  return `<details open><summary>DWARF notices (${dwarf.issues.length})</summary><ul>` +
    dwarf.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("") + `</ul></details>`;
};

export const renderDwarfAnalysis = (dwarf: DwarfAnalysis): string =>
  `<p class="smallNote">Compilation units, program entities, types, variables, and source lines ` +
  `from DWARF. Sections marked inventory only are not decoded; unresolved data is reported below.</p>` +
  renderSections(dwarf) + renderUnits(dwarf) + renderDwarfEntities(dwarf) +
  renderDwarfSourceLines(dwarf) + renderDwarfMacros(dwarf) + renderDwarfLookups(dwarf) +
  renderDwarfFrames(dwarf) + renderTags(dwarf) + renderIssues(dwarf);

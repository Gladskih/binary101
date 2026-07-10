"use strict";

import { escapeHtml } from "../html-utils.js";
import type {
  DwarfAnalysis,
  DwarfSectionStatus,
  DwarfTagCount,
  DwarfUnit
} from "../analyzers/dwarf/types.js";
import {
  DWARF_TAG,
  dwarfLanguageName,
  dwarfTagName,
  dwarfUnitTypeName
} from "../analyzers/dwarf/constants.js";

const statusLabel = (status: DwarfSectionStatus): string => {
  if (status === "decoded") return "decoded";
  if (status === "referenced") return "used for references";
  if (status === "compressed-unsupported") return "compressed; not decoded";
  if (status === "relocations-unsupported") return "relocations required; not decoded";
  return "inventory only";
};

const hexValue = (value: number | bigint): string => `0x${value.toString(16)}`;

const dieCount = (unit: DwarfUnit): number =>
  unit.tagCounts.reduce((count, tag) => count + tag.count, 0);

const tagCount = (unit: DwarfUnit, tag: number): number =>
  unit.tagCounts.find(entry => entry.tag === tag)?.count ?? 0;

const renderSections = (dwarf: DwarfAnalysis): string => {
  const rows = dwarf.sections.map(section =>
    `<tr><td class="mono">${escapeHtml(section.name)}</td>` +
    `<td class="dwarfTable__numeric">${escapeHtml(hexValue(section.offset))}</td>` +
    `<td class="dwarfTable__numeric">${section.size}</td>` +
    `<td>${escapeHtml(statusLabel(section.status))}</td></tr>`
  ).join("");
  return `<h5>Sections</h5><div class="tableWrap"><table class="table">` +
    `<thead><tr><th>Name</th><th>File offset</th><th>Bytes</th><th>Analysis</th>` +
    `</tr></thead><tbody>${rows}</tbody></table></div>`;
};

const renderSource = (unit: DwarfUnit): string => {
  if (!unit.root?.name) return "-";
  const directory = unit.root.compilationDirectory
    ? `<div class="smallNote dim mono">${escapeHtml(unit.root.compilationDirectory)}</div>`
    : "";
  return `<span class="mono">${escapeHtml(unit.root.name)}</span>${directory}`;
};

const unitTypeLabel = (unit: DwarfUnit): string => {
  if (unit.unitType != null) return dwarfUnitTypeName(unit.unitType);
  return unit.root ? dwarfTagName(unit.root.tag) : "legacy unit";
};

const renderUnits = (dwarf: DwarfAnalysis): string => {
  if (!dwarf.units.length) return "";
  const rows = dwarf.units.map(unit =>
    `<tr><td class="dwarfTable__numeric">${escapeHtml(hexValue(unit.offset))}</td>` +
    `<td>DWARF ${unit.version}<div class="smallNote">${unit.format}-bit format</div></td>` +
    `<td>${escapeHtml(unitTypeLabel(unit))}</td>` +
    `<td class="dwarfTable__numeric">${unit.addressSize}</td>` +
    `<td>${renderSource(unit)}</td>` +
    `<td>${escapeHtml(unit.root?.producer ?? "-")}</td>` +
    `<td>${escapeHtml(
      unit.root?.language == null ? "-" : dwarfLanguageName(unit.root.language)
    )}</td>` +
    `<td class="dwarfTable__numeric">${dieCount(unit)}</td>` +
    `<td class="dwarfTable__numeric">${tagCount(unit, DWARF_TAG.subprogram)}</td>` +
    `<td class="dwarfTable__numeric">${unit.maxDepth}</td></tr>`
  ).join("");
  return `<h5>Units</h5><div class="tableWrap"><table class="table">` +
    `<thead><tr><th>Offset</th><th>Version</th><th>Type</th><th>Addr bytes</th>` +
    `<th>Source</th><th>Producer</th><th>Language</th><th>DIEs</th>` +
    `<th>Subprograms</th><th>Max depth</th></tr></thead><tbody>${rows}</tbody></table></div>`;
};

const aggregateTags = (dwarf: DwarfAnalysis): DwarfTagCount[] => {
  const counts = new Map<number, DwarfTagCount>();
  dwarf.units.forEach(unit => unit.tagCounts.forEach(tag => {
    const existing = counts.get(tag.tag);
    counts.set(tag.tag, { ...tag, count: tag.count + (existing?.count ?? 0) });
  }));
  return [...counts.values()].sort((left, right) => right.count - left.count);
};

const renderTags = (dwarf: DwarfAnalysis): string => {
  const tags = aggregateTags(dwarf);
  if (!tags.length) return "";
  const rows = tags.map(tag =>
    `<tr><td class="mono">${escapeHtml(dwarfTagName(tag.tag))}</td>` +
    `<td class="dwarfTable__numeric">${tag.count}</td></tr>`
  ).join("");
  return `<details><summary style="cursor:pointer">DIE tag statistics (${tags.length} kinds)` +
    `</summary><div class="tableWrap"><table class="table"><thead><tr>` +
    `<th>Tag</th><th>Count</th></tr></thead><tbody>${rows}</tbody></table></div></details>`;
};

const renderIssues = (dwarf: DwarfAnalysis): string => {
  if (!dwarf.issues.length) return "";
  return `<details open><summary style="cursor:pointer">DWARF notices ` +
    `(${dwarf.issues.length})</summary><ul>` +
    dwarf.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("") +
    `</ul></details>`;
};

export const renderDwarfAnalysis = (dwarf: DwarfAnalysis): string =>
  `<div class="smallNote">Compilation units and DIE structure from ` +
  `<span class="mono">.debug_info</span>/<span class="mono">.debug_types</span>. ` +
  `Line programs, ranges, locations, expressions, frames, macros, name indexes, split ` +
  `supplementary DWARF, and relocatable ELF DWARF are inventoried but not decoded in ` +
  `this iteration.</div>` +
  renderSections(dwarf) + renderUnits(dwarf) + renderTags(dwarf) + renderIssues(dwarf);

"use strict";

import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import type { MsvcRttiAnalysis } from "../../analyzers/pe/msvc-rtti/types.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import {
  getMsvcRttiPagedTableModel,
  MSVC_RTTI_VFTABLE_TABLE_ID
} from "./msvc-rtti-table.js";

export const getMsvcRttiSummaryCounts = (analysis: MsvcRttiAnalysis) => ({
  completeObjectLocators: new Set(
    analysis.completeObjectLocators.map(locator => locator.rva)
  ).size,
  types: new Set(analysis.types.map(type => type.rva)).size,
  vftables: new Set(analysis.vftables.map(vftable => vftable.rva)).size,
  virtualFunctionTargets: new Set(
    analysis.vftables.flatMap(vftable => vftable.functionTargetRvas)
  ).size
});

export const renderMsvcRtti = (pe: PeWindowsParseResult, out: string[]): void => {
  const analysis = pe.msvcRtti;
  if (!analysis) return;
  const counts = getMsvcRttiSummaryCounts(analysis);
  const table = getMsvcRttiPagedTableModel(pe, MSVC_RTTI_VFTABLE_TABLE_ID);
  if (!table) return;
  out.push(renderPeSectionStart(
    "Microsoft C++ RTTI",
    `${counts.types} types, ${counts.completeObjectLocators} COL, ${counts.vftables} vftables`
  ));
  out.push("<dl>");
  out.push(renderDefinitionRow("Layout", escapeHtml(analysis.layout)));
  out.push(renderDefinitionRow("Unique types", String(counts.types)));
  out.push(renderDefinitionRow(
    "Complete object locators",
    String(counts.completeObjectLocators)
  ));
  out.push(renderDefinitionRow("vftables", String(counts.vftables)));
  out.push(renderDefinitionRow(
    "Unique virtual function targets",
    String(counts.virtualFunctionTargets)
  ));
  out.push("</dl>");
  out.push(renderAutoPagedSortableTable(table));
  out.push(renderPeSectionEnd());
};

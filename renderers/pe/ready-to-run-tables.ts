import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type { PeClrHeader } from "../../analyzers/pe/clr/types.js";
import type { PeClrReadyToRun, PeClrReadyToRunSection } from "../../analyzers/pe/clr/ready-to-run-types.js";
import { readyToRunImageSections } from "../../analyzers/pe/clr/ready-to-run-image-sections.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { createAnalysisStatisticsTable } from "../analysis-statistics.js";
import { readyToRunStatistics } from "./ready-to-run-statistics.js";

const uniqueSections = (data: PeClrReadyToRun): PeClrReadyToRunSection[] => {
  const sections = new Map<string, PeClrReadyToRunSection>();
  for (const section of readyToRunImageSections(data)) {
    sections.set(`${section.type}:${section.rva}:${section.size}`, section);
  }
  return [...sections.values()];
};

const sectionModel = (sections: PeClrReadyToRunSection[]): PagedSortableTableModel => {
  const groups = new Map<string, { blocks: number; bytes: number }>();
  for (const section of sections) {
    const group = groups.get(section.name) ?? { blocks: 0, bytes: 0 };
    group.blocks++;
    group.bytes += section.size;
    groups.set(section.name, group);
  }
  const rows = [...groups].map(([name, group]) => [name, group.blocks, group.bytes]);
  return { id: "pe-r2r-sections", rowCount: rows.length, pageSize: 100, tableClassName: "readyToRunTable",
    columns: [{ label: "Section" }, { label: "Blocks", className: "peNumeric" },
      { label: "Encoded bytes", className: "peNumeric" }],
    rowAt: index => rows[index] ? { cells: rows[index]!.map((value, column) => ({
      html: escapeHtml(String(value)), sortValue: String(value), className: column ? "peNumeric" : ""
    })) } : null,
    sortValueAt: (row, column) => String(rows[row]?.[column] ?? "") };
};

export const createReadyToRunTableModels = (data: PeClrReadyToRun): PagedSortableTableModel[] => {
  const sections = uniqueSections(data);
  return [createAnalysisStatisticsTable("pe-r2r-statistics", readyToRunStatistics(sections)), sectionModel(sections)];
};

export const getReadyToRunTableModel = (
  clr: Pick<PeClrHeader, "readyToRun"> | null | undefined, id: string
): PagedSortableTableModel | null => id.startsWith("pe-r2r-") && clr?.readyToRun
  ? createReadyToRunTableModels(clr.readyToRun).find(model => model.id === id) ?? null : null;

export const renderReadyToRunData = (data: PeClrReadyToRun): string => {
  const text = data.sections.flatMap(section => section.decoded?.kind === "text"
    ? [renderDefinitionRow(section.name, escapeHtml(section.decoded.text),
      "Compiler information retained in the ReadyToRun image.")] : []).join("");
  return (text ? `<dl>${text}</dl>` : "") +
    `<p class="smallNote">ReadyToRun stores precompiled managed code and the dependencies needed to run it. ` +
    `The summary combines the root and readable component directories; shared sections are counted once.</p>` +
    createReadyToRunTableModels(data).filter(table => table.rowCount)
      .map(table => renderAutoPagedSortableTable(table)).join("");
};

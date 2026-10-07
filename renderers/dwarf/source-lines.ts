import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { escapeHtml } from "../../html-utils.js";
import { dwarfLineProgramForUnit } from "../../analyzers/dwarf/unit-sections.js";
import type { DwarfAnalysis, DwarfLineProgram, DwarfLineRow } from "../../analyzers/dwarf/types.js";
import { dwarfLineFile, dwarfSourcePath } from "./source-paths.js";

const rowFlags = (row: DwarfLineRow): string => [
  row.isStatement ? "statement" : "", row.basicBlock ? "basic block" : "",
  row.prologueEnd ? "prologue end" : "", row.epilogueBegin ? "epilogue begin" : "",
  row.discriminator ? `discriminator ${row.discriminator}` : "",
  row.isa ? `ISA ${row.isa}` : "",
  row.operationIndex ? `operation ${row.operationIndex}` : ""
].filter(Boolean).join(", ");

export const createDwarfSourceLineTableModel = (
  dwarf: DwarfAnalysis, program: DwarfLineProgram
): PagedSortableTableModel => {
  const unit = dwarf.units.find(item => dwarfLineProgramForUnit(dwarf, item) === program);
  const rows = program.rows.filter(row => !row.endSequence);
  const values: Array<(row: DwarfLineRow) => string> = [
    row => {
      const file = dwarfLineFile(program, row.file);
      return file ? dwarfSourcePath(program, file, unit) : "unresolved file " + row.file;
    },
    row => row.line.toString(), row => row.column ? row.column.toString() : "-", rowFlags
  ];
  return {
    id: dwarfSourceLineTableId(program), rowCount: rows.length,
    pageSize: 100, // Page navigation covers all source mappings; no records are dropped.
    columns: [{ label: "Source file" }, { label: "Line", className: "dwarfTable__numeric" },
      { label: "Column", className: "dwarfTable__numeric" }, { label: "Meaning" }],
    rowAt: rowIndex => {
      const row = rows[rowIndex];
      return row ? { cells: values.map((value, columnIndex) => ({
        html: escapeHtml(value(row)),
        className: columnIndex === 1 || columnIndex === 2 ? "dwarfTable__numeric" : ""
      })) } : null;
    },
    sortValueAt: (rowIndex, columnIndex) => {
      const row = rows[rowIndex];
      return row ? values[columnIndex]?.(row) ?? "" : "";
    }
  };
};

const renderProgramRows = (dwarf: DwarfAnalysis, program: DwarfLineProgram): string => {
  const model = createDwarfSourceLineTableModel(dwarf, program);
  return model.rowCount ? "<details><summary>Source line mappings (" + model.rowCount +
    ")</summary>" + renderAutoPagedSortableTable(model) + "</details>" : "";
};

const renderProgramFiles = (dwarf: DwarfAnalysis, program: DwarfLineProgram): string => {
  const unit = dwarf.units.find(item => dwarfLineProgramForUnit(dwarf, item) === program);
  return program.files.map(file => `<tr><td class="mono">${escapeHtml(
    dwarfSourcePath(program, file, unit) || "(empty path)"
  )}</td><td class="dwarfTable__numeric">${file.size ?? "-"}</td>` +
    `<td>${file.md5 ? Array.from(file.md5, byte => byte.toString(16).padStart(2, "0")).join("") : "-"}` +
    `</td></tr>`).join("");
};

export const dwarfSourceLineTableId = (program: DwarfLineProgram): string =>
  `dwarf-lines-${program.sectionName ? program.sectionName + "-" : ""}${program.offset}`;

export const renderDwarfSourceLines = (dwarf: DwarfAnalysis): string => {
  if (!dwarf.linePrograms.length) return "";
  return `<h5>Line programs</h5><p class="smallNote">Line programs are decoded into source files, ` +
    `line numbers, columns, and statement boundaries.</p>` + dwarf.linePrograms.map(program =>
    `<p>DWARF ${program.version}; ${program.files.length} source files; ` +
    `${program.rows.filter(row => row.endSequence).length} code sequences.</p>` +
    (program.files.length ? `<div class="tableWrap"><table class="table"><thead><tr>` +
      `<th>Source file</th><th>Bytes</th><th>Source MD5</th></tr></thead><tbody>` +
      renderProgramFiles(dwarf, program) + `</tbody></table></div>` : "") +
    renderProgramRows(dwarf, program)
  ).join("");
};

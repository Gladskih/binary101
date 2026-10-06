import { escapeHtml } from "../../html-utils.js";
import { dwarfUnitRoot } from "../../analyzers/dwarf/attribute-values.js";
import type { DwarfAnalysis, DwarfLineProgram, DwarfLineRow } from "../../analyzers/dwarf/types.js";
import { dwarfLineFile, dwarfSourcePath } from "./source-paths.js";

const rowFlags = (row: DwarfLineRow): string => [
  row.isStatement ? "statement" : "", row.basicBlock ? "basic block" : "",
  row.prologueEnd ? "prologue end" : "", row.epilogueBegin ? "epilogue begin" : "",
  row.discriminator ? `discriminator ${row.discriminator}` : "",
  row.isa ? `ISA ${row.isa}` : "",
  row.operationIndex ? `operation ${row.operationIndex}` : ""
].filter(Boolean).join(", ");

const renderProgramRows = (dwarf: DwarfAnalysis, program: DwarfLineProgram): string => {
  const unit = dwarf.units.find(item => dwarfUnitRoot(item)?.statementListOffset === BigInt(program.offset));
  const rows = program.rows.filter(row => !row.endSequence).map(row => {
    const file = dwarfLineFile(program, row.file);
    return `<tr><td class="mono">${escapeHtml(file
      ? dwarfSourcePath(program, file, unit) : `unresolved file ${row.file}`)}</td>` +
      `<td class="dwarfTable__numeric">${row.line}</td>` +
      `<td class="dwarfTable__numeric">${row.column || "-"}</td>` +
      `<td>${escapeHtml(rowFlags(row))}</td></tr>`;
  }).join("");
  if (!rows) return "";
  return `<details><summary>Source line mappings (${program.rows.filter(row => !row.endSequence).length})` +
    `</summary><div class="tableWrap"><table class="table"><thead><tr>` +
    `<th>Source file</th><th>Line</th><th>Column</th><th>Meaning</th>` +
    `</tr></thead><tbody>${rows}</tbody></table></div></details>`;
};

const renderProgramFiles = (dwarf: DwarfAnalysis, program: DwarfLineProgram): string => {
  const unit = dwarf.units.find(item => dwarfUnitRoot(item)?.statementListOffset === BigInt(program.offset));
  return program.files.map(file => `<tr><td class="mono">${escapeHtml(
    dwarfSourcePath(program, file, unit) || "(empty path)"
  )}</td><td class="dwarfTable__numeric">${file.size ?? "-"}</td>` +
    `<td>${file.md5 ? Array.from(file.md5, byte => byte.toString(16).padStart(2, "0")).join("") : "-"}` +
    `</td></tr>`).join("");
};

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

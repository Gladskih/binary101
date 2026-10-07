import { escapeHtml } from "../../html-utils.js";
import { dwarfAttributeValue, dwarfNumericValue } from "../../analyzers/dwarf/attribute-values.js";
import { dwarfLineProgramForUnit, dwarfSectionContributionAt,
  dwarfUnitContribution } from "../../analyzers/dwarf/unit-sections.js";
import type { DwarfMacroEntry, DwarfMacroUnit } from "../../analyzers/dwarf/macro-types.js";
import type { DwarfAnalysis, DwarfFormValue, DwarfLineProgram, DwarfUnit } from "../../analyzers/dwarf/types.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { dwarfLineFile, dwarfSourcePath } from "./source-paths.js";

const macroOwner = (dwarf: DwarfAnalysis, macro: DwarfMacroUnit): DwarfUnit | undefined =>
  dwarf.units.find(unit => {
    if (unit.sectionName.endsWith(".dwo") !== macro.sectionName.endsWith(".dwo")) return false;
    const root = unit.dies[0];
    const reference = macro.version == null ? dwarfAttributeValue(root, 0x43)
      : dwarfAttributeValue(root, 0x79) ?? dwarfAttributeValue(root, 0x2119);
    const offset = dwarfNumericValue(reference);
    const base = dwarfUnitContribution(dwarf, unit, macro.sectionName.replace(/\.dwo$/, ""))?.offset ?? 0;
    return offset != null && offset + BigInt(base) === BigInt(macro.offset);
  });

const operandText = (value: DwarfFormValue | undefined): string => {
  if (!value) return "";
  if (value.kind === "string") return value.value;
  if (value.kind === "block") return `${value.value.length}-byte vendor data`;
  if (value.kind === "flag") return value.value ? "yes" : "no";
  if (value.kind.startsWith("string-")) return "unresolved macro text";
  return dwarfNumericValue(value)?.toString() ?? "unresolved vendor operand";
};

const action = (opcode: number): string => {
  if ([1, 5, 8, 11].includes(opcode)) return "define";
  if ([2, 6, 9, 12].includes(opcode)) return "undefine";
  if (opcode === 3) return "include file";
  if (opcode === 4) return "end file";
  if (opcode === 7) return "import shared macros";
  if (opcode === 10) return "import supplementary macros";
  return "vendor directive";
};

const importedText = (dwarf: DwarfAnalysis, owner: DwarfMacroUnit, entry: DwarfMacroEntry): string => {
  const offset = dwarfNumericValue(entry.operands[0]);
  const base = dwarfSectionContributionAt(dwarf, owner.sectionName, owner.offset)?.offset ?? 0;
  const target = offset == null ? null : dwarf.macros?.find(macro => macro.version != null &&
    macro.sectionName === owner.sectionName && BigInt(macro.offset) === offset + BigInt(base));
  return target ? `${target.entries.length} directives in shared sequence`
    : "unresolved macro sequence";
};

const entryText = (dwarf: DwarfAnalysis, owner: DwarfMacroUnit, entry: DwarfMacroEntry): string => {
  if (entry.opcode === 7) return importedText(dwarf, owner, entry);
  if (entry.opcode === 10) return "external debug file required";
  if (entry.opcode === 3 || entry.opcode === 4) return "";
  return entry.opcode === 255 ? entry.operands.map(operandText).join("; ")
    : operandText(entry.operands[1] ?? entry.operands[0]);
};

const sourceNames = (dwarf: DwarfAnalysis, macro: DwarfMacroUnit): string[] => {
  const owner = macroOwner(dwarf, macro);
  const program = macroLineProgram(dwarf, macro, owner);
  const files: bigint[] = [];
  return macro.entries.map(entry => {
    if (entry.opcode === 4) { files.pop(); return ""; }
    if (entry.opcode === 3) files.push(dwarfNumericValue(entry.operands[1]) ?? -1n);
    const index = files.at(-1);
    const line = [1, 2, 3, 5, 6, 8, 9, 11, 12].includes(entry.opcode)
      ? dwarfNumericValue(entry.operands[0]) : null;
    if (index == null) return line === 0n ? "compiler / command line" : "shared or unrecorded source";
    return sourcePath(program, index, owner) + (line ? `:${line}` : "");
  });
};

const macroLineProgram = (dwarf: DwarfAnalysis, macro: DwarfMacroUnit,
  owner: DwarfUnit | undefined): DwarfLineProgram | undefined => {
  if (macro.lineOffset == null) return owner ? dwarfLineProgramForUnit(dwarf, owner) : undefined;
  const name = macro.sectionName.replace(/macro|macinfo/, "line");
  const base = dwarfSectionContributionAt(dwarf, macro.sectionName, macro.offset, name)?.offset ?? 0;
  return dwarf.linePrograms.find(program => (program.sectionName ?? ".debug_line") === name &&
    BigInt(program.offset) === macro.lineOffset! + BigInt(base));
};

const sourcePath = (program: DwarfLineProgram | undefined, index: bigint,
  owner: DwarfUnit | undefined): string => {
  const file = program ? dwarfLineFile(program, index) : undefined;
  return file && program ? dwarfSourcePath(program, file, owner) : `unresolved file ${index}`;
};

export const createDwarfMacroTableModel = (dwarf: DwarfAnalysis, macro: DwarfMacroUnit): PagedSortableTableModel => {
  const sources = sourceNames(dwarf, macro);
  const values = (index: number): string[] => {
    const entry = macro.entries[index];
    return entry ? [action(entry.opcode), entryText(dwarf, macro, entry), sources[index] ?? ""] : [];
  };
  return {
    id: `dwarf-macros-${macro.sectionName}-${macro.offset}`, pageSize: 100,
    rowCount: macro.entries.length,
    columns: [{ label: "Directive" }, { label: "Macro / definition" }, { label: "Source" }],
    rowAt: index => macro.entries[index] ? { cells: values(index).map(value => ({ html: escapeHtml(value) })) } : null,
    sortValueAt: (index, column) => values(index)[column] ?? ""
  };
};

export const renderDwarfMacros = (dwarf: DwarfAnalysis): string => {
  const macros = dwarf.macros?.filter(macro => macro.entries.length) ?? [];
  if (!macros.length) return "";
  return "<h5>Preprocessor macros</h5>" + macros.map((macro, index) =>
    `<details><summary>Macro sequence ${index + 1}: ${macro.entries.length} directives</summary>` +
    renderAutoPagedSortableTable(createDwarfMacroTableModel(dwarf, macro)) + "</details>"
  ).join("");
};

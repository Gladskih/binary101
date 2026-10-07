import { escapeHtml } from "../../html-utils.js";
import { evaluateDwarfCfi } from "../../analyzers/dwarf/cfi-state.js";
import { dwarfAttributeValue } from "../../analyzers/dwarf/attribute-values.js";
import { dwarfCodeRanges } from "../../analyzers/dwarf/code-ranges.js";
import type { DwarfAnalysis } from "../../analyzers/dwarf/types.js";
import type { DwarfFrameFde } from "../../analyzers/dwarf/frame-types.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { dwarfCfaRuleText, dwarfRegisterRuleText } from "./cfi-rules.js";

export const createDwarfFrameRuleTableModel = (dwarf: DwarfAnalysis,
  fde: DwarfFrameFde): PagedSortableTableModel => {
  const cie = dwarf.frames?.cies.find(cie => cie.offset === fde.cieOffset);
  const rows = cie?.encoding ? evaluateDwarfCfi({ ...cie.encoding, instructions: cie.instructions }, fde).rows : [];
  const values = (index: number): string[] => {
    const row = rows[index];
    return row ? [`+${row.location - fde.start} bytes`, dwarfCfaRuleText(row.cfa),
      Object.entries(row.registers).map(([register, rule]) => `register ${register}: ${dwarfRegisterRuleText(rule)}`).join("; "),
      row.returnAddressSigned ? "signed" : "unsigned", String(row.argumentSize)] : [];
  };
  return { id: `dwarf-frame-rules-${fde.offset}`, pageSize: 100, rowCount: rows.length,
    columns: ["Position in region", "Frame address", "Caller register recovery", "Return address", "Argument bytes"]
      .map(label => ({ label })),
    rowAt: index => rows[index] ? { cells: values(index).map(text => ({ html: escapeHtml(text) })) } : null,
    sortValueAt: (index, column) => values(index)[column] ?? "" };
};

const functionNames = (dwarf: DwarfAnalysis): Map<bigint, string> => {
  const names = new Map<bigint, string>();
  for (const unit of dwarf.units) for (const die of unit.dies) {
    if (die.tag !== 0x2e) continue; // DW_TAG_subprogram, DWARF 5 Table 7.1.
    const name = dwarfAttributeValue(die, 0x03);
    for (const range of dwarfCodeRanges(die)) {
      if (name?.kind === "string") names.set(range.start, name.value);
    }
  }
  return names;
};

const recoveryRules = (dwarf: DwarfAnalysis, fde: DwarfFrameFde): string => {
  const model = createDwarfFrameRuleTableModel(dwarf, fde);
  return model.rowCount ? renderAutoPagedSortableTable(model) : "Recovery rules are unavailable";
};

export const createDwarfFrameTableModel = (dwarf: DwarfAnalysis): PagedSortableTableModel => {
  const frames = dwarf.frames;
  const names = functionNames(dwarf);
  const common = new Map(frames?.cies.map(cie => [cie.offset, cie]));
  const values = (index: number): string[] => {
    const fde = frames?.fdes[index];
    const encoding = fde && common.get(fde.cieOffset)?.encoding;
    return fde ? [names.get(fde.start) ?? "Unresolved function", String(fde.range),
      encoding ? `register ${encoding.returnRegister}` : "Unresolved return register"] : [];
  };
  return { id: "dwarf-frames", pageSize: 100, rowCount: frames?.fdes.length ?? 0,
    columns: ["Function", "Covered bytes", "Return address register", "Recovery rules"].map(label => ({ label })),
    rowAt: index => frames?.fdes[index] ? { cells: [...values(index).map(text => ({ html: escapeHtml(text) })),
      { html: recoveryRules(dwarf, frames.fdes[index]!) }] } : null,
    sortValueAt: (index, column) => values(index)[column] ?? "" };
};

export const renderDwarfFrames = (dwarf: DwarfAnalysis): string => dwarf.frames?.fdes.length
  ? `<details><summary>Stack and caller recovery (${dwarf.frames.fdes.length} regions)</summary>` +
    renderAutoPagedSortableTable(createDwarfFrameTableModel(dwarf)) + "</details>" : "";

export const getDwarfFrameTableModel = (dwarf: DwarfAnalysis, id: string): PagedSortableTableModel | null => {
  if (id === "dwarf-frames") return createDwarfFrameTableModel(dwarf);
  const fde = dwarf.frames?.fdes.find(fde => id === `dwarf-frame-rules-${fde.offset}`);
  return fde ? createDwarfFrameRuleTableModel(dwarf, fde) : null;
};

import { renderCollectionStart, renderCollectionEnd } from "../counted-collection.js";
import { dwarfExpressionText } from "../dwarf/expressions.js";
import { renderDwarfFrames } from "../dwarf/frames.js";
import { escapeHtml } from "../../html-utils.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { ElfCfiInstruction, ElfUnwindPointer, ElfUnwindSection } from
  "../../analyzers/elf/unwind-types.js";
import type { PagedSortableTableModel } from "../../ui/paged-sortable-table-state.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";
import { renderElfCfiState } from "./cfi-state.js";
import { formatElfHex } from "./value-format.js";

const pointerText = (pointer: ElfUnwindPointer | null): string => pointer
  ? `${pointer.indirect ? "Indirect at " : ""}0x${pointer.address.toString(16)}` : "—";

const formatOperand = (operation: string, operand: ElfCfiInstruction["operands"][number]): string => {
  if (Array.isArray(operand)) return dwarfExpressionText(operand);
  if (operation === "set_loc" && typeof operand === "bigint") return formatElfHex(operand);
  return String(operand);
};

const instructionsHtml = (instructions: ElfCfiInstruction[]): string => {
  if (!instructions.length) return "—";
  return `${renderCollectionStart(`${instructions.length} instructions`, instructions.length)}<table class="table">` +
    `<thead><tr><th>Offset</th><th>Operation</th><th>Operands</th></tr></thead><tbody>` +
    instructions.map(item => `<tr><td class="peNumeric">0x${item.offset.toString(16)}</td>` +
      `<td>${escapeHtml(item.operation)}</td>` +
      `<td>${escapeHtml(item.operands.map(operand => formatOperand(item.operation, operand)).join(", "))}</td></tr>`)
      .join("") + `</tbody></table>${renderCollectionEnd(instructions.length)}`;
};

export const createElfUnwindTableModel = (section: ElfUnwindSection): PagedSortableTableModel => {
  const rules = new Map<number, string>();
  const ruleHtml = (index: number): string => {
    if (rules.has(index)) return rules.get(index)!;
    const fde = section.fdes[index]!;
    const cie = section.cies.find(item => item.offset === fde.cieOffset);
    const html = cie ? renderElfCfiState(cie, fde) : "Missing CIE";
    rules.set(index, html);
    return html;
  };
  const values = (index: number): string[] => {
    const fde = section.fdes[index];
    return fde ? [`0x${fde.offset.toString(16)}`, `0x${fde.cieOffset.toString(16)}`,
      pointerText(fde.start), String(fde.range), pointerText(fde.lsda), String(fde.instructions.length)] : [];
  };
  return { id: elfUnwindTableId(section), pageSize: 100, rowCount: section.fdes.length,
    columns: ["FDE offset", "CIE offset", "PC start", "PC bytes", "LSDA", "CFI"]
      .map((label, column) => ({ label, className: column < 5 ? "peNumeric" : "" })),
    rowAt: index => section.fdes[index] ? { cells: values(index).map((value, column) => ({
      html: column === 5 ? instructionsHtml(section.fdes[index]!.instructions) + ruleHtml(index) : escapeHtml(value),
      sortValue: value, className: column < 5 ? "peNumeric" : ""
    })) } : null,
    sortValueAt: (index, column) => values(index)[column] ?? ""
  };
};

const renderUnwindSection = (elf: ElfParseResult, section: ElfUnwindSection, out: string[]): void => {
  const name = elf.sections.find(item => item.index === section.sectionIndex)?.name;
  out.push(renderElfSectionStart(elfUnwindTitle(section, name)));
  if (name === ".debug_frame" && elf.dwarf?.frames) {
    out.push(renderDwarfFrames(elf.dwarf), renderElfSectionEnd());
    return;
  }
  // https://github.com/ARM-software/abi-aa/blob/main/aadwarf64/aadwarf64.rst#dwarf-register-names
  if (elf.header.machine === 183) out.push(`<p class="smallNote">AArch64 DWARF registers: ` +
    `r0–r30 = x0–x30; r30 = link register; r31 = sp; r64–r95 = v0–v31.</p>`);
  out.push(`<p class="smallNote">CFI offsets are shown as encoded values and use the CIE alignment factors. ` +
    `The set_loc operand is a decoded address. ` +
    `Indirect pointers identify pointer storage. DWARF expressions are shown as bytes.</p>`);
  if (section.cies.length) {
    out.push(`<div class="tableWrap"><table class="table"><thead><tr>` +
      `<th>CIE offset</th><th>Version</th><th>Augmentation</th><th>Code alignment</th>` +
      `<th>Data alignment</th><th>Return register</th><th>Personality</th><th>CFI</th></tr></thead><tbody>` +
      section.cies.map(cie => `<tr><td class="peNumeric">0x${cie.offset.toString(16)}</td>` +
        `<td class="peNumeric">${cie.version}</td>` +
        `<td>${escapeHtml(cie.augmentation)}</td><td class="peNumeric">${cie.codeAlignment}</td>` +
        `<td class="peNumeric">${cie.dataAlignment}</td><td class="peNumeric">${cie.returnRegister}</td>` +
        `<td>${escapeHtml(pointerText(cie.personality))}</td>` +
        `<td>${instructionsHtml(cie.instructions)}</td></tr>`).join("") + `</tbody></table></div>`);
  }
  if (section.fdes.length) out.push(renderAutoPagedSortableTable(createElfUnwindTableModel(section)));
  if (section.issues.length) {
    out.push(`<ul>${section.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
  }
  out.push(renderElfSectionEnd());
};

export const renderElfUnwind = (elf: ElfParseResult, out: string[], onlyIndex?: number): void => {
  for (const [index, section] of (elf.unwind ?? []).entries()) {
    if (onlyIndex != null && index !== onlyIndex) continue;
    renderUnwindSection(elf, section, out);
  }
};

export const elfUnwindTitle = (section: ElfUnwindSection, name: string | undefined): string =>
  `${section.sectionIndex === null
    ? `.eh_frame via PT_GNU_EH_FRAME #${section.programHeaderIndex}` : name ?? "Unwind"}: call frame information`;

export const elfUnwindTableId = (section: ElfUnwindSection): string =>
  section.sectionIndex === null
    ? `elf-unwind-segment-${section.programHeaderIndex}` : `elf-unwind-${section.sectionIndex}`;

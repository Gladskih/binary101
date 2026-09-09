import { escapeHtml } from "../../html-utils.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { ElfCfiInstruction, ElfUnwindPointer, ElfUnwindSection } from
  "../../analyzers/elf/unwind-types.js";
import type { PagedSortableTableModel } from "../../ui/paged-sortable-table-state.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";

const pointerText = (pointer: ElfUnwindPointer | null): string => pointer
  ? `${pointer.indirect ? "Indirect at " : ""}0x${pointer.address.toString(16)}` : "—";

const instructionsHtml = (instructions: ElfCfiInstruction[]): string => {
  if (!instructions.length) return "—";
  return `<details><summary>${instructions.length} instructions</summary><table class="table">` +
    `<thead><tr><th>Offset</th><th>Operation</th><th>Encoded operands</th></tr></thead><tbody>` +
    instructions.map(item => `<tr><td class="peNumeric">0x${item.offset.toString(16)}</td>` +
      `<td>${escapeHtml(item.operation)}</td><td>${escapeHtml(item.operands.map(String).join(", "))}</td></tr>`)
      .join("") + `</tbody></table></details>`;
};

export const createElfUnwindTableModel = (section: ElfUnwindSection): PagedSortableTableModel => {
  const values = (index: number): string[] => {
    const fde = section.fdes[index];
    return fde ? [`0x${fde.offset.toString(16)}`, `0x${fde.cieOffset.toString(16)}`,
      pointerText(fde.start), String(fde.range), pointerText(fde.lsda), String(fde.instructions.length)] : [];
  };
  return { id: `elf-unwind-${section.sectionIndex}`, pageSize: 100, rowCount: section.fdes.length,
    columns: ["FDE offset", "CIE offset", "PC start", "PC bytes", "LSDA", "CFI"]
      .map(label => ({ label, className: "peNumeric" })),
    rowAt: index => section.fdes[index] ? { cells: values(index).map((value, column) => ({
      html: column === 5 ? instructionsHtml(section.fdes[index]!.instructions) : escapeHtml(value),
      sortValue: value, className: "peNumeric"
    })) } : null,
    sortValueAt: (index, column) => values(index)[column] ?? ""
  };
};

export const renderElfUnwind = (elf: ElfParseResult, out: string[]): void => {
  for (const section of elf.unwind ?? []) {
    const name = elf.sections.find(item => item.index === section.sectionIndex)?.name ?? "Unwind";
    out.push(renderElfSectionStart(`${name}: call frame information`));
    out.push(`<p class="smallNote">CFI operands are encoded values; offsets use the CIE alignment factors. ` +
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
  }
};

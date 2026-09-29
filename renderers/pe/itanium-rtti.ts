import type { ItaniumRttiAnalysis } from "../../analyzers/itanium-rtti/types.js";
import { escapeHtml } from "../../html-utils.js";
import { renderPeSectionEnd, renderPeSectionStart } from "./collapsible-section.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from
  "../paged-sortable-table.js";

const address = (value: number): string => `0x${value.toString(16)}`;

const tableModel = (
  id: string, headings: string[], rows: string[][]
): PagedSortableTableModel => {
  const columns = headings.map(label => ({ label,
    className: /RVA|^Offset$|flags/.test(label) ? "peNumeric" : "" }));
  return { id, columns, rowCount: rows.length, pageSize: 250,
    rowAt: index => rows[index] ? { cells: rows[index].map((cell, column) => ({
      html: escapeHtml(cell), sortValue: cell, className: columns[column]!.className
    })) } : null,
    sortValueAt: (row, column) => rows[row]?.[column] ?? ""
  };
};

export const getItaniumRttiTableModel = (
  analysis: ItaniumRttiAnalysis | null | undefined, id: string
): PagedSortableTableModel | null => {
  if (!analysis) return null;
  switch (id) {
    case "pe-itanium-types": return tableModel(id,
      ["RVA", "Encoded name", "Kind", "Hierarchy flags"],
      analysis.types.map(type => [address(type.address), type.name, type.kind,
        type.flags == null ? "—" : address(type.flags)]));
    case "pe-itanium-bases": return tableModel(id,
      ["Type RVA", "Base RVA", "Access", "Offset kind", "Offset"],
      analysis.types.flatMap(type => type.bases.map(base => [
        address(type.address), address(base.typeAddress), base.isPublic ? "Public" : "Non-public",
        base.isVirtual ? "Virtual: vtable slot" : "Object", String(base.offset)
      ])));
    case "pe-itanium-vtables": return tableModel(id,
      ["Address point RVA", "Type RVA", "Function prefix RVAs"],
      analysis.vtables.map(entry => [address(entry.address), address(entry.typeAddress),
        entry.functionPrefix.map(address).join(", ")]));
    default: return null;
  }
};

export const renderItaniumRtti = (analysis: ItaniumRttiAnalysis | null | undefined): string => {
  if (!analysis) return "";
  return renderPeSectionStart("Itanium C++ RTTI", `${analysis.types.length} types`) +
    `<p class="smallNote">Conservative subset: primary vtables with relocation-backed pointers ` +
    `and a closed runtime type graph. Names retain their ABI encoding. ` +
    `Function addresses show only a verified prefix, not the full vtable.</p>` +
    analysis.warnings.map(warning => `<p class="smallNote">${escapeHtml(warning)}</p>`).join("") +
    [["pe-itanium-types", "Class types"], ["pe-itanium-bases", "Direct bases"],
      ["pe-itanium-vtables", "Primary vtables"]].map(([id, label]) =>
      `<h4>${label}</h4>` + renderAutoPagedSortableTable(getItaniumRttiTableModel(analysis, id!)!)
    ).join("") + renderPeSectionEnd();
};

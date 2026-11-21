import { escapeHtml } from "../../html-utils.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { ElfAttributeSection, ElfAttributeVendor, ElfBuildAttribute } from "../../analyzers/elf/attribute-types.js";
import { renderAutoPagedSortableTable, type PagedSortableTableModel } from "../paged-sortable-table.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";

// ARM build attributes and RISC-V psABI attribute tags (links in attribute-values.ts).
const attributeNames: Record<string, Record<string, string>> = {
  aeabi: { 4: "CPU raw name", 5: "CPU name", 6: "CPU architecture", 7: "CPU profile",
    8: "ARM ISA use", 9: "Thumb ISA use", 10: "FP architecture", 12: "Advanced SIMD architecture",
    18: "R9 use", 20: "FP denormals", 21: "FP exceptions", 23: "FP number model",
    24: "Alignment needed", 25: "Alignment preserved", 26: "Enum size", 27: "HardFP use",
    28: "VFP arguments", 30: "Optimization goals", 32: "Compatibility", 34: "Unaligned access",
    64: "No defaults", 65: "Also compatible with", 67: "Conformance" },
  aeabi_feature_and_bits: { 0: "BTI compatibility", 1: "Return address signing", 2: "GCS compatibility" },
  aeabi_pauthabi: { 1: "Pointer authentication platform", 2: "Pointer authentication schema version" },
  riscv: { 4: "Stack alignment", 5: "Architecture", 6: "Unaligned access",
    8: "Privileged spec", 10: "Privileged spec minor", 12: "Privileged spec revision",
    14: "Atomics ABI", 16: "x3 register usage" }
};

const attributeValue = (value: ElfBuildAttribute["value"]): string =>
  typeof value === "object" ? `${value.flag}: ${value.vendor}` : String(value);

const attributeCells = (name: string, attribute: ElfBuildAttribute): string[] => [
  String(attribute.tag), attributeNames[name]?.[String(attribute.tag)] ?? "Unknown tag",
  name === "aeabi_feature_and_bits" && attributeNames[name]?.[String(attribute.tag)]
    ? ({ 0: "0 · Not universal or unspecified", 1: "1 · All executable sections" } as Record<string, string>)[
      String(attribute.value)] ?? attributeValue(attribute.value)
    : attributeValue(attribute.value)
];

const vendorRows = (vendor: ElfAttributeVendor): string[][] => {
  if (!vendor.aarch64) return vendor.scopes.flatMap(scope => scope.attributes.map(attribute =>
    [vendor.name, String(scope.tag), scope.indices.join(", "), ...attributeCells(vendor.name, attribute)]));
  const { comprehension, parameterType, attributes } = vendor.aarch64;
  const scope = ({ 0: "File · required", 1: "File · optional" } as Record<number, string>)[
    comprehension] ?? `File · comprehension ${comprehension}`;
  const framing = [vendor.name, scope, "", "", "Value encoding",
    ({ 0: "0 · ULEB128", 1: "1 · NUL-terminated string" } as Record<number, string>)[parameterType] ??
    String(parameterType)];
  return [framing, ...attributes.map(attribute =>
    [vendor.name, scope, "", ...attributeCells(vendor.name, attribute)])];
};

export const createElfAttributeTableModel = (section: ElfAttributeSection): PagedSortableTableModel => {
  const rows = section.vendors.flatMap(vendorRows);
  return {
    id: `elf-attributes-${section.sectionIndex}`, pageSize: 100, rowCount: rows.length,
    columns: ["Vendor", "Scope", "Section / symbol indices", "Tag", "Attribute", "Value"]
      .map(label => ({ label })),
    rowAt: index => rows[index] ? { cells: rows[index]!.map(value =>
      ({ html: escapeHtml(value), sortValue: value })) } : null,
    sortValueAt: (index, column) => rows[index]?.[column] ?? ""
  };
};

export const renderElfAttributes = (elf: ElfParseResult, out: string[], onlyIndex?: number): void => {
  for (const [index, section] of (elf.attributes ?? []).entries()) {
    if (onlyIndex != null && index !== onlyIndex) continue;
    out.push(renderElfSectionStart(`Architecture attributes (section #${section.sectionIndex})`));
    if (section.vendors.some(vendor => vendor.aarch64)) {
      out.push('<p class="smallNote">A required subsection must be understood by a consumer. ' +
        "A consumer can ignore an optional subsection it does not recognize.</p>");
    }
    out.push(renderAutoPagedSortableTable(createElfAttributeTableModel(section)));
    if (section.issues.length) out.push(`<ul>${section.issues.map(issue =>
      `<li>${escapeHtml(issue)}</li>`).join("")}</ul>`);
    out.push(renderElfSectionEnd());
  }
};

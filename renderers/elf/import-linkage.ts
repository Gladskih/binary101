import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { ElfImportLink } from "../../analyzers/elf/import-linkage.js";
import { elfRelocationTypeName } from "../../analyzers/elf/relocation-names.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";
import { formatElfHex } from "./value-format.js";

const referenceColumns = [
  { label: "Slot CALL refs", kind: "Indirect call",
    tooltip: "Decoded CALL instructions that directly address the import slot." },
  { label: "Slot JMP refs", kind: "Indirect jump",
    tooltip: "Decoded JMP instructions that directly address the import slot." },
  { label: "Stub CALL refs", kind: "Call to stub",
    tooltip: "Decoded CALL instructions targeting a jump stub that addresses the import slot." },
  { label: "Stub JMP refs", kind: "Jump to stub",
    tooltip: "Decoded JMP instructions targeting a jump stub that addresses the import slot." }
];

const versionRequirements = (elf: ElfParseResult): Map<number, string[]> => {
  const requirements = new Map<number, string[]>();
  for (const requirement of elf.symbolVersions?.requirements ?? []) {
    for (const version of requirement.versions) {
      const index = version.index & 0x7fff; // GNU versym index: glibc elf.h.
      requirements.set(index, [...(requirements.get(index) ?? []),
        `${version.name} (${requirement.file})`]);
    }
  }
  return requirements;
};

const versionedTables = (elf: ElfParseResult): Set<number> => {
  const addresses = elf.dynamic?.entries.filter(entry => entry.tag === 6).map(entry => entry.value);
  const sections = new Map(elf.sections.map(section => [section.index, section]));
  return new Set(elf.relocations?.tables.flatMap((table, index) => {
    if (table.symbolTableIndex == null) return [index];
    const section = sections.get(table.symbolTableIndex);
    return section?.type === 11 && addresses?.length &&
      addresses.every(address => address === section.addr) ? [index] : [];
  }));
};

const recordedVersion = (elf: ElfParseResult, link: ElfImportLink,
  requirements: Map<number, string[]>, tables: Set<number>): string => {
  const entry = elf.relocations?.entries[link.relocationIndex];
  if (!entry?.symbolIndex || (entry.symbol?.sectionIndex !== 0 && link.kind !== "COPY relocation")) return "-";
  // Versym indices belong to the dynamic symbol table, not an arbitrary SYMTAB.
  if (!tables.has(entry.tableIndex)) return "Unknown (symbol table identity)";
  const index = elf.symbolVersions?.symbols[entry.symbolIndex];
  if (index == null || (index & 0x7fff) <= 1) return "-";
  return requirements.get(index & 0x7fff)?.join("; ") ?? `Unknown version #${index & 0x7fff}`;
};

const linkValues = (elf: ElfParseResult, link: ElfImportLink,
  version: string, names: Map<number, string>): string[] => {
  const entry = elf.relocations?.entries[link.relocationIndex];
  if (!entry) return [];
  const table = elf.relocations!.tables[entry.tableIndex];
  return [entry.symbol?.name || (link.kind === "IFUNC resolver slot" ? "Local resolver" : "Unknown"),
    version, link.kind,
    entry.type == null ? "Unknown" : elfRelocationTypeName(elf.header.machine, entry.type),
    table?.sources.join(", ") ?? "Unknown",
    link.sections.map(index => names.get(index) ?? `#${index}`).join(", ") || "-",
    relroCoverage(link),
    link.issues.join(" ") || "-"];
};

const relroCoverage = (link: ElfImportLink): string => {
  if (!link.relroSegments.length) return "Not covered";
  return link.kind === "COPY relocation" || link.kind === "Other symbol relocation"
    ? "Target address covered" : "Covered";
};

export const createElfImportLinkageModel = (elf: ElfParseResult): PagedSortableTableModel => {
  const links = elf.importLinkage?.links ?? [];
  const requirements = versionRequirements(elf);
  const tables = versionedTables(elf);
  const names = new Map(elf.sections.map(section => [section.index, section.name || `#${section.index}`]));
  const code = new Map(elf.disassembly?.importCode?.map(evidence => [evidence.slotAddress, evidence]));
  const codeValues = (link: ElfImportLink): string[] => {
    const address = elf.relocations?.entries[link.relocationIndex]?.offset;
    const evidence = address == null ? undefined : code.get(address);
    return referenceColumns.map(({ kind }) => String(evidence?.references.reduce((count, reference) =>
      count + (reference.kind === kind ? reference.count : 0), 0) ?? 0));
  };
  const values = (index: number): string[] => links[index]
    ? [...linkValues(elf, links[index]!, recordedVersion(elf, links[index]!, requirements, tables), names),
      ...(elf.disassembly?.importCode ? codeValues(links[index]!) : [])] : [];
  const columns = ["Symbol", "Version requirement (recorded library)", "Linkage", "Relocation",
    "Relocation table", "Target section", "RELRO coverage", "Notes"]
    .map(label => ({ label, className: "" }));
  if (elf.disassembly?.importCode) columns.push(...referenceColumns.map(({ label, tooltip }) => ({
    label, tooltip, className: "peNumeric"
  })));
  return { id: "elf-import-linkage", tableClassName: "elfImportLinkage", pageSize: 100,
    rowCount: links.length, columns,
    rowAt: index => links[index] ? { cells: values(index).map((value, column) => ({
      html: escapeHtml(value), sortValue: value, className: columns[column]?.className ?? ""
    })) } : null,
    sortValueAt: (index, column) => values(index)[column] ?? ""
  };
};

export const renderElfImportLinkage = (elf: ElfParseResult, out: string[]): void => {
  const report = elf.importLinkage;
  if (!report) return;
  out.push(renderElfSectionStart("Import linkage"));
  out.push(`<p class="smallNote">Cross-matches runtime relocations with symbols, ` +
    `version requirements and target ranges. DT_NEEDED and version requirements do not prove ` +
    `the runtime provider. PLT stub addresses are not inferred from relocation order.</p><dl>`);
  out.push(renderDefinitionRow("PLT binding policy", escapeHtml(report.binding),
    "Recorded NOW flags request immediate binding; the runtime may override lazy binding."));
  out.push(renderDefinitionRow("DT_PLTGOT", escapeHtml(elf.dynamic?.entries
    .filter(entry => entry.tag === 3).map(entry => formatElfHex(entry.value)).join(", ") ||
    "Not recorded"), "Processor-specific PLT/GOT address; not a portable table extent."));
  out.push(renderDefinitionRow("Relocation links", String(report.links.length)));
  out.push(renderDefinitionRow("Code evidence", elf.disassembly?.importCode
    ? "ISA results available; counts describe decoded instruction sites, not execution frequency."
    : elf.disassembly ? "No supported code evidence was collected."
      : "Run ISA analysis to add x86 slot calls/jumps and direct branches to jump stubs."));
  out.push(`</dl><p class="smallNote">RELRO coverage describes recorded ranges, ` +
    `not observed runtime page protection. ` +
    `Other symbol relocations may include data, TLS and architecture-specific operations. ` +
    `Missing code evidence does not mean a symbol is unused. Register-based targets are not resolved.</p>`);
  if (report.links.some(link => link.kind === "COPY relocation")) out.push(
    `<p class="smallNote">For a COPY relocation, this file defines the destination storage. ` +
    `The dynamic linker copies initial bytes from a symbol definition in another object.</p>`);
  if (report.links.length) out.push(renderAutoPagedSortableTable(createElfImportLinkageModel(elf)));
  else out.push(`<p>No matching runtime relocation links were decoded.</p>`);
  if (report.issues.length) out.push(`<p>Analysis contains incomplete or anomalous input:</p><ul>` +
    report.issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("") + `</ul>`);
  out.push(renderElfSectionEnd());
};

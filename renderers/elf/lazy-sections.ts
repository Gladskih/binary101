import type { ElfParseResult, ElfReport } from "../../analyzers/elf/types.js";
import { renderElfSanitizers } from "./sanitizers.js";
import { renderElf, renderProgramHeaders, renderSectionHeaders, renderIssues } from "./index.js";
import { renderHeader } from "./header.js";
import { renderElfSectionStart, renderElfSectionEnd } from "./collapsible-section.js";
import { renderInstructionSetsShell, renderInstructionSetsContent } from "./disassembly.js";
import { renderElfLinking } from "./linking.js";
import { renderElfImportLinkage } from "./import-linkage.js";
import { renderElfSymbols } from "./symbols.js";
import { renderElfSymbolVersions } from "./symbol-versions.js";
import { renderElfSymbolTables } from "./symbol-tables.js";
import { renderElfSectionGroups } from "./section-groups.js";
import { elfUnwindTitle, renderElfUnwind } from "./unwind.js";
import { elfSFrameTitle, renderElfSFrame } from "./sframe.js";
import { elfLsdaTitle, renderElfLsda } from "./lsda.js";
import { renderElfArmEhabi } from "./arm-ehabi.js";
import { renderElfHashTables } from "./hash-tables.js";
import { renderElfAttributes } from "./attributes.js";
import { renderElfMips } from "./mips.js";
import { renderElfRelocations } from "./relocations.js";
import { renderElfTls } from "./tls.js";
import { renderElfNotes } from "./notes.js";
import { renderElfNativeAot } from "./native-aot.js";
import { renderElfDebug } from "./debug.js";
import { renderEmbeddedResources } from "../embedded-resources.js";
import { markSupplementalAnalysis } from "../supplemental-analysis.js";
import { renderChecksWithoutFindings } from "../checks-without-findings.js";
import { elfDynamicTagCatalog } from "../../analyzers/elf/dynamic-tags.js";

export interface ElfLazySection {
  key: string;
  title: string;
  render: () => string;
}

type Renderer = (elf: ElfParseResult, out: string[], index?: number) => void;

export const getElfLazySections = (elf: ElfParseResult): ElfLazySection[] => {
  const result: ElfLazySection[] = [];
  const add = (key: string, title: string, renderer: Renderer, index?: number): void => {
    result.push({ key, title, render: () => {
      const out: string[] = [];
      renderer(elf, out, index);
      return out.join("").slice(renderElfSectionStart(title).length, -renderElfSectionEnd().length);
    } });
  };
  result.push({ key: "instruction-sets", title: "Instruction sets", render: () => {
    const out: string[] = [];
    renderInstructionSetsContent(elf, out);
    return out.join("");
  } });
  add("header", "ELF header", renderHeader);
  if (elf.sanitizerEvidence?.length) add("sanitizers", "Sanitizer evidence", renderElfSanitizers);
  if (elf.interpreter || elf.dynamic) add("linking", "Dynamic linking", renderElfLinking);
  if (elf.importLinkage) add("import-linkage", "Import linkage", renderElfImportLinkage);
  if (elf.dynSymbols) add("symbols", "Imports / exports", renderElfSymbols);
  if (elf.symbolVersions) add("versions", "Symbol versions", renderElfSymbolVersions);
  addTables(elf, add);
  addMetadata(elf, add);
  return result;
};

type AddSection = (key: string, title: string, renderer: Renderer, index?: number) => void;

const addTables = (elf: ElfParseResult, add: AddSection): void => {
  const names = new Map(elf.sections.map(section => [section.index, section.name]));
  elf.symbolTables?.forEach((table, index) => add(`symbols-${index}`,
    `Symbols: ${names.get(table.sectionIndex) || `section #${table.sectionIndex}`}`,
    renderElfSymbolTables, index));
  if (elf.sectionGroups?.length) add("groups", "Section groups / COMDAT", renderElfSectionGroups);
  elf.unwind?.forEach((section, index) => add(`unwind-${index}`,
    elfUnwindTitle(section, section.sectionIndex == null ? undefined : names.get(section.sectionIndex)),
    renderElfUnwind, index));
  elf.sframe?.forEach((table, index) => add(`sframe-${index}`,
    elfSFrameTitle(table), renderElfSFrame, index));
  if (elf.lsdas?.length) add("lsda", elfLsdaTitle(elf.lsdas), renderElfLsda);
  addArchitecture(elf, add);
};

const addArchitecture = (elf: ElfParseResult, add: AddSection): void => {
  elf.armEhabi?.forEach((table, index) => add(`ehabi-${index}`,
    `ARM exception handling (${table.source})`, renderElfArmEhabi, index));
  elf.hashTables?.forEach((table, index) => add(`hash-${index}`,
    `${table.kind === "gnu" ? "GNU" : "System V"} symbol hash table`, renderElfHashTables, index));
  elf.attributes?.forEach((section, index) => add(`attributes-${index}`,
    `Architecture attributes (section #${section.sectionIndex})`, renderElfAttributes, index));
  elf.mips?.forEach((metadata, index) => add(`mips-${index}`,
    `MIPS ABI metadata (${metadata.source})`, renderElfMips, index));
};

const addMetadata = (elf: ElfParseResult, add: AddSection): void => {
  if (elf.relocations) add("relocations", `Relocations (${elf.relocations.entries.length})`, renderElfRelocations);
  if (elf.tls) add("tls", "TLS", renderElfTls);
  if (elf.notes) add("notes", "Notes", renderElfNotes);
  addBuildMetadata(elf, add);
  if (elf.programHeaders.length) add("program-headers",
    `Program headers (${elf.programHeaders.length})`, renderProgramHeaders);
  if (elf.sections.length) add("section-headers", `Section headers (${elf.sections.length})`, renderSectionHeaders);
  if (elf.issues.length) add("issues", "Notices", renderIssues);
};

const addBuildMetadata = (elf: ElfParseResult, add: AddSection): void => {
  if (elf.embeddedResources) add("embedded-resources", "Qt / GLib embedded resources",
    (current, out) => { out.push(renderEmbeddedResources(current.embeddedResources)); });
  if (elf.nativeAot) add("native-aot", "NativeAOT metadata", renderElfNativeAot);
  if (elf.comment || elf.debugLink || elf.dwarf || elf.goBuildInfo || elf.miniDebugInfo) {
    add("debug", "Build / debug", renderElfDebug);
  }
};

const supplementalSections = new Set([
  "embedded-resources", "instruction-sets", "issues", "native-aot", "sanitizers", "import-linkage"
]);

export const renderElfLazy = (elf: ElfReport | null): string => {
  if (!elf || "incompleteHeader" in elf) return renderElf(elf);
  return getElfLazySections(elf).map(section => {
    const html = (section.key === "instruction-sets"
      ? renderInstructionSetsShell()
      : renderElfSectionStart(section.title) + renderElfSectionEnd())
      .replace("<section ", `<section data-elf-lazy-section="${section.key}" ` +
        (section.key === "linking" && elf.dynamic ? `data-report-search-labels="` +
          `${Object.values(elfDynamicTagCatalog(elf.header.machine)).map(([name]) => name).join("|")}" ` : ""));
    return supplementalSections.has(section.key) ? markSupplementalAnalysis(html) : html;
  }).join("") + renderChecksWithoutFindings(elf);
};

import type { AnalyzerName } from "../analyzers/analyzer-types.js";
import type { ReportTextMatch } from "./report-text-search.js";
import type { WorkspaceSection } from "./workspace-sections.js";

const peSections: Readonly<Record<string, string>> = {
  dos: "dos-header", coff: "pe-headers", opt: "pe-headers", entrySection: "pe-headers",
  sections: "section-headers", dirs: "data-directories", imports: "imports", exports: "exports",
  resources: "resources", debug: "debug", dwarf: "dwarf", clr: "clr", readyToRun: "clr",
  security: "security", tls: "tls", reloc: "reloc", exception: "exception", iat: "iat",
  loadcfg: "load-config", delayImports: "delay-imports", boundImports: "bound-imports",
  msvcRtti: "msvc-rtti", msvcEh: "msvc-eh", itaniumRtti: "itanium-rtti", overlay: "overlay",
  importLinking: "import-linking", appHost: "apphost", nativeAotCandidate: "native-aot",
  disassembly: "peInstructionSetsPanel", entrypointDisassembly: "peEntrypointDisassemblyPanel",
  warnings: "sanity"
};

const elfSections: Readonly<Record<string, string>> = {
  ident: "header", header: "header", programHeaders: "program-headers", sections: "section-headers",
  interpreter: "linking", dynamic: "linking", dynSymbols: "symbols", symbolVersions: "versions",
  tls: "tls", relocations: "relocations", notes: "notes", dwarf: "debug", debugLink: "debug",
  comment: "debug", goBuildInfo: "debug", nativeAot: "native-aot", disassembly: "instruction-sets",
  embeddedResources: "embedded-resources", sanitizerEvidence: "sanitizers", issues: "issues"
};

const elfIndexedSections: Readonly<Record<string, string>> = {
  symbolTables: "symbols", unwind: "unwind", attributes: "attributes", mips: "mips",
  hashTables: "hash", armEhabi: "ehabi"
};

export const reportSearchSection = (
  analyzer: AnalyzerName | null,
  match: ReportTextMatch,
  sections: readonly Pick<WorkspaceSection, "key" | "title" | "origin">[]
): string | null => {
  const field = String(match.path[0] ?? "");
  const suffix = analyzer === "pe" ? peSections[field] : analyzer === "elf" ?
    (elfIndexedSections[field] && typeof match.path[1] === "number"
      ? `${elfIndexedSections[field]}-${match.path[1]}` : elfSections[field]) : undefined;
  if (suffix) return sections.find(section => section.key === `analysis-${suffix}`)?.key ?? null;
  if (analyzer === "pe" || analyzer === "elf") return null;
  const native = sections.filter(section => !section.origin && section.title !== "Preview");
  return native.length === 1 ? native[0]!.key : null;
};

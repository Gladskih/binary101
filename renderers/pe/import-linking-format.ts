"use strict";

import { dd, safe } from "../../html-utils.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import type {
  PeDeclaredIatRelation,
  PeImportBindingRelation,
  PeImportLinkingFinding,
  PeImportLinkingModule,
  PeIatDirectoryRelation
} from "../../analyzers/pe/imports/linking.js";
import type { PeImportLookupSource } from "../../analyzers/pe/imports/index.js";
import { peSectionNameValue } from "../../analyzers/pe/sections/name.js";
import type { PeSection } from "../../analyzers/pe/types.js";

type PeFindingSeverity = PeImportLinkingFinding["severity"];
type PeFindingGroups = Record<PeFindingSeverity, PeImportLinkingFinding[]>;

// Microsoft PE metadata for CFG-protected delay-load IATs:
// PROTECT_DELAYLOAD_IAT requests protected delay-load handling, and
// DELAYLOAD_IAT_IN_ITS_OWN_SECTION advertises the backward-compatible own-section layout.
// https://learn.microsoft.com/fr-fr/windows/win32/secbp/pe-metadata
const IMAGE_GUARD_PROTECT_DELAYLOAD_IAT = 0x00001000;
const IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION = 0x00002000;
const CANONICAL_DELAYLOAD_IAT_SECTION_NAME = ".didat";

const findSectionContainingRva = (sections: PeSection[], rva: number): PeSection | null => {
  const normalizedRva = rva >>> 0;
  for (const section of sections) {
    const start = section.virtualAddress >>> 0;
    const size = (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);
    const end = start + size;
    if (normalizedRva >= start && normalizedRva < end) return section;
  }
  return null;
};

const hasGuardFlag = (pe: PeWindowsParseResult, flag: number): boolean =>
  ((pe.loadcfg?.GuardFlags ?? 0) & flag) !== 0;

const getSectionDisplayName = (section: PeSection | null): string => {
  if (!section) return "(outside sections)";
  const name = peSectionNameValue(section.name);
  return name || "(unnamed)";
};

export const describeSectionForRva = (pe: PeWindowsParseResult, rva: number): string => {
  if (!rva) return "-";
  return safe(getSectionDisplayName(findSectionContainingRva(pe.sections, rva)));
};

export const findLinkedModuleForImport = (
  pe: PeWindowsParseResult,
  importIndex: number
): PeImportLinkingModule | null =>
  pe.importLinking?.modules.find(module =>
    module.imports.some(linkedImport => linkedImport.importIndex === importIndex)
  ) ?? null;

export const findLinkedModuleForBoundImport = (
  pe: PeWindowsParseResult,
  boundImportIndex: number
): PeImportLinkingModule | null =>
  pe.importLinking?.modules.find(module =>
    module.boundImports.some(linkedImport => linkedImport.boundImportIndex === boundImportIndex)
  ) ?? null;

export const findLinkedModuleForDelayImport = (
  pe: PeWindowsParseResult,
  delayImportIndex: number
): PeImportLinkingModule | null =>
  pe.importLinking?.modules.find(module =>
    module.delayImports.some(linkedImport => linkedImport.delayImportIndex === delayImportIndex)
  ) ?? null;

export const findLinkedImportDescriptor = (
  linkedModule: PeImportLinkingModule | null,
  importIndex: number
) => linkedModule?.imports.find(linkedImport => linkedImport.importIndex === importIndex) ?? null;

export const findLinkedDelayImportDescriptor = (
  linkedModule: PeImportLinkingModule | null,
  delayImportIndex: number
) => linkedModule?.delayImports.find(linkedImport => linkedImport.delayImportIndex === delayImportIndex) ?? null;

export const getModuleDisplayName = (
  pe: PeWindowsParseResult,
  linkedModule: PeImportLinkingModule
): string => {
  const importIndex = linkedModule.imports[0]?.importIndex;
  const boundImportIndex = linkedModule.boundImports[0]?.boundImportIndex;
  const delayImportIndex = linkedModule.delayImports[0]?.delayImportIndex;
  return (
    (importIndex != null ? pe.imports.entries[importIndex]?.dll : null) ||
    (boundImportIndex != null ? pe.boundImports?.entries[boundImportIndex]?.name : null) ||
    (delayImportIndex != null ? pe.delayImports?.entries[delayImportIndex]?.name : null) ||
    linkedModule.moduleKey
  );
};

export const filterFindings = (
  linkedModule: PeImportLinkingModule | null,
  codes: string[]
): PeImportLinkingFinding[] =>
  linkedModule?.findings?.filter(finding => codes.includes(finding.code)) ?? [];

const groupFindingsBySeverity = (findings?: PeImportLinkingFinding[]): PeFindingGroups => ({
  confirmed: findings?.filter(finding => finding.severity === "confirmed") ?? [],
  info: findings?.filter(finding => finding.severity === "info") ?? [],
  warning: findings?.filter(finding => finding.severity === "warning") ?? []
});

const renderFindingGroup = (
  label: string,
  findings: PeImportLinkingFinding[],
  colorVariable: string
): string =>
  dd(
    label,
    `<div class="smallNote" style="margin:0;color:${colorVariable}">${findings
      .map(finding => `<div>- ${safe(finding.message)}</div>`)
      .join("")}</div>`,
    label === "Validated"
      ? "Cross-checks that matched the PE documentation or a documented producer-specific layout."
      : label === "Warnings"
        ? "Cross-checks that contradict documented or expected relationships."
        : "Cross-checks that are informative but not inherently invalid."
  );

export const renderFindingRows = (findings?: PeImportLinkingFinding[]): string => {
  const groups = groupFindingsBySeverity(findings);
  const rows: string[] = [];
  if (groups.confirmed.length) {
    rows.push(renderFindingGroup("Validated", groups.confirmed, "var(--ok-fg)"));
  }
  if (groups.warning.length) {
    rows.push(renderFindingGroup("Warnings", groups.warning, "var(--warn-fg)"));
  }
  if (groups.info.length) {
    rows.push(renderFindingGroup("Notes", groups.info, "var(--muted)"));
  }
  return rows.join("");
};

export const renderFindingSummary = (
  findings: PeImportLinkingFinding[],
  severity: PeFindingSeverity
): string => {
  const filtered = findings.filter(finding => finding.severity === severity);
  if (!filtered.length) return "-";
  const colorVariable =
    severity === "confirmed"
      ? "var(--ok-fg)"
      : severity === "warning"
        ? "var(--warn-fg)"
        : "var(--muted)";
  return `<div class="smallNote" style="margin:0;color:${colorVariable}">${filtered
    .map(finding => `<div>- ${safe(finding.message)}</div>`)
    .join("")}</div>`;
};

export const countFindings = (
  modules: PeImportLinkingModule[],
  severity: PeFindingSeverity
): number =>
  modules.reduce(
    (count, module) =>
      count + (module.findings?.filter(finding => finding.severity === severity).length ?? 0),
    0
  );

export const countStandaloneFindings = (
  findings: PeImportLinkingFinding[] | undefined,
  severity: PeFindingSeverity
): number => findings?.filter(finding => finding.severity === severity).length ?? 0;

export const countModulesWithFindingCodes = (
  modules: PeImportLinkingModule[],
  codes: string[]
): number =>
  modules.filter(module => module.findings?.some(finding => codes.includes(finding.code))).length;

export const filterStandaloneFindings = (
  findings: PeImportLinkingFinding[] | undefined,
  codes: string[]
): PeImportLinkingFinding[] => findings?.filter(finding => codes.includes(finding.code)) ?? [];

export const renderLookupSourceLabel = (
  lookupSource: PeImportLookupSource | undefined
): string => {
  if (lookupSource === "import-lookup-table") {
    return "INT / OriginalFirstThunk";
  }
  if (lookupSource === "iat-fallback") {
    return "IAT fallback / FirstThunk";
  }
  return "No thunk table";
};

export const renderLookupSource = (lookupSource: PeImportLookupSource | undefined): string => {
  if (lookupSource === "import-lookup-table") {
    return "INT / OriginalFirstThunk<div class=\"smallNote\">PE format: names came from the Import Lookup Table.</div>";
  }
  if (lookupSource === "iat-fallback") {
    return "IAT fallback / FirstThunk<div class=\"smallNote\">OriginalFirstThunk is 0, so names were recovered from FirstThunk.</div>";
  }
  return "No thunk table";
};

export const renderBinding = (
  bindingRelation: PeImportBindingRelation | undefined
): string => {
  if (bindingRelation === "bound-directory-match") {
    return "Matched BOUND_IMPORT entry";
  }
  if (bindingRelation === "timestamp-only") {
    return "Descriptor timestamp only";
  }
  return "No binding metadata";
};

export const renderIatRelation = (
  relation: PeIatDirectoryRelation | undefined
): string => {
  if (relation === "covered") return "Starts inside IMAGE_DIRECTORY_ENTRY_IAT";
  if (relation === "outside-directory") return "Starts outside IMAGE_DIRECTORY_ENTRY_IAT";
  if (relation === "missing-directory") return "IMAGE_DIRECTORY_ENTRY_IAT is absent";
  return "No table RVA";
};

export const renderDeclaredIatRelation = (
  relation: PeDeclaredIatRelation | undefined
): string => {
  if (relation === "exact-match") return "Exact match";
  if (relation === "declared-covers-inferred") {
    return "Declared IAT covers all inferred eager IAT ranges";
  }
  if (relation === "declared-misses-inferred") {
    return "Declared IAT misses inferred eager IAT ranges";
  }
  return "Declared IAT absent";
};

export const summarizeLookupSources = (
  pe: PeWindowsParseResult,
  linkedModule: PeImportLinkingModule
): string => {
  const sources = linkedModule.imports.map(linkedImport =>
    pe.imports.entries[linkedImport.importIndex]?.lookupSource ?? "missing"
  );
  const uniqueSources = [...new Set(sources)];
  if (!uniqueSources.length) return "-";
  if (uniqueSources.length === 1) {
    return safe(renderLookupSourceLabel(uniqueSources[0]));
  }
  return "Mixed";
};

export const summarizeRelations = (relations: PeIatDirectoryRelation[]): string => {
  const uniqueRelations = [...new Set(relations)];
  if (!uniqueRelations.length) return "-";
  if (uniqueRelations.length === 1) return safe(renderIatRelation(uniqueRelations[0]));
  return safe(`Mixed (${uniqueRelations.map(renderIatRelation).join("; ")})`);
};

export const countRelation = (
  relations: PeIatDirectoryRelation[],
  targetRelation: PeIatDirectoryRelation
): number => relations.filter(relation => relation === targetRelation).length;

export const renderDelayGuardContext = (pe: PeWindowsParseResult): string => {
  if (!pe.loadcfg) return "No LOAD_CONFIG";
  const protectsDelayLoadIat = hasGuardFlag(pe, IMAGE_GUARD_PROTECT_DELAYLOAD_IAT);
  const advertisesOwnSection = hasGuardFlag(pe, IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION);
  if (protectsDelayLoadIat && advertisesOwnSection) {
    return "PROTECT_DELAYLOAD_IAT + DELAYLOAD_IAT_IN_ITS_OWN_SECTION";
  }
  if (protectsDelayLoadIat) return "PROTECT_DELAYLOAD_IAT";
  if (advertisesOwnSection) return "DELAYLOAD_IAT_IN_ITS_OWN_SECTION";
  return "No delay-load guard flags";
};

export const renderDelaySectionContext = (
  pe: PeWindowsParseResult,
  iatRva: number
): string => {
  const section = findSectionContainingRva(pe.sections, iatRva >>> 0);
  const sectionName = getSectionDisplayName(section);
  return sectionName.toLowerCase() === CANONICAL_DELAYLOAD_IAT_SECTION_NAME
    ? `${safe(sectionName)}<div class="smallNote">Microsoft documents .didat as the canonical section for protected delay-load IATs.</div>`
    : safe(sectionName);
};

export const renderImportNamesForIndices = (
  pe: PeWindowsParseResult,
  importIndices: number[]
): string => {
  const names = [...new Set(importIndices
    .map(importIndex => pe.imports.entries[importIndex]?.dll)
    .filter((value): value is string => !!value))];
  if (!names.length) return "-";
  return safe(names.join(", "));
};

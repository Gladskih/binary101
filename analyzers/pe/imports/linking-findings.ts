"use strict";

import type { PeDelayImportEntry } from "./delay.js";
import type { PeIatDirectory } from "./iat.js";
import type { PeImportParseResult } from "./index.js";
import type { PeLoadConfig } from "../load-config/index.js";
import { peSectionNameValue } from "../sections/name.js";
import type { PeSection } from "../types.js";
import type {
  PeIatDirectoryRelation,
  PeImportLinkingFinding,
  PeImportLinkingModule
} from "./linking-model.js";

// Microsoft PE Load Config GuardFlags:
// PROTECT_DELAYLOAD_IAT requests protected delay-load IAT handling,
// DELAYLOAD_IAT_IN_ITS_OWN_SECTION advertises the backward-compatible own-section layout.
// https://learn.microsoft.com/fr-fr/windows/win32/secbp/pe-metadata
const IMAGE_GUARD_PROTECT_DELAYLOAD_IAT = 0x00001000;
const IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION = 0x00002000;
const CANONICAL_DELAYLOAD_IAT_SECTION_NAME = ".didat";

const pushFinding = (
  findings: PeImportLinkingFinding[],
  finding: PeImportLinkingFinding
): void => {
  if (!findings.some(existing => existing.code === finding.code)) findings.push(finding);
};

export const resolveIatDirectoryRelation = (
  tableRva: number,
  iat: PeIatDirectory | null
): PeIatDirectoryRelation => {
  if (!tableRva) return "missing-table-rva";
  if (!iat?.rva || !iat.size) return "missing-directory";
  // Microsoft PE format: IMAGE_DIRECTORY_ENTRY_IAT gives one RVA/size span for the image IAT.
  // Compare thunk-table starts against that declared half-open range.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  const iatStart = iat.rva >>> 0;
  const iatEnd = iatStart + (iat.size >>> 0);
  const normalizedTableRva = tableRva >>> 0;
  return normalizedTableRva >= iatStart && normalizedTableRva < iatEnd
    ? "covered"
    : "outside-directory";
};

const findSectionContainingRva = (sections: PeSection[], rva: number): PeSection | null => {
  for (const section of sections) {
    const start = section.virtualAddress >>> 0;
    const size = (section.virtualSize >>> 0) || (section.sizeOfRawData >>> 0);
    const end = start + size;
    if (rva >= start && rva < end) return section;
  }
  return null;
};

const hasGuardFlag = (loadcfg: PeLoadConfig | null, flag: number): boolean =>
  ((loadcfg?.GuardFlags ?? 0) & flag) !== 0;

const getSectionName = (section: PeSection | null): string =>
  section ? peSectionNameValue(section.name).toLowerCase() : "";

const addEagerImportFindings = (
  linkedModule: PeImportLinkingModule,
  imports: PeImportParseResult,
  findings: PeImportLinkingFinding[]
): void => {
  if (linkedModule.boundImports.length && !linkedModule.imports.length) {
    pushFinding(findings, {
      code: "bound-without-import",
      severity: "warning",
      message: "Bound import entry without a matching eager import descriptor."
    });
  }
  if (linkedModule.boundImports.length && linkedModule.imports.length) {
    linkedModule.imports = linkedModule.imports.map(linkedImport => ({
      ...linkedImport,
      bindingRelation: "bound-directory-match"
    }));
    pushFinding(findings, {
      code: "bound-match",
      severity: "confirmed",
      message: "BOUND_IMPORT metadata matches an eager import descriptor for this module."
    });
  }
  linkedModule.imports.forEach(linkedImport => {
    const entry = imports.entries[linkedImport.importIndex];
    if (!entry) return;
    if (entry.lookupSource === "import-lookup-table") {
      pushFinding(findings, {
        code: "int-lookup",
        severity: "confirmed",
        message: "Names come from OriginalFirstThunk / the Import Lookup Table (INT)."
      });
    }
    if (entry.lookupSource === "iat-fallback") {
      pushFinding(findings, {
        code: "iat-fallback",
        severity: "info",
        message: "OriginalFirstThunk is 0, so names were recovered from FirstThunk/IAT."
      });
    }
    if (linkedImport.iatDirectoryRelation === "covered") {
      pushFinding(findings, {
        code: "eager-iat-covered",
        severity: "confirmed",
        message: "FirstThunk begins inside IMAGE_DIRECTORY_ENTRY_IAT."
      });
    }
    if (linkedImport.iatDirectoryRelation === "outside-directory") {
      pushFinding(findings, {
        code: "eager-iat-outside-directory",
        severity: "warning",
        message: "FirstThunk starts outside IMAGE_DIRECTORY_ENTRY_IAT."
      });
    }
    if (entry.timeDateStamp && !linkedModule.boundImports.length) {
      pushFinding(findings, {
        code: "timestamp-without-bound-import",
        severity: "warning",
        message:
          "Import descriptor TimeDateStamp is non-zero, but no matching BOUND_IMPORT entry was found."
      });
    }
    if (entry.lookupSource === "iat-fallback" && entry.timeDateStamp) {
      pushFinding(findings, {
        code: "iat-fallback-with-timestamp",
        severity: "warning",
        message:
          "Names came from FirstThunk/IAT even though the descriptor carries binding-style timestamp metadata."
      });
    }
  });
};

const addDelayImportFindings = (
  linkedModule: PeImportLinkingModule,
  delayImports: { entries: PeDelayImportEntry[] } | null,
  iat: PeIatDirectory | null,
  loadcfg: PeLoadConfig | null,
  sections: PeSection[],
  findings: PeImportLinkingFinding[]
): void => {
  if (!delayImports || !linkedModule.delayImports.length) return;
  if (linkedModule.imports.length) {
    pushFinding(findings, {
      code: "eager-and-delay",
      severity: "info",
      message: "Module appears in both eager imports and delay-load imports."
    });
  }
  const mainIatSection = iat?.rva ? findSectionContainingRva(sections, iat.rva >>> 0) : null;
  const protectsDelayLoadIat = hasGuardFlag(loadcfg, IMAGE_GUARD_PROTECT_DELAYLOAD_IAT);
  const advertisesOwnSection = hasGuardFlag(loadcfg, IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION);
  linkedModule.delayImports.forEach(linkedDelayImport => {
    const entry = delayImports.entries[linkedDelayImport.delayImportIndex];
    if (!entry) return;
    const delayIatSection = findSectionContainingRva(sections, entry.ImportAddressTableRVA >>> 0);
    const delayIatSectionName = getSectionName(delayIatSection);
    const ownSection = delayIatSection != null && delayIatSection !== mainIatSection;
    if (linkedDelayImport.iatDirectoryRelation === "covered") {
      pushFinding(findings, {
        code: "delay-iat-covered",
        severity: "confirmed",
        message: "Delay-load ImportAddressTableRVA begins inside IMAGE_DIRECTORY_ENTRY_IAT."
      });
      if (advertisesOwnSection && !ownSection) {
        pushFinding(findings, {
          code: "delay-iat-own-section-mismatch",
          severity: "warning",
          message:
            "Load Config says the delay-load IAT is in its own section, but the RVA does not resolve to a distinct section."
        });
      }
      return;
    }
    if (linkedDelayImport.iatDirectoryRelation !== "outside-directory") return;
    if (protectsDelayLoadIat && advertisesOwnSection && ownSection) {
      pushFinding(findings, {
        code: "protected-delay-iat-own-section",
        severity: "confirmed",
        message:
          delayIatSectionName === CANONICAL_DELAYLOAD_IAT_SECTION_NAME
            ? "Delay-load IAT is isolated in the canonical .didat section, and Load Config advertises the protected own-section layout."
            : "Delay-load IAT is isolated in its own section, and Load Config advertises the protected own-section layout."
      });
      return;
    }
    if (protectsDelayLoadIat && ownSection) {
      pushFinding(findings, {
        code: "protected-delay-iat-separate-section",
        severity: "confirmed",
        message:
          "Delay-load IAT is isolated in a separate section, and Load Config enables protected delay-load IAT handling."
      });
      return;
    }
    if (advertisesOwnSection && !ownSection) {
      pushFinding(findings, {
        code: "delay-iat-own-section-mismatch",
        severity: "warning",
        message:
          "Load Config says the delay-load IAT is in its own section, but the RVA does not resolve to a distinct section."
      });
      return;
    }
    if (delayIatSection) {
      pushFinding(findings, {
        code: "delay-iat-outside-directory",
        severity: "info",
        message:
          `Delay-load ImportAddressTableRVA starts outside IMAGE_DIRECTORY_ENTRY_IAT and resolves to section ${delayIatSectionName || "(unnamed)"}.`
      });
      return;
    }
    pushFinding(findings, {
      code: "delay-iat-outside-directory",
      severity: "info",
      message: "Delay-load ImportAddressTableRVA starts outside IMAGE_DIRECTORY_ENTRY_IAT."
    });
  });
};

export const analyzeLinkedModule = (
  linkedModule: PeImportLinkingModule,
  imports: PeImportParseResult,
  delayImports: { entries: PeDelayImportEntry[] } | null,
  iat: PeIatDirectory | null,
  loadcfg: PeLoadConfig | null,
  sections: PeSection[]
): PeImportLinkingModule => {
  const findings: PeImportLinkingFinding[] = [];
  addEagerImportFindings(linkedModule, imports, findings);
  addDelayImportFindings(linkedModule, delayImports, iat, loadcfg, sections, findings);
  return findings.length ? { ...linkedModule, findings } : linkedModule;
};

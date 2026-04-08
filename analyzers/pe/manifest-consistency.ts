"use strict";

import { getManifestProcessorArchitectureForMachine } from "./constants.js";
import type { PeClrHeader } from "./clr/types.js";
import type { PeResources } from "./resources/index.js";
import type {
  ResourceLangWithPreview,
  ResourceManifestPreview,
  ResourceManifestValidation
} from "./resources/preview/types.js";

// ECMA-335 II.25.3.3.1 ("Runtime flags"):
// https://carlwa.com/ecma-335/#ii.25.3.3.1-runtime-flags
const COMIMAGE_FLAGS_ILONLY = 0x00000001;
// Microsoft Learn, "Application manifests":
// https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests
// The documented assemblyIdentity processorArchitecture values for application manifests are
// x86, amd64, arm, arm64, and *.
const DOCUMENTED_MANIFEST_ARCHITECTURES = new Set(["x86", "amd64", "arm", "arm64", "*"]);

interface ManifestResourceEntry {
  resourceId: number | null;
  lang: number | null;
  manifestInfo: ResourceManifestPreview;
}

const normalizeText = (value: string | null | undefined): string | null => {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
};

const normalizeArchitecture = (value: string | null | undefined): string | null => {
  const normalized = normalizeText(value)?.toLowerCase();
  return normalized ? normalized : null;
};

const describeManifestEntry = (entry: ManifestResourceEntry): string => {
  const idPart = entry.resourceId != null ? `ID ${entry.resourceId}` : "unnamed ID";
  const langPart = entry.lang != null ? `LANG ${entry.lang}` : "LANG neutral";
  return `${idPart} / ${langPart}`;
};

const getManifestEntries = (resources: PeResources | null): ManifestResourceEntry[] => {
  if (!resources?.detail?.length) return [];
  const manifestGroup = resources.detail.find(group => group.typeName === "MANIFEST");
  if (!manifestGroup?.entries?.length) return [];
  return manifestGroup.entries.flatMap(entry =>
    entry.langs.flatMap(lang =>
      lang.manifestInfo
        ? [{
            resourceId: entry.id,
            lang: lang.lang,
            manifestInfo: lang.manifestInfo
          }]
        : []
    )
  );
};

const addProcessorArchitectureFindings = (
  entries: ManifestResourceEntry[],
  machine: number,
  validated: Set<string>,
  warnings: Set<string>
): void => {
  const expectedArchitecture = getManifestProcessorArchitectureForMachine(machine);
  if (!expectedArchitecture) return;
  entries.forEach(entry => {
    const manifestArchitecture = normalizeArchitecture(entry.manifestInfo.processorArchitecture);
    if (!manifestArchitecture) return;
    if (manifestArchitecture === "*" || manifestArchitecture === expectedArchitecture) {
      validated.add(
        `Manifest ${describeManifestEntry(entry)} declares processorArchitecture="${manifestArchitecture}", ` +
          `which is consistent with COFF Machine ${machine.toString(16)}.`
      );
      return;
    }
    if (!DOCUMENTED_MANIFEST_ARCHITECTURES.has(manifestArchitecture)) return;
    warnings.add(
      `Manifest ${describeManifestEntry(entry)} declares processorArchitecture=` +
        `"${manifestArchitecture}", but COFF Machine ${machine.toString(16)} expects ` +
        `"${expectedArchitecture}" or "*".`
    );
  });
};

const addSupportedArchitecturesFindings = (
  entries: ManifestResourceEntry[],
  clr: PeClrHeader | null,
  validated: Set<string>,
  warnings: Set<string>
): void => {
  const ilOnly = clr != null && (clr.Flags & COMIMAGE_FLAGS_ILONLY) !== 0;
  entries.forEach(entry => {
    if (!entry.manifestInfo.supportedArchitectures.length) return;
    if (ilOnly) {
      validated.add(
        `Manifest ${describeManifestEntry(entry)} uses supportedArchitectures and the image advertises an IL-only CLR header.`
      );
      return;
    }
    warnings.add(
      `Manifest ${describeManifestEntry(entry)} uses supportedArchitectures, but the image ` +
        "does not advertise an IL-only CLR header."
    );
  });
};

const addConflictingValueFindings = (
  entries: ManifestResourceEntry[],
  selectValue: (entry: ManifestResourceEntry) => string | null,
  fieldName: string,
  validated: Set<string>,
  warnings: Set<string>
): void => {
  const values = new Map<string, string[]>();
  let presentValueCount = 0;
  entries.forEach(entry => {
    const selectedValue = selectValue(entry);
    if (selectedValue) presentValueCount += 1;
    const value = selectedValue || "(missing)";
    const members = values.get(value) || [];
    members.push(describeManifestEntry(entry));
    values.set(value, members);
  });
  if (values.size < 2) {
    if (entries.length > 1 && presentValueCount > 0) {
      const [value] = values.keys();
      validated.add(`Embedded manifest resources agree on ${fieldName}: "${value}".`);
    }
    return;
  }
  const details = [...values.entries()]
    .map(([value, members]) => `"${value}": ${members.join(", ")}`)
    .join(" | ");
  warnings.add(`Embedded manifest resources disagree on ${fieldName}. ${details}`);
};

export const analyzeManifestConsistency = (
  resources: PeResources | null,
  machine: number,
  clr: PeClrHeader | null
): ResourceManifestValidation | null => {
  const entries = getManifestEntries(resources);
  if (!entries.length) return null;
  const validated = new Set<string>();
  const warnings = new Set<string>();
  addProcessorArchitectureFindings(entries, machine, validated, warnings);
  addSupportedArchitecturesFindings(entries, clr, validated, warnings);
  addConflictingValueFindings(
    entries,
    entry => normalizeArchitecture(entry.manifestInfo.processorArchitecture),
    "processorArchitecture",
    validated,
    warnings
  );
  addConflictingValueFindings(
    entries,
    entry => normalizeText(entry.manifestInfo.requestedExecutionLevel)?.toLowerCase() || null,
    "requestedExecutionLevel",
    validated,
    warnings
  );
  return {
    status: warnings.size ? "warnings" : "consistent",
    checkedCount: validated.size + warnings.size,
    validated: [...validated],
    warnings: [...warnings]
  };
};

export const collectManifestWarnings = (
  resources: PeResources | null,
  machine: number,
  clr: PeClrHeader | null
): string[] => analyzeManifestConsistency(resources, machine, clr)?.warnings ?? [];

export const attachManifestValidation = (
  resources: PeResources | null,
  manifestValidation: ResourceManifestValidation | null
): PeResources | null => {
  if (!resources || !manifestValidation) return resources;
  let touched = false;
  const detail = resources.detail.map(group => {
    if (group.typeName !== "MANIFEST") return group;
    touched = true;
    return {
      ...group,
      entries: group.entries.map(entry => ({
        ...entry,
        langs: entry.langs.map(langEntry => ({
          ...langEntry,
          ...(hasManifestPreview(langEntry) ? { manifestValidation } : {})
        }))
      }))
    };
  });
  return touched ? { ...resources, detail } : resources;
};

const hasManifestPreview = (langEntry: ResourceLangWithPreview): boolean =>
  !!(langEntry.manifestInfo || langEntry.manifestTree || langEntry.previewKind === "text");

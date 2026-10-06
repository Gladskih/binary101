"use strict";
import { hex, humanSize } from "../../binary-utils.js";
import {
  isPeWindowsParseResult, type PeParseResult, type PeWindowsParseResult
} from "../../analyzers/pe/index.js";
import { renderPeSectionShell } from "./collapsible-section.js";
import { PE_DELAY_IMPORTS_PANEL_ID, PE_IMPORTS_PANEL_ID } from "./import-sections.js";
import { getLinuxBootSummary } from "./linux-boot.js";
import { getMsvcRttiSectionDescriptor } from "./msvc-rtti-section-descriptor.js";
import { getNativeAotSectionDescriptor } from "./native-aot-section-descriptor.js";
import { getPeClrSectionDescriptor } from "./clr-section-descriptor.js";
import { getPeAppHostSectionDescriptor } from "./apphost-section-descriptor.js";
import { PE_OVERLAY_PANEL_ID, getUnexplainedOverlaySize } from "./overlay.js";
import { PE_PACKER_SECTIONS, pePackerSectionDescriptors } from "./packer-sections.js";
import { getPePayloadLazySectionDescriptors } from "./payload-section-descriptors.js";
import { getPeSanityIssues } from "./layout.js";
export const PE_LAZY_SECTION_KEYS = {
  architecture: "architecture",
  appHost: "apphost",
  boundImports: "bound-imports",
  bunStandalone: PE_PACKER_SECTIONS["bun-standalone"].key,
  clr: "clr",
  dataDirectories: "data-directories",
  debug: "debug",
  dwarf: "dwarf",
  delayImports: "delay-imports",
  dosHeader: "dos-header",
  exception: "exception",
  exports: "exports",
  globalPtr: "global-ptr",
  iat: "iat",
  importLinking: "import-linking",
  imports: "imports",
  innoSetup: PE_PACKER_SECTIONS["inno-setup"].key,
  legacyCoffTail: "legacy-coff-tail",
  linuxBoot: "linux-boot",
  loadConfig: "load-config",
  msvcRtti: "msvc-rtti",
  itaniumRtti: "itanium-rtti",
  nativeAot: "native-aot",
  nsisInstaller: PE_PACKER_SECTIONS["nsis-installer"].key,
  overlay: "overlay",
  appendedPayloads: "appended-payloads",
  peHeaders: "pe-headers",
  reloc: "reloc",
  resources: "resources",
  resourcePayloads: "resource-payloads",
  sanity: "sanity",
  sanitizers: "sanitizers",
  sectionHeaders: "section-headers",
  security: "security",
  tls: "tls",
  typeLibraries: "type-libraries",
  upx: PE_PACKER_SECTIONS.upx.key
} as const;
export type PeLazySectionKey = typeof PE_LAZY_SECTION_KEYS[keyof typeof PE_LAZY_SECTION_KEYS];
export type PeLazySectionDescriptor =
  { id?: string; key: PeLazySectionKey; summary?: string; title: string };
const plural = (count: number, one: string, many: string): string =>
  `${count} ${count === 1 ? one : many}`;
const coffTailSummary = (pe: PeParseResult): string =>
  (pe.coff.NumberOfSymbols >>> 0) > 0
    ? plural(pe.coff.NumberOfSymbols >>> 0, "symbol-table record", "symbol-table records")
    : "COFF string table";
const pushIf = (
  descriptors: PeLazySectionDescriptor[],
  condition: unknown,
  descriptor: PeLazySectionDescriptor
): void => {
  if (condition) descriptors.push(descriptor);
};
const importFunctionCount = (pe: PeWindowsParseResult): number =>
  pe.imports.entries.reduce((count, entry) => count + (entry.functions?.length ?? 0), 0);
const delayImportFunctionCount = (pe: PeWindowsParseResult): number =>
  pe.delayImports?.entries.reduce((count, entry) => count + (entry.functions?.length ?? 0), 0) ?? 0;
const resourceLeafCount = (pe: PeWindowsParseResult): number =>
  pe.resources?.top?.reduce((count, row) => count + (row.leafCount ?? 0), 0) ??
  pe.resources?.paths?.length ??
  pe.resources?.detail?.reduce((count, group) =>
    count + group.entries.reduce((entryCount, entry) => entryCount + entry.langs.length, 0), 0
  ) ??
  0;
const hasCoffTail = (pe: PeParseResult): boolean =>
  (pe.coff.NumberOfSymbols >>> 0) !== 0 || pe.coffStringTableSize != null;
const hasSanity = (pe: PeParseResult): boolean =>
  getPeSanityIssues(pe).length > 0;

const addHeaderDescriptors = (pe: PeParseResult, descriptors: PeLazySectionDescriptor[]): void => {
  descriptors.push({
    key: PE_LAZY_SECTION_KEYS.dosHeader,
    summary: `e_lfanew ${hex(pe.dos.e_lfanew, 8)}`,
    title: "DOS header"
  });
  descriptors.push({
    key: PE_LAZY_SECTION_KEYS.peHeaders,
    summary: `${plural(pe.coff.NumberOfSections, "section", "sections")}`,
    title: "PE/COFF headers"
  });
  pushIf(descriptors, pe.dirs?.length, {
    key: PE_LAZY_SECTION_KEYS.dataDirectories,
    summary: `${pe.dirs?.filter(directory => directory.rva || directory.size).length ?? 0} present`,
    title: "Data directories"
  });
  pushIf(descriptors, pe.sections?.length, {
    key: PE_LAZY_SECTION_KEYS.sectionHeaders,
    summary: plural(pe.sections?.length ?? 0, "section", "sections"),
    title: "Section headers"
  });
  pushIf(descriptors, pe.dwarf, {
    key: PE_LAZY_SECTION_KEYS.dwarf,
    summary: `${plural(pe.dwarf?.units.length ?? 0, "unit", "units")}`,
    title: "DWARF debug information"
  });
  pushIf(descriptors, hasCoffTail(pe), {
    key: PE_LAZY_SECTION_KEYS.legacyCoffTail,
    summary: coffTailSummary(pe),
    title: "Legacy COFF tail"
  });
};

const addWindowsToolingDescriptors = (
  pe: PeWindowsParseResult,
  descriptors: PeLazySectionDescriptor[]
): void => {
  descriptors.push(...pePackerSectionDescriptors(pe.packers));
  pushIf(descriptors, pe.loadcfg, {
    key: PE_LAZY_SECTION_KEYS.loadConfig,
    summary: `v${pe.loadcfg?.Major ?? 0}.${pe.loadcfg?.Minor ?? 0}`,
    title: "Load Config"
  });
  pushIf(descriptors, pe.debug, {
    key: PE_LAZY_SECTION_KEYS.debug,
    summary: `debug: ${plural(pe.debug?.entries?.length ?? 0, "entry", "entries")}`,
    title: "Debug directory"
  });
  pushIf(descriptors, pe.linuxBoot, {
    key: PE_LAZY_SECTION_KEYS.linuxBoot,
    summary: pe.linuxBoot ? getLinuxBootSummary(pe.linuxBoot) : "",
    title: "Linux boot protocol"
  });
};

const addWindowsImportDescriptors = (
  pe: PeWindowsParseResult,
  descriptors: PeLazySectionDescriptor[]
): void => {
  pushIf(descriptors, pe.importLinking?.modules.length, {
    key: PE_LAZY_SECTION_KEYS.importLinking,
    summary: `${plural(pe.importLinking?.modules.length ?? 0, "module", "modules")}`,
    title: "Import linkage"
  });
  pushIf(descriptors, pe.imports.entries.length || pe.imports.warning, {
    id: PE_IMPORTS_PANEL_ID,
    key: PE_LAZY_SECTION_KEYS.imports,
    summary: `imports: ${pe.imports.entries.length} DLL / ${importFunctionCount(pe)} functions`,
    title: "Import table"
  });
};

const addWindowsDeferredImportDescriptors = (
  pe: PeWindowsParseResult,
  descriptors: PeLazySectionDescriptor[]
): void => {
  pushIf(descriptors, pe.boundImports?.entries.length || pe.boundImports?.warning, {
    key: PE_LAZY_SECTION_KEYS.boundImports,
    summary: `${plural(pe.boundImports?.entries.length ?? 0, "module", "modules")}`,
    title: "Bound imports"
  });
  pushIf(descriptors, pe.delayImports?.entries.length || pe.delayImports?.warning, {
    id: PE_DELAY_IMPORTS_PANEL_ID,
    key: PE_LAZY_SECTION_KEYS.delayImports,
    summary:
      `delay imports: ${pe.delayImports?.entries.length ?? 0} DLL / ` +
      `${delayImportFunctionCount(pe)} functions`,
    title: "Delay-load imports"
  });
  pushIf(descriptors, pe.iat || pe.importLinking?.inferredEagerIat, {
    key: PE_LAZY_SECTION_KEYS.iat,
    summary:
      `${pe.iat ? "declared" : "undeclared"}, ` +
      `${pe.importLinking?.inferredEagerIat?.ranges.length ?? 0} inferred range(s)`,
    title: "Import Address Tables (IAT)"
  });
};

const addWindowsDirectoryDescriptors = (
  pe: PeWindowsParseResult,
  descriptors: PeLazySectionDescriptor[]
): void => {
  pushIf(descriptors, pe.resources, {
    key: PE_LAZY_SECTION_KEYS.resources,
    summary: `resources: ${resourceLeafCount(pe)} leaves`,
    title: "Resources"
  });
  if (pe.resources?.detail?.some(group => group.typeName === "TYPELIB")) {
    descriptors.push({ id: "pe-type-libraries", key: PE_LAZY_SECTION_KEYS.typeLibraries,
      title: "Type libraries (COM)" });
  }
  if (pe.exports) descriptors.push({
    key: PE_LAZY_SECTION_KEYS.exports,
    summary: plural(pe.exports.entries.length, "entry", "entries"),
    title: "Export directory"
  });
  pushIf(descriptors, pe.tls, {
    key: PE_LAZY_SECTION_KEYS.tls,
    summary: pe.tls?.parsed === false
      ? "unparsed"
      : plural(pe.tls?.CallbackCount ?? 0, "callback", "callbacks") +
        (pe.tls?.callbackTableStatus === "incomplete" ? " (incomplete list)" : ""),
    title: "TLS directory"
  });
  if (pe.reloc) descriptors.push({
    key: PE_LAZY_SECTION_KEYS.reloc,
    summary: plural(pe.reloc.totalEntries, "entry", "entries"),
    title: "Base relocations"
  });
  if (pe.msvcRtti) descriptors.push(getMsvcRttiSectionDescriptor(pe.msvcRtti));
  if (pe.itaniumRtti) descriptors.push({ key: PE_LAZY_SECTION_KEYS.itaniumRtti,
    title: "Itanium C++ RTTI", summary: `${pe.itaniumRtti.types.length} types`
  });
  if (pe.exception) descriptors.push({
    key: PE_LAZY_SECTION_KEYS.exception,
    summary: plural(pe.exception.functionCount, "function", "functions"),
    title: "Exception directory (.pdata)"
  });
  addWindowsDeferredImportDescriptors(pe, descriptors);
  addWindowsRuntimeDescriptors(pe, descriptors);
};

const addWindowsRuntimeDescriptors = (
  pe: PeWindowsParseResult,
  descriptors: PeLazySectionDescriptor[]
): void => {
  const clr = getPeClrSectionDescriptor(pe);
  if (clr) descriptors.push(clr);
  if (pe.appHost) descriptors.push(getPeAppHostSectionDescriptor(pe.appHost));
  pushIf(descriptors, pe.nativeAotCandidate,
    getNativeAotSectionDescriptor(pe.nativeAotCandidate));
  pushIf(descriptors, pe.security, {
    key: PE_LAZY_SECTION_KEYS.security,
    summary: `Authenticode: ${plural(pe.security?.count ?? 0, "record", "records")}`,
    title: "Security (WIN_CERTIFICATE)"
  });
  pushIf(descriptors, pe.architecture, {
    key: PE_LAZY_SECTION_KEYS.architecture,
    summary: "reserved slot",
    title: "Architecture directory"
  });
  pushIf(descriptors, pe.globalPtr, {
    key: PE_LAZY_SECTION_KEYS.globalPtr,
    summary: "machine-specific",
    title: "Global pointer (GP)"
  });
};

const addWindowsDescriptors = (
  pe: PeWindowsParseResult,
  descriptors: PeLazySectionDescriptor[]
): void => {
  addWindowsToolingDescriptors(pe, descriptors);
  addWindowsImportDescriptors(pe, descriptors);
  addWindowsDirectoryDescriptors(pe, descriptors);
};

export const getPeLazySectionDescriptors = (pe: PeParseResult): PeLazySectionDescriptor[] => {
  const descriptors: PeLazySectionDescriptor[] = [];
  addHeaderDescriptors(pe, descriptors);
  if (isPeWindowsParseResult(pe)) {
    descriptors.push({ key: PE_LAZY_SECTION_KEYS.sanitizers, title: "Sanitizer evidence" });
    addWindowsDescriptors(pe, descriptors);
    descriptors.push(...getPePayloadLazySectionDescriptors(pe.payloads));
  }
  pushIf(descriptors, pe.overlay?.ranges.length || pe.overlay?.warnings?.length, {
    id: PE_OVERLAY_PANEL_ID,
    key: PE_LAZY_SECTION_KEYS.overlay,
    summary: `overlay: ${humanSize(getUnexplainedOverlaySize(pe))}`,
    title: "Overlay"
  });
  pushIf(descriptors, hasSanity(pe), {
    key: PE_LAZY_SECTION_KEYS.sanity,
    summary: "structural findings",
    title: "Sanity"
  });
  return descriptors;
};
export const renderPeLazySectionShells = (pe: PeParseResult, out: string[]): void => {
  getPeLazySectionDescriptors(pe).forEach(section => {
    out.push(renderPeSectionShell(section.key, section.title, section.summary, section.id));
  });
};

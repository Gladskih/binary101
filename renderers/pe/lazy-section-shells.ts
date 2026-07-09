"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import {
  isPeWindowsParseResult,
  type PeParseResult,
  type PeWindowsParseResult
} from "../../analyzers/pe/index.js";
import { renderPeSectionShell } from "./collapsible-section.js";
import { PE_DELAY_IMPORTS_PANEL_ID, PE_IMPORTS_PANEL_ID } from "./import-sections.js";
import { getLinuxBootSummary } from "./linux-boot.js";
import { PE_OVERLAY_PANEL_ID, getUnexplainedOverlaySize } from "./overlay.js";
import { getPeSanityIssues } from "./layout.js";

export const PE_LAZY_SECTION_KEYS = {
  architecture: "architecture",
  boundImports: "bound-imports",
  clr: "clr",
  dataDirectories: "data-directories",
  debug: "debug",
  delayImports: "delay-imports",
  dosHeader: "dos-header",
  exception: "exception",
  exports: "exports",
  globalPtr: "global-ptr",
  iat: "iat",
  importLinking: "import-linking",
  imports: "imports",
  legacyCoffTail: "legacy-coff-tail",
  linuxBoot: "linux-boot",
  loadConfig: "load-config",
  nativeAot: "native-aot",
  overlay: "overlay",
  packers: "packers",
  peHeaders: "pe-headers",
  reloc: "reloc",
  resources: "resources",
  sanity: "sanity",
  sectionHeaders: "section-headers",
  security: "security",
  tls: "tls"
} as const;

export type PeLazySectionKey =
  typeof PE_LAZY_SECTION_KEYS[keyof typeof PE_LAZY_SECTION_KEYS];

export type PeLazySectionDescriptor = {
  id?: string;
  key: PeLazySectionKey;
  summary?: string;
  title: string;
};

const compactCount = (count: number): string =>
  count >= 10_000 ? `${Math.round(count / 1000)}k` : String(count);

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

const metadataRowCount = (pe: PeWindowsParseResult): number =>
  pe.clr?.meta?.tables?.rowCounts.reduce((count, row) => count + row.rows, 0) ?? 0;

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
  pushIf(descriptors, pe.packers?.findings.length || pe.packers?.warnings?.length, {
    key: PE_LAZY_SECTION_KEYS.packers,
    summary: `${pe.packers?.findings.length ?? 0} finding(s)`,
    title: "Packaging signatures"
  });
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
  pushIf(descriptors, pe.exports, {
    key: PE_LAZY_SECTION_KEYS.exports,
    summary: `${plural(pe.exports?.entries?.length ?? 0, "entry", "entries")}`,
    title: "Export directory"
  });
  pushIf(descriptors, pe.tls, {
    key: PE_LAZY_SECTION_KEYS.tls,
    summary: pe.tls?.parsed === false
      ? "unparsed"
      : `${plural(pe.tls?.CallbackCount ?? 0, "callback", "callbacks")}`,
    title: "TLS directory"
  });
  pushIf(descriptors, pe.reloc, {
    key: PE_LAZY_SECTION_KEYS.reloc,
    summary: `${plural(pe.reloc?.totalEntries ?? 0, "entry", "entries")}`,
    title: "Base relocations"
  });
  pushIf(descriptors, pe.exception, {
    key: PE_LAZY_SECTION_KEYS.exception,
    summary: `${plural(pe.exception?.functionCount ?? 0, "function", "functions")}`,
    title: "Exception directory (.pdata)"
  });
  addWindowsDeferredImportDescriptors(pe, descriptors);
  pushIf(descriptors, pe.clr, {
    key: PE_LAZY_SECTION_KEYS.clr,
    summary: metadataRowCount(pe) > 0
      ? `CLR metadata: ${compactCount(metadataRowCount(pe))} rows`
      : `runtime v${pe.clr?.MajorRuntimeVersion ?? 0}.${pe.clr?.MinorRuntimeVersion ?? 0}`,
    title: "CLR (.NET) header"
  });
  pushIf(descriptors, pe.nativeAotCandidate, {
    key: PE_LAZY_SECTION_KEYS.nativeAot,
    summary: "conservative evidence",
    title: "Native AOT candidate"
  });
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
  if (isPeWindowsParseResult(pe)) addWindowsDescriptors(pe, descriptors);
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

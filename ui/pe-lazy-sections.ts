"use strict";

import {
  isPeWindowsParseResult,
  type PeParseResult,
  type PeWindowsParseResult
} from "../analyzers/pe/index.js";
import type { PePackerId } from "../analyzers/pe/packers/index.js";
import { renderHeaders } from "../renderers/pe/headers.js";
import { renderPackerReport } from "../renderers/pe/packers.js";
import { renderLoadConfig } from "../renderers/pe/load-config.js";
import { renderLinuxBoot } from "../renderers/pe/linux-boot.js";
import { renderDebug } from "../renderers/pe/debug-view.js";
import { renderPeDwarf } from "../renderers/pe/dwarf.js";
import { renderResources } from "../renderers/pe/resources.js";
import { renderException } from "../renderers/pe/exception.js";
import { renderNativeAotCandidate } from "../renderers/pe/native-aot.js";
import { renderMsvcRtti } from "../renderers/pe/msvc-rtti.js";
import { renderOverlayPanel } from "../renderers/pe/overlay.js";
import { renderPePayloads } from "../renderers/pe/payloads.js";
import {
  PE_LAZY_SECTION_KEYS,
  type PeLazySectionKey
} from "../renderers/pe/lazy-section-shells.js";
import {
  renderArchitectureDirectory,
  renderClr,
  renderExports,
  renderGlobalPtrDirectory,
  renderSecurity,
  renderTls
} from "../renderers/pe/directories.js";
import {
  renderBoundImports,
  renderDelayImports,
  renderIat,
  renderImportLinking,
  renderImportsPanel
} from "../renderers/pe/import-sections.js";
import { renderReloc, renderSanity } from "../renderers/pe/layout.js";
import { enhanceAccessibleTooltips } from "./accessible-tooltips.js";
import { enhancePeDisassemblyPagedTables } from "./analysis-paged-tables.js";
import { captureOpenDetails, restoreOpenDetails } from "./details-open-state.js";
import {
  capturePagedSortableTableState,
  type PagedSortableTableSnapshot
} from "./paged-sortable-tables.js";
import { syncManifestTreeControls } from "./manifest-tree-controls.js";
import {
  captureSortableTableState,
  enhanceSortableTables,
  restoreSortableTableState,
  type SortableTableState
} from "./sortable-tables.js";
import {
  captureLazyDomState,
  emptyLazyDomState,
  restoreLazyDomState,
  type LazyDomState
} from "./lazy-section-dom-state.js";

type LazySectionSnapshot = {
  domState: LazyDomState;
  openDetails: Set<string>;
  pagedTables: PagedSortableTableSnapshot[];
  sortableTables: SortableTableState[];
};

const enhancedRoots = new WeakSet<ParentNode>();
const parseResultByRoot = new WeakMap<ParentNode, PeParseResult>();
const snapshotBySection = new WeakMap<HTMLElement, LazySectionSnapshot>();

const emptySnapshot = (): LazySectionSnapshot => ({
  domState: emptyLazyDomState(),
  openDetails: new Set(),
  pagedTables: [],
  sortableTables: []
});

const renderToString = (render: (out: string[]) => void): string => {
  const out: string[] = [];
  render(out);
  return out.join("");
};

const renderPackerById = (pe: PeWindowsParseResult, id: PePackerId): string => {
  const report = pe.packers?.reports.find(candidate => candidate.id === id);
  return report ? renderToString(out => renderPackerReport(report, out, pe.payloads)) : "";
};

const renderWindowsLazyMarkup = (
  pe: PeWindowsParseResult,
  key: PeLazySectionKey
): string => {
  switch (key) {
    case PE_LAZY_SECTION_KEYS.upx:
      return renderPackerById(pe, "upx");
    case PE_LAZY_SECTION_KEYS.nsisInstaller:
      return renderPackerById(pe, "nsis-installer");
    case PE_LAZY_SECTION_KEYS.bunStandalone:
      return renderPackerById(pe, "bun-standalone");
    case PE_LAZY_SECTION_KEYS.loadConfig:
      return renderToString(out => renderLoadConfig(pe, out));
    case PE_LAZY_SECTION_KEYS.debug:
      return renderToString(out => renderDebug(pe, out));
    case PE_LAZY_SECTION_KEYS.linuxBoot:
      return renderToString(out => renderLinuxBoot(pe, out));
    case PE_LAZY_SECTION_KEYS.importLinking:
      return renderToString(out => renderImportLinking(pe, out));
    case PE_LAZY_SECTION_KEYS.imports:
      return renderImportsPanel(pe);
    case PE_LAZY_SECTION_KEYS.resources:
      return pe.resources ? renderToString(out => renderResources(pe.resources!, out)) : "";
    case PE_LAZY_SECTION_KEYS.exports:
      return pe.exports ? renderToString(out => renderExports(pe.exports!, out)) : "";
    case PE_LAZY_SECTION_KEYS.tls:
      return pe.tls ? renderToString(out => renderTls(pe.tls!, out)) : "";
    case PE_LAZY_SECTION_KEYS.reloc:
      return pe.reloc ? renderToString(out => renderReloc(pe.reloc!, out)) : "";
    case PE_LAZY_SECTION_KEYS.msvcRtti:
      return pe.msvcRtti ? renderToString(out => renderMsvcRtti(pe, out)) : "";
    case PE_LAZY_SECTION_KEYS.exception:
      return pe.exception ? renderToString(out => renderException(pe.exception!, out)) : "";
    case PE_LAZY_SECTION_KEYS.boundImports:
      return renderToString(out => renderBoundImports(pe, out));
    case PE_LAZY_SECTION_KEYS.delayImports:
      return renderToString(out => renderDelayImports(pe, out));
    case PE_LAZY_SECTION_KEYS.clr:
      return pe.clr ? renderToString(out => renderClr(pe.clr!, out)) : "";
    case PE_LAZY_SECTION_KEYS.nativeAot:
      return renderToString(out => renderNativeAotCandidate(pe.nativeAotCandidate, out));
    case PE_LAZY_SECTION_KEYS.security:
      return pe.security ? renderToString(out => renderSecurity(pe.security!, out)) : "";
    case PE_LAZY_SECTION_KEYS.iat:
      return renderToString(out => renderIat(pe, out));
    case PE_LAZY_SECTION_KEYS.architecture:
      return renderToString(out => renderArchitectureDirectory(pe, out));
    case PE_LAZY_SECTION_KEYS.globalPtr:
      return renderToString(out => renderGlobalPtrDirectory(pe, out));
    case PE_LAZY_SECTION_KEYS.payloads:
      return renderToString(out => renderPePayloads(pe.payloads, out));
    default:
      return "";
  }
};

const renderLazySectionMarkup = (pe: PeParseResult, key: PeLazySectionKey): string => {
  switch (key) {
    case PE_LAZY_SECTION_KEYS.dosHeader:
    case PE_LAZY_SECTION_KEYS.peHeaders:
    case PE_LAZY_SECTION_KEYS.dataDirectories:
    case PE_LAZY_SECTION_KEYS.sectionHeaders:
    case PE_LAZY_SECTION_KEYS.legacyCoffTail:
      return renderToString(out => renderHeaders(pe, out));
    case PE_LAZY_SECTION_KEYS.dwarf:
      return renderToString(out => renderPeDwarf(pe, out));
    case PE_LAZY_SECTION_KEYS.overlay:
      return renderOverlayPanel(pe);
    case PE_LAZY_SECTION_KEYS.sanity:
      return renderToString(out => renderSanity(pe, out));
    default:
      return isPeWindowsParseResult(pe) ? renderWindowsLazyMarkup(pe, key) : "";
  }
};

const sectionTitle = (section: Element): string =>
  section.querySelector(":scope > details > summary b")?.textContent?.trim() ?? "";

const sectionBody = (section: ParentNode): HTMLElement | null =>
  section.querySelector<HTMLElement>("[data-pe-lazy-section-body]");

const sectionDetails = (section: HTMLElement): HTMLDetailsElement | null =>
  Array.from(section.children).find(
    child => child instanceof HTMLElement && child.tagName === "DETAILS"
  ) as HTMLDetailsElement | null;

const extractBodyHtml = (markup: string, title: string): string => {
  const template = document.createElement("template");
  template.innerHTML = markup;
  const sections = Array.from(template.content.querySelectorAll<HTMLElement>(".peSection"));
  const section = sections.find(candidate => sectionTitle(candidate) === title) ?? sections[0];
  return section?.querySelector(".peSectionBody")?.innerHTML ?? "";
};

const captureSnapshot = (body: HTMLElement): LazySectionSnapshot => ({
  domState: captureLazyDomState(body),
  openDetails: captureOpenDetails(body),
  pagedTables: capturePagedSortableTableState(body),
  sortableTables: captureSortableTableState(body)
});

const restoreMountedState = (
  body: HTMLElement,
  pe: PeParseResult,
  snapshot: LazySectionSnapshot
): void => {
  enhanceSortableTables(body);
  restoreSortableTableState(body, snapshot.sortableTables);
  enhancePeDisassemblyPagedTables(body, pe, snapshot.pagedTables);
  enhanceAccessibleTooltips(body);
  restoreOpenDetails(
    body,
    snapshot.openDetails,
    viewer => syncManifestTreeControls(viewer as Element | null)
  );
  restoreLazyDomState(body, snapshot.domState);
};

const mountSection = (section: HTMLElement, pe: PeParseResult): void => {
  const body = sectionBody(section);
  const key = section.dataset["peLazySection"] as PeLazySectionKey | undefined;
  if (!body || !key || section.dataset["peLazyMounted"] === "true") return;
  body.innerHTML = extractBodyHtml(renderLazySectionMarkup(pe, key), sectionTitle(section));
  section.dataset["peLazyMounted"] = "true";
  restoreMountedState(body, pe, snapshotBySection.get(section) ?? emptySnapshot());
};

const unmountSection = (section: HTMLElement): void => {
  const body = sectionBody(section);
  if (!body || section.dataset["peLazyMounted"] !== "true") return;
  snapshotBySection.set(section, captureSnapshot(body));
  body.innerHTML = "";
  section.dataset["peLazyMounted"] = "false";
};

const rootForSection = (section: HTMLElement): ParentNode | null =>
  section.closest("#analysisValue") ?? section.parentElement;

const handleToggle = (event: Event): void => {
  const details = event.target instanceof HTMLElement && event.target.tagName === "DETAILS"
    ? event.target as HTMLDetailsElement
    : null;
  const section = details?.closest<HTMLElement>("[data-pe-lazy-section]");
  if (!details || !section || details !== sectionDetails(section)) return;
  const root = rootForSection(section);
  const pe = root ? parseResultByRoot.get(root) : undefined;
  if (!pe) return;
  if (details.open) {
    mountSection(section, pe);
  } else {
    unmountSection(section);
  }
};

const mountOpenSections = (root: ParentNode, pe: PeParseResult): void => {
  root.querySelectorAll<HTMLElement>("[data-pe-lazy-section]").forEach(section => {
    const details = sectionDetails(section);
    if (details?.open) mountSection(section, pe);
  });
};

export const enhancePeLazySections = (root: ParentNode, pe: PeParseResult | null): void => {
  if (!pe) return;
  parseResultByRoot.set(root, pe);
  if (!enhancedRoots.has(root)) {
    root.addEventListener("toggle", handleToggle, true);
    enhancedRoots.add(root);
  }
  mountOpenSections(root, pe);
};

export const refreshPeLazySection = (
  key: PeLazySectionKey,
  pe: PeParseResult
): boolean => {
  if (typeof document.querySelector !== "function") return false;
  const section = document.querySelector<HTMLElement>(`[data-pe-lazy-section="${key}"]`);
  const body = section ? sectionBody(section) : null;
  if (!section || !body) return false;
  const root = rootForSection(section);
  if (root) parseResultByRoot.set(root, pe);
  if (section.dataset["peLazyMounted"] === "true") {
    snapshotBySection.set(section, captureSnapshot(body));
    body.innerHTML = "";
    section.dataset["peLazyMounted"] = "false";
  }
  if (sectionDetails(section)?.open) mountSection(section, pe);
  return true;
};

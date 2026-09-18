import type { ElfParseResult } from "../analyzers/elf/types.js";
import { getElfLazySections, type ElfLazySection } from "../renderers/elf/lazy-sections.js";
import { getElfPagedTableModel } from "../renderers/elf/paged-tables.js";
import { enhanceAccessibleTooltips } from "./accessible-tooltips.js";
import { captureOpenDetails, restoreOpenDetails } from "./details-open-state.js";
import { captureLazyDomState, restoreLazyDomState } from "./lazy-section-dom-state.js";
import { capturePagedSortableTableState, enhancePagedSortableTables } from "./paged-sortable-tables.js";
import { captureSortableTableState, enhanceSortableTables, restoreSortableTableState } from "./sortable-tables.js";

const sectionBody = (section: HTMLElement): HTMLElement | null =>
  section.querySelector<HTMLElement>(".peSectionBody") ??
  section.querySelector<HTMLElement>(".analysisPanelBody");

const captureState = (body: HTMLElement) => ({
  details: captureOpenDetails(body),
  dom: captureLazyDomState(body),
  pages: capturePagedSortableTableState(body),
  sorts: captureSortableTableState(body)
});

type SectionState = {
  elf: ElfParseResult;
  descriptor: ElfLazySection;
  mounted: boolean;
  snapshot?: ReturnType<typeof captureState>;
};
const states = new WeakMap<HTMLElement, SectionState>();

const mount = (body: HTMLElement, state: SectionState): void => {
  if (state.mounted) return;
  body.innerHTML = state.descriptor.render();
  state.mounted = true;
  enhanceSortableTables(body);
  enhancePagedSortableTables(body, id => getElfPagedTableModel(state.elf, id), state.snapshot?.pages);
  enhanceAccessibleTooltips(body);
  if (!state.snapshot) return;
  restoreSortableTableState(body, state.snapshot.sorts);
  restoreOpenDetails(body, state.snapshot.details, () => {});
  restoreLazyDomState(body, state.snapshot.dom);
};

const unmount = (body: HTMLElement, state: SectionState): void => {
  if (!state.mounted) return;
  state.snapshot = captureState(body);
  body.innerHTML = "";
  state.mounted = false;
};

const enhanceSection = (
  section: HTMLElement, elf: ElfParseResult, descriptor: ElfLazySection
): void => {
  const details = section.querySelector<HTMLDetailsElement>(":scope > details");
  const body = sectionBody(section);
  if (!details || !body) return;
  const previous = states.get(section);
  if (previous) { previous.elf = elf; previous.descriptor = descriptor; return; }
  const state: SectionState = { elf, descriptor, mounted: false };
  states.set(section, state);
  details.addEventListener("toggle", event => {
    if (event.target !== details) return;
    if (details.open) mount(body, state);
    else unmount(body, state);
  });
  if (details.open) mount(body, state);
};

export const enhanceElfLazySections = (root: ParentNode, elf: ElfParseResult | null): void => {
  if (!elf) return;
  const descriptors = new Map(getElfLazySections(elf).map(section => [section.key, section]));
  root.querySelectorAll<HTMLElement>("[data-elf-lazy-section]").forEach(section => {
    const descriptor = descriptors.get(section.dataset["elfLazySection"] ?? "");
    if (descriptor) enhanceSection(section, elf, descriptor);
  });
};

export const refreshElfLazySection = (key: string, elf: ElfParseResult): boolean => {
  if (typeof document.querySelector !== "function") return false;
  const section = document.querySelector<HTMLElement>(`[data-elf-lazy-section="${key}"]`);
  if (!section) return false;
  const state = states.get(section);
  const body = sectionBody(section);
  const descriptor = getElfLazySections(elf).find(candidate => candidate.key === key);
  if (!state || !body || !descriptor) return false;
  unmount(body, state);
  state.elf = elf;
  state.descriptor = descriptor;
  if (section.querySelector<HTMLDetailsElement>(":scope > details")?.open) mount(body, state);
  return true;
};

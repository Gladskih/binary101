import type { ParseForUiResult } from "../analyzers/index.js";
import { revealPagedSortableTableRow } from "./paged-sortable-tables.js";

const revealResourceTarget = (container: HTMLElement, link: HTMLElement,
  entries: Array<{ langs: unknown[] }>, groupIndex: number, entryIndex: number, languageIndex: number): void => {
  for (let parent: HTMLElement | null = container; parent; parent = parent.parentElement) {
    if (parent.tagName === "DETAILS") (parent as HTMLDetailsElement).open = true;
  }
  const table = container.querySelector<HTMLElement>("[data-paged-sortable-table-root]");
  if (table) revealPagedSortableTableRow(table,
    entries.slice(0, entryIndex).reduce((sum, entry) => sum + entry.langs.length, 0) + languageIndex);
  link.ownerDocument.getElementById(`pe-resource-${groupIndex}-${entryIndex}-${languageIndex}`)
    ?.scrollIntoView({ block: "center" });
};

const validResourceTarget = (group: { entries: Array<{ langs: unknown[] }> } | undefined,
  entry: number, language: number): group is { entries: Array<{ langs: unknown[] }> } =>
  Boolean(group?.entries[entry]?.langs[language]);

const navigateResource = (link: HTMLElement, result: ParseForUiResult): void => {
  const match = /^(\d+)-(\d+)-(\d+)$/u.exec(link.dataset["peResourceTarget"] ?? "");
  if (!match || result.analyzer !== "pe" || !("resources" in result.parsed)) return;
  const [groupIndex, entryIndex, languageIndex] = match.slice(1).map(Number) as [number, number, number];
  const resources = result.parsed.resources;
  if (!resources) return;
  const group = resources.detail[groupIndex];
  if (!validResourceTarget(group, entryIndex, languageIndex)) return;
  const container = link.ownerDocument.querySelector<HTMLElement>(`[data-pe-resource-group="${groupIndex}"]`);
  if (!container) return;
  revealResourceTarget(container, link, group.entries, groupIndex, entryIndex, languageIndex);
};

const selectDialogControl = (control: HTMLElement): void => {
  const dialog = control.closest<HTMLElement>("[data-pe-dialog]");
  const index = control.dataset["peDialogControl"];
  if (!dialog || index == null) return;
  dialog.querySelectorAll(".peDialog__control--selected,.peDialog__properties--selected")
    .forEach(element => element.classList.remove("peDialog__control--selected", "peDialog__properties--selected"));
  control.classList.add("peDialog__control--selected");
  dialog.querySelector(`[data-pe-dialog-property="${index}"]`)?.classList.add("peDialog__properties--selected");
};

const switchRibbonTab = (target: Element | null): void => {
  const tab = target?.closest<HTMLElement>("[data-pe-ribbon-tab]");
  const ribbon = tab?.closest("[data-pe-ribbon]");
  if (tab && ribbon) {
    ribbon.querySelectorAll<HTMLElement>("[data-pe-ribbon-tab]").forEach(button =>
      button.setAttribute("aria-selected", String(button === tab)));
    ribbon.querySelectorAll<HTMLElement>("[data-pe-ribbon-panel]").forEach(panel => {
      panel.hidden = panel.dataset["peRibbonPanel"] !== tab.dataset["peRibbonTab"];
    });
  }
};

export const handlePeResourcePreviewClick = (event: Event, result: ParseForUiResult): void => {
  const target = typeof Element !== "undefined" && event.target instanceof Element ? event.target : null;
  const link = target?.closest<HTMLElement>("[data-pe-resource-target]");
  if (link) { event.preventDefault(); navigateResource(link, result); }
  const control = target?.closest<HTMLElement>("[data-pe-dialog-control]");
  if (control) selectDialogControl(control);
  switchRibbonTab(target);
};

const updateDialogInput = (input: HTMLInputElement): void => {
  const dialog = input.closest<HTMLElement>("[data-pe-dialog]");
  if (!dialog) return;
  if (input.hasAttribute("data-pe-dialog-hidden")) dialog.toggleAttribute("data-hide-invisible", !input.checked);
  if (input.hasAttribute("data-pe-dialog-tab-order")) dialog.toggleAttribute("data-show-tab-order", input.checked);
  if (input.hasAttribute("data-pe-dialog-zoom")) {
    const window = dialog.querySelector<HTMLElement>(".peDialog__window");
    if (window) window.style.setProperty("zoom", String(Number(input.value) / 100));
  }
};

const measureDialog = (dialog: HTMLElement): void => {
  const client = dialog.querySelector<HTMLElement>("[data-pe-dialog-client]");
  const context = dialog.ownerDocument.createElement("canvas").getContext("2d");
  if (!client || !context) return;
  const style = getComputedStyle(dialog);
  context.font = `${style.fontStyle} ${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
  // MapDialogRect divides the average character width by 4 and font height by 8.
  // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-mapdialogrect
  const metrics = context.measureText("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
  const unitX = Math.max(0.25, metrics.width / 52 / 4);
  const unitY = Math.max(0.25, (metrics.fontBoundingBoxAscent + metrics.fontBoundingBoxDescent ||
    Number.parseFloat(style.fontSize) * 1.2) / 8);
  dialog.style.setProperty("--pe-dlu-x", `${unitX}px`);
  dialog.style.setProperty("--pe-dlu-y", `${unitY}px`);
  const baseWidth = Number(dialog.dataset["peDialogWidth"]) * unitX;
  const baseHeight = Number(dialog.dataset["peDialogHeight"]) * unitY;
  if (typeof ResizeObserver === "undefined") return;
  const observer = new ResizeObserver(() => {
    if (!dialog.isConnected) { observer.disconnect(); return; }
    dialog.style.setProperty("--pe-dialog-dx", `${client.clientWidth - baseWidth}px`);
    dialog.style.setProperty("--pe-dialog-dy", `${client.clientHeight - baseHeight}px`);
  });
  observer.observe(client);
};

export const enhancePeResourcePreviews = (root: ParentNode): void => {
  root.querySelectorAll<HTMLElement>("[data-pe-dialog]:not([data-pe-dialog-ready])").forEach(dialog => {
    dialog.dataset["peDialogReady"] = "true";
    measureDialog(dialog);
    dialog.addEventListener("input", event => {
      if (event.target instanceof HTMLInputElement) updateDialogInput(event.target);
    });
    dialog.addEventListener("keydown", event => {
      const target = event.target instanceof HTMLElement ? event.target : null;
      if ((event.key === "Enter" || event.key === " ") && target?.hasAttribute("data-pe-dialog-control")) {
        event.preventDefault(); selectDialogControl(target);
      }
    });
  });
};

export const handleResourcePreviewRendered = (event: Event): void => {
  if (typeof Element !== "undefined" && event.target instanceof Element) enhancePeResourcePreviews(event.target);
};

import type { ParseForUiResult } from "../analyzers/analyzer-types.js";
import type { WorkspaceSection } from "./workspace-sections.js";
import { searchReportText, type ReportTextMatch } from "./report-text-search.js";
import { reportSearchSection } from "./report-search-location.js";
import { revealPagedSortableTableText } from "./paged-sortable-tables.js";

export class ReportSearch {
  private controller: AbortController | null = null;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private matches: ReportTextMatch[] = [];
  private displayed = 0;
  private query = "";
  private readonly panel: HTMLElement;
  constructor(
    root: Document,
    private readonly getResult: () => ParseForUiResult | null,
    private readonly getSections: () => readonly WorkspaceSection[],
    private readonly reveal: (key: string, value: string) => void
  ) {
    this.panel = root.getElementById("reportSearchResults")!;
  }
  reset(): void {
    this.controller?.abort();
    clearTimeout(this.timer);
    this.matches = [];
    this.query = "";
    this.panel.replaceChildren();
  }
  update(query: string): void {
    this.reset();
    this.query = query.trim();
    if (!this.query) return;
    this.panel.textContent = "Searching parsed text…";
    // Debounce typing; search walks decoded data, never the file's raw bytes.
    this.timer = setTimeout(() => { void this.search(); }, 180);
  }
  private async search(): Promise<void> {
    const result = this.getResult();
    if (!result) {
      this.panel.textContent = "Parsed text is not available yet.";
      return;
    }
    const controller = new AbortController();
    this.controller = controller;
    try {
      const matches = await searchReportText(result.parsed, this.query, controller.signal);
      if (controller.signal.aborted) return;
      this.matches = matches;
      this.displayed = 0;
      this.render();
    } catch (error) {
      if (!controller.signal.aborted) this.panel.textContent = `Search failed: ${String(error)}`;
    }
  }
  private render(): void {
    this.panel.replaceChildren();
    const status = document.createElement("p");
    status.className = "smallNote";
    status.setAttribute("role", "status");
    status.textContent = `${this.matches.length} text matches in parsed data. ` +
      "Includes unloaded sections and all table pages; raw bytes are not scanned.";
    this.panel.append(status);
    const sectionMatches = this.getSections().filter(section =>
      section.title.toLowerCase().includes(this.query.toLowerCase()));
    for (const section of sectionMatches) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "reportSearchSection overviewLink";
      button.textContent = section.title;
      button.addEventListener("click", () => this.reveal(section.key, ""));
      this.panel.append(button);
    }
    const list = document.createElement("ol");
    list.className = "reportSearchList";
    this.panel.append(list);
    this.appendPage(list);
  }
  private appendPage(list: HTMLOListElement): void {
    this.panel.querySelector(".reportSearchMore")?.remove();
    // Results are paged in the UI; the search itself visits every decoded string.
    const end = Math.min(this.displayed + 50, this.matches.length);
    for (let index = this.displayed; index < end; index++) list.append(this.renderMatch(this.matches[index]!));
    this.displayed = end;
    if (end === this.matches.length) return;
    const more = document.createElement("button");
    more.type = "button";
    more.className = "secondaryButton reportSearchMore";
    more.textContent = `Show next ${Math.min(50, this.matches.length - end)}`;
    more.addEventListener("click", () => this.appendPage(list));
    this.panel.append(more);
  }
  private renderMatch(match: ReportTextMatch): HTMLLIElement {
    const item = document.createElement("li");
    const sectionKey = reportSearchSection(this.getResult()?.analyzer ?? null, match, this.getSections());
    const context = document.createElement("div");
    context.className = "reportSearchContext";
    context.textContent = match.path.map(part => typeof part === "number" ? `[${part}]` : part).join(" / ");
    const text = document.createElement("pre");
    const offset = Math.max(0, match.value.toLowerCase().indexOf(this.query.toLowerCase()) - 60);
    text.textContent = (offset ? "…" : "") + match.value.slice(offset, offset + 360) +
      (offset + 360 < match.value.length ? "…" : "");
    item.append(context, text);
    if (sectionKey) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "overviewLink";
      button.textContent = `Open ${this.getSections().find(section => section.key === sectionKey)?.title}`;
      button.addEventListener("click", () => this.reveal(sectionKey, match.value));
      item.append(button);
    }
    return item;
  }
}

export const revealReportText = (section: HTMLElement, value: string): void => {
  if (!value) return;
  revealPagedSortableTableText(section, value);
  const walker = document.createTreeWalker(section, NodeFilter.SHOW_TEXT);
  let node: Node | null;
  while ((node = walker.nextNode())) {
    if (!node.textContent?.includes(value) || !node.parentElement) continue;
    const target = node.parentElement.closest<HTMLElement>("td, dd, pre, code, li") ?? node.parentElement;
    for (let parent = target.parentElement; parent && section.contains(parent); parent = parent.parentElement) {
      if (parent instanceof HTMLDetailsElement) parent.open = true;
    }
    section.querySelector(".reportSearchTarget")?.classList.remove("reportSearchTarget");
    target.classList.add("reportSearchTarget");
    target.scrollIntoView({ block: "center", inline: "nearest" });
    return;
  }
};

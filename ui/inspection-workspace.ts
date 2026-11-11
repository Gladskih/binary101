import { formatHumanSize } from "../binary-utils.js";
import { collectWorkspaceSections, type WorkspaceSection } from "./workspace-sections.js";
import {
  filterWorkspaceNavigation,
  renderWorkspaceNavigation,
  renderWorkspaceSelect
} from "./workspace-navigation.js";
import type { InspectionContext } from "./inspection-context.js";
import { createWorkspaceReflow } from "./workspace-reflow.js";

interface WorkspaceScrollPosition {
  page: number;
  top: number;
  left: number;
}

class InspectionWorkspace {
  private sections: WorkspaceSection[] = [];
  private selected = "overview";
  private analysisComplete = false;
  private readonly scrollPositions = new Map<string, WorkspaceScrollPosition>();
  private pendingScroll: string | null = null;
  private readonly viewport: HTMLElement;
  private readonly analysis: HTMLElement;
  private readonly navigation: HTMLElement;
  private readonly filter: HTMLInputElement;
  private readonly mobileView: HTMLSelectElement;
  private readonly appTitle: string;
  private readonly reflow: ReturnType<typeof createWorkspaceReflow>;
  constructor(private readonly root: Document) {
    this.appTitle = root.title;
    this.analysis = this.element("analysisValue");
    this.navigation = this.element("workspaceNavigation");
    this.filter = this.element("workspaceFilter") as HTMLInputElement;
    this.mobileView = this.element("workspaceMobileView") as HTMLSelectElement;
    this.viewport = this.element("workspaceViewport");
    this.reflow = createWorkspaceReflow(this.viewport);
    this.attachEvents();
    this.observeChanges();
  }
  private element(id: string): HTMLElement {
    return this.root.getElementById(id)!;
  }
  begin(file: File, context: InspectionContext): void {
    this.selected = "overview";
    this.analysisComplete = false;
    this.scrollPositions.clear();
    this.pendingScroll = null;
    this.reflow.reset();
    this.filter.value = "";
    this.element("fileBackButton").hidden = context.source !== "navigation";
    this.element("workspaceFileSize").textContent = formatHumanSize(file.size);
    this.viewport.scrollTo({ top: 0, left: 0, behavior: "instant" });
    window.scrollTo({ top: 0, behavior: "instant" });
    this.refresh();
  }
  revealFile(): void {
    this.element("fileNameDetail").focus({ preventScroll: true });
  }
  completeAnalysis(): void {
    this.analysisComplete = true;
    this.refresh();
  }
  refresh(): void {
    this.sections = collectWorkspaceSections(this.analysis);
    renderWorkspaceNavigation(this.navigation, this.sections);
    renderWorkspaceSelect(this.mobileView, this.sections);
    this.element("workspaceUnsupported").hidden = !this.analysisComplete || this.sections.length > 0;
    this.updateNotices();
    this.select(this.sections.some(section => section.key === this.selected) ? this.selected :
      this.selected === "hashes" ? "hashes" : "overview");
    this.filterNavigation();
    this.syncLayout();
  }
  private select(key: string): void {
    const section = this.sections.find(item => item.key === key);
    if (!section && key !== "overview" && key !== "hashes") return;
    if (this.selected !== key) {
      this.scrollPositions.set(this.selected, {
        page: window.scrollY, top: this.viewport.scrollTop, left: this.viewport.scrollLeft
      });
      this.reflow.reset();
    }
    this.selected = key;
    this.element("workspaceOverview").hidden = key !== "overview";
    const hashes = this.element("hashDetails") as HTMLDetailsElement;
    hashes.hidden = key !== "hashes";
    hashes.open = key === "hashes";
    this.analysis.hidden = !section;
    for (const item of this.sections) {
      item.element.hidden = item !== section;
      if (item.details) item.details.open = item === section;
    }
    this.updateHeading(section);
    this.mobileView.value = key;
    this.navigation.querySelectorAll<HTMLElement>("[data-workspace-target]").forEach(button => {
      if (button.dataset["workspaceTarget"] === key) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    });
  }
  private updateHeading(section: WorkspaceSection | undefined): void {
    this.element("workspaceTitle").textContent = section?.title ??
      (this.selected === "hashes" ? "File hashes" : "Overview");
    this.element("workspaceDescription").textContent = section?.description ?? "";
    const heading = this.element("workspaceHeading");
    if (section?.origin === "supplemental" || this.selected === "hashes") {
      heading.dataset["analysisOrigin"] = "supplemental";
      heading.title = "Supplemental analysis";
    } else {
      delete heading.dataset["analysisOrigin"];
      heading.removeAttribute("title");
    }
  }
  private updateNotices(): void {
    const notice = this.element("workspaceNotice");
    const section = this.sections.find(item => /^(sanity|issues|notices)$/i.test(item.title));
    notice.replaceChildren();
    notice.hidden = !section;
    if (!section) return;
    const text = this.root.createElement("span");
    text.textContent = "This file has analysis notices to review.";
    const button = this.root.createElement("button");
    button.type = "button";
    button.dataset["workspaceTarget"] = section.key;
    button.textContent = "Review notices →";
    notice.append(text, button);
  }
  private activate(key: string): boolean {
    if (key === this.selected) return false;
    this.pendingScroll = key;
    this.select(key);
    if (!this.sections.find(section => section.key === key)?.details) this.restoreScroll(key);
    return true;
  }
  private restoreScroll(key: string): void {
    requestAnimationFrame(() => {
      if (this.selected !== key || this.pendingScroll !== key) return;
      this.pendingScroll = null;
      const position = this.scrollPositions.get(key);
      this.viewport.scrollTo({ top: position?.top ?? 0, left: position?.left ?? 0,
        behavior: "instant" });
      if (getComputedStyle(this.viewport).overflowY !== "auto") {
        window.scrollTo({ top: position?.page ?? 0, behavior: "instant" });
      }
      this.reflow.capture();
    });
  }
  private filterNavigation(): void {
    this.element("workspaceNavigationEmpty").hidden =
      filterWorkspaceNavigation(this.navigation, this.filter.value) > 0;
  }
  private syncLayout(): void {
    const fileVisible = !this.element("fileInfoCard").hidden;
    const directoryVisible = !this.element("directoryInfoCard").hidden;
    this.root.body.classList.toggle("hasInspection", fileVisible || directoryVisible);
    const name = fileVisible ? this.element("fileNameDetail").textContent :
      directoryVisible ? this.element("directoryName").textContent : null;
    const title = name ? `${name} — ${this.appTitle}` : this.appTitle;
    if (this.root.title !== title) this.root.title = title;
  }
  private followToggle(event: Event): void {
    const section = this.sections.find(item => item.details === event.target);
    if (!section?.details?.open) return;
    if (this.selected !== section.key) this.select(section.key);
    // Lazy renderers mount in the same toggle event; restore after they finish.
    if (this.pendingScroll === section.key) this.restoreScroll(section.key);
  }
  private followLink(event: Event): void {
    const link = event.target instanceof Element ? event.target.closest("a") : null;
    const href = link?.getAttribute("href");
    if (!href?.startsWith("#")) return;
    const target = this.root.getElementById(href.slice(1));
    const section = this.sections.find(item => target && item.element.contains(target));
    if (section && this.selected !== section.key) {
      this.select(section.key);
      this.viewport.focus({ preventScroll: true });
    }
  }
  private attachEvents(): void {
    this.element("fileInfoCard").addEventListener("click", event => {
      const button = event.target instanceof Element ?
        event.target.closest<HTMLElement>("[data-workspace-target]") : null;
      if (!button || !this.activate(button.dataset["workspaceTarget"] ?? "overview")) return;
      if (event.detail === 0 || this.viewport.contains(button)) {
        this.viewport.focus({ preventScroll: true });
      }
    });
    this.mobileView.addEventListener("change", () => this.activate(this.mobileView.value));
    this.filter.addEventListener("input", () => this.filterNavigation());
    this.analysis.addEventListener("toggle", event => this.followToggle(event), true);
    this.analysis.addEventListener("click", event => this.followLink(event), true);
    this.element("fileOpenButton").addEventListener("click", () => {
      (this.element("fileInput") as HTMLInputElement).click();
    });
    this.element("fileBackButton").addEventListener("click", () => window.history.back());
  }
  private observeChanges(): void {
    new MutationObserver(records => {
      if (records.some(record => record.target === this.analysis)) this.refresh();
    }).observe(this.analysis, { childList: true });
    const observer = new MutationObserver(() => this.syncLayout());
    for (const id of ["fileInfoCard", "directoryInfoCard"]) {
      observer.observe(this.element(id), { attributes: true, attributeFilter: ["hidden"] });
    }
    for (const id of ["fileNameDetail", "directoryName"]) {
      observer.observe(this.element(id), { childList: true });
    }
  }
}

export const createInspectionWorkspace = (root: Document) => new InspectionWorkspace(root);

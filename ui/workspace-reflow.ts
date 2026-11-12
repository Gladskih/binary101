interface ReadingPosition {
  path: number[];
  offset: number;
  left: number;
  atStart: boolean;
}

class WorkspaceReflow {
  private position: ReadingPosition | null = null;
  private paneLayout: boolean;
  private restoring = false;
  private revision = 0;
  constructor(private readonly viewport: HTMLElement) {
    this.paneLayout = this.usesPane();
    viewport.addEventListener("scroll", () => this.capture(), { passive: true });
    window.addEventListener("scroll", () => this.capture(), { passive: true });
    window.addEventListener("resize", () => this.reflow());
  }
  reset(): void {
    this.position = null;
    this.restoring = false;
    this.revision += 1;
    this.paneLayout = this.usesPane();
  }
  usesPane(): boolean {
    // Horizontal scrolling also computes overflow-y:auto in page layouts.
    return getComputedStyle(this.viewport).getPropertyValue("--workspace-scroll-mode").trim() === "pane";
  }
  private visibleTop(): number {
    return Math.max(0, this.viewport.getBoundingClientRect().top);
  }
  private readingTop(): number {
    let top = this.visibleTop();
    this.viewport.querySelectorAll<HTMLElement>("thead th, .pagedSortableTableToolbar")
      .forEach(element => {
        const bounds = element.getBoundingClientRect();
        if (bounds.top <= top + 1 && bounds.bottom > top) top = bounds.bottom;
      });
    return top;
  }
  private readingElement(top: number): HTMLElement | null {
    const bounds = this.viewport.getBoundingClientRect();
    const target = this.viewport.ownerDocument.elementFromPoint(
      bounds.left + Math.min(bounds.width / 2, bounds.width - 24),
      // Sample below sticky controls and away from the scroll area's edges.
      Math.min(top + 12, bounds.bottom - 12)
    );
    const candidate = target?.closest("tr, li, p, summary, dt, dd, img, pre") ?? target;
    return candidate instanceof HTMLElement && candidate !== this.viewport &&
      this.viewport.contains(candidate) ? candidate : null;
  }
  capture(): void {
    if (this.restoring || this.usesPane() !== this.paneLayout ||
      !this.viewport.getClientRects().length) return;
    const top = this.readingTop();
    const target = this.readingElement(top);
    if (!target) return;
    const path: number[] = [];
    for (let current: Element = target; current !== this.viewport;) {
      const parent = current.parentElement;
      if (!parent) return;
      path.unshift(Array.from(parent.children).indexOf(current));
      current = parent;
    }
    this.position = {
      path,
      offset: target.getBoundingClientRect().top - top,
      atStart: this.paneLayout ? this.viewport.scrollTop === 0 : window.scrollY === 0,
      left: this.paneLayout ? this.viewport.scrollLeft :
        target.closest<HTMLElement>(".tableWrap")?.scrollLeft ?? 0
    };
  }
  private findAnchor(path: number[]): Element | null {
    let target: Element | null = this.viewport;
    for (const index of path) target = target?.children.item(index) ?? null;
    return target;
  }
  private restore(position: ReadingPosition): void {
    const target = this.findAnchor(position.path);
    if (!target) return;
    const edge = this.paneLayout ? this.visibleTop() + this.tableHeaderHeight(target) : 0;
    const distance = target.getBoundingClientRect().top - edge - position.offset;
    if (this.paneLayout) {
      this.viewport.scrollTo({ top: position.atStart ? 0 : this.viewport.scrollTop + distance,
        left: position.left, behavior: "instant" });
    } else {
      window.scrollTo({ top: position.atStart ? 0 : window.scrollY + distance, behavior: "instant" });
      const table = target.closest<HTMLElement>(".tableWrap");
      if (table) table.scrollLeft = position.left;
    }
  }
  private tableHeaderHeight(target: Element): number {
    let height = 0;
    for (let table = target.closest("table"); table;) {
      const header = table.tHead;
      const cell = header?.querySelector("th");
      if (header && cell) height = Math.max(height, header.getBoundingClientRect().height +
        (Number.parseFloat(getComputedStyle(cell).top) || 0));
      table = table.parentElement?.closest("table") ?? null;
    }
    return height;
  }
  private reflow(): void {
    if (this.usesPane() === this.paneLayout) return;
    this.paneLayout = this.usesPane();
    if (!this.position || !this.viewport.getClientRects().length) return;
    const position = this.position;
    const revision = ++this.revision;
    this.restoring = true;
    requestAnimationFrame(() => {
      if (revision !== this.revision) return;
      this.restore(position);
      requestAnimationFrame(() => {
        if (revision !== this.revision) return;
        this.restoring = false;
        this.capture();
      });
    });
  }
}

export const createWorkspaceReflow = (viewport: HTMLElement) => new WorkspaceReflow(viewport);

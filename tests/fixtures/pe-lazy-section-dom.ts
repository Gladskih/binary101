import { PE_LAZY_SECTION_KEYS, type PeLazySectionKey } from
  "../../renderers/pe/lazy-section-shells.js";

type ToggleHandler = (event: Event) => void;
type GlobalDom = { document?: unknown; Element?: unknown; HTMLElement?: unknown };

class FakeChildren extends Array<FakeElement> {
  item(index: number): FakeElement | null { return this[index] ?? null; }
}

class FakeClassList {
  private readonly values = new Set<string>();

  add(value: string): void { this.values.add(value); }

  contains(value: string): boolean { return this.values.has(value); }
}

export class FakeElement {
  readonly attributes = new Map<string, string>();
  readonly children = new FakeChildren();
  readonly classList = new FakeClassList();
  readonly dataset: Record<string, string> = {};
  filterControl: FakeElement | null = null;
  id = "";
  nestedDetails: FakeElement | null = null;
  open = false;
  pagedRoot: FakeElement | null = null;
  parentElement: FakeElement | null = null;
  selectedRow: FakeElement | null = null;
  textContent: string | null = null;
  value?: string;
  private html = "";
  private readonly queries = new Map<string, FakeElement>();

  constructor(readonly tagName: string) {}

  get innerHTML(): string { return this.html; }

  set innerHTML(value: string) { this.html = value; }

  get outerHTML(): string { return this.html; }

  set outerHTML(value: string) { this.html = value; }

  addEventListener(_type?: string, _handler?: unknown): void {}

  append(...children: FakeElement[]): void {
    children.forEach(child => {
      child.parentElement = this;
      this.children.push(child);
    });
  }

  closest(selector: string): FakeElement | null {
    let current: FakeElement | null = this;
    while (current) {
      if (selector === "#analysisValue" && current.id === "analysisValue") return current;
      if (selector === "[data-pe-lazy-section]" && current.dataset["peLazySection"]) {
        return current;
      }
      if (selector === "details" && current.tagName === "DETAILS") return current;
      current = current.parentElement;
    }
    return null;
  }

  getAttribute(name: string): string | null { return this.attributes.get(name) ?? null; }

  querySelector(selector: string): FakeElement | null { return this.queries.get(selector) ?? null; }

  querySelectorAll(selector: string): FakeElement[] {
    if (selector === "details") return this.nestedDetails ? [this.nestedDetails] : [];
    if (selector === "[data-paged-sortable-table-root]") {
      return this.pagedRoot ? [this.pagedRoot] : [];
    }
    if (selector.includes("data-pe-lazy-state-control")) {
      return this.filterControl ? [this.filterControl] : [];
    }
    if (selector.includes("aria-selected")) return this.selectedRow ? [this.selectedRow] : [];
    return [];
  }

  removeAttribute(name: string): void { this.attributes.delete(name); }

  setAttribute(name: string, value: string): void { this.attributes.set(name, value); }

  setQuery(selector: string, element: FakeElement): void { this.queries.set(selector, element); }
}

class FakeLazyBody extends FakeElement {
  override get innerHTML(): string { return super.innerHTML; }

  override set innerHTML(value: string) {
    super.innerHTML = value;
    this.children.length = 0;
    this.filterControl = null;
    this.nestedDetails = null;
    this.pagedRoot = null;
    this.selectedRow = null;
    if (!value) return;
    this.filterControl = new FakeElement("INPUT");
    this.filterControl.dataset["peLazyStateControl"] = "true";
    this.filterControl.value = "";
    this.selectedRow = new FakeElement("TR");
    this.nestedDetails = createNestedDetails("Manifest branch");
    this.pagedRoot = createPagedRoot();
    this.append(this.filterControl, this.selectedRow, this.nestedDetails, this.pagedRoot);
  }
}

export class FakeRoot extends FakeElement {
  toggleHandler: ToggleHandler | null = null;

  constructor(private readonly section: FakeElement) {
    super("DIV");
    this.id = "analysisValue";
    this.append(section);
  }

  override addEventListener(type: string, handler: ToggleHandler): void {
    if (type === "toggle") this.toggleHandler = handler;
  }

  override querySelectorAll(selector: string): FakeElement[] {
    return selector === "[data-pe-lazy-section]" ? [this.section] : [];
  }
}

class FakeTemplate {
  readonly content = {
    querySelectorAll: (selector: string): FakeElement[] =>
      selector === ".peSection" && this.section ? [this.section] : []
  };
  private section: FakeElement | null = null;

  set innerHTML(value: string) {
    this.section = value ? createExtractedSection("Resources", "mounted resources body") : null;
  }
}

class FakeDocument {
  constructor(private readonly section: FakeElement) {}

  createElement(tagName: string): FakeTemplate | FakeElement {
    return tagName === "template" ? new FakeTemplate() : new FakeElement(tagName.toUpperCase());
  }

  querySelector(selector: string): FakeElement | null {
    return selector === `[data-pe-lazy-section="${PE_LAZY_SECTION_KEYS.resources}"]`
      ? this.section
      : null;
  }
}

const createNestedDetails = (label: string): FakeElement => {
  const details = new FakeElement("DETAILS");
  const summary = new FakeElement("SUMMARY");
  summary.textContent = label;
  details.append(summary);
  return details;
};

const createPagedRoot = (): FakeElement => {
  const root = new FakeElement("DIV");
  const tableBody = new FakeElement("TBODY");
  const toolbar = new FakeElement("DIV");
  root.dataset["pagedSortableTableId"] = "pe-resource-detail-0";
  root.dataset["pagedSortablePageIndex"] = "0";
  root.dataset["pagedSortableSortColumn"] = "";
  root.dataset["pagedSortableSortDirection"] = "";
  root.setQuery("[data-paged-sortable-table-body]", tableBody);
  root.setQuery(".pagedSortableTableToolbar", toolbar);
  return root;
};

const createExtractedSection = (title: string, bodyHtml: string): FakeElement => {
  const section = new FakeElement("SECTION");
  const titleElement = new FakeElement("B");
  const body = new FakeElement("DIV");
  titleElement.textContent = title;
  body.innerHTML = bodyHtml;
  section.setQuery(":scope > details > summary b", titleElement);
  section.setQuery(".peSectionBody", body);
  return section;
};

export const createLazySection = (
  key: PeLazySectionKey
): { body: FakeLazyBody; details: FakeElement; section: FakeElement } => {
  const section = new FakeElement("SECTION");
  const details = new FakeElement("DETAILS");
  const summary = new FakeElement("SUMMARY");
  const title = new FakeElement("B");
  const body = new FakeLazyBody("DIV");
  section.dataset["peLazySection"] = key;
  title.textContent = "Resources";
  body.dataset["peLazySectionBody"] = "true";
  summary.append(title);
  details.append(summary, body);
  section.append(details);
  section.setQuery(":scope > details > summary b", title);
  section.setQuery("[data-pe-lazy-section-body]", body);
  return { body, details, section };
};

export const installDom = (section: FakeElement): { restore: () => void } => {
  const globals = globalThis as GlobalDom;
  const originalDocument = globals.document;
  const originalElement = globals.Element;
  const originalHTMLElement = globals.HTMLElement;
  globals.document = new FakeDocument(section);
  globals.Element = FakeElement;
  globals.HTMLElement = FakeElement;
  return {
    restore: () => {
      globals.document = originalDocument;
      globals.Element = originalElement;
      globals.HTMLElement = originalHTMLElement;
    }
  };
};

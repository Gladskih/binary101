"use strict";

import assert from "node:assert/strict";

export type AnchorStub = {
  href: string;
  download: string;
  clicked: number;
  click: () => void;
};

export type Iso9660ActionsDomStubs = {
  getButton: () => HTMLButtonElement;
  getChild: () => Element;
  getDirButton: () => HTMLButtonElement;
  getDirChild: () => Element;
  getDirContainer: () => Element;
  getDirRow: () => { hidden: boolean };
  getAnchor: () => AnchorStub | null;
  getCreatedBlob: () => Blob | null;
  getMessages: () => Array<string | null | undefined>;
  restore: () => void;
};

export const installIso9660ActionsDomStubs = (): Iso9660ActionsDomStubs => {
  const globals = globalThis as unknown as Record<string, unknown>;

  const hadGlobals = {
    Element: Object.prototype.hasOwnProperty.call(globals, "Element"),
    HTMLButtonElement: Object.prototype.hasOwnProperty.call(globals, "HTMLButtonElement"),
    document: Object.prototype.hasOwnProperty.call(globals, "document")
  };

  const originals = {
    Element: globals["Element"],
    HTMLButtonElement: globals["HTMLButtonElement"],
    document: globals["document"],
    createObjectURL: URL.createObjectURL,
    revokeObjectURL: URL.revokeObjectURL
  };

  class FakeElement {
    readonly tagName: string;
    readonly parent: FakeElement | null;
    readonly classes: Set<string>;

    constructor(tagName: string, parent: FakeElement | null = null) {
      this.tagName = tagName.toLowerCase();
      this.parent = parent;
      this.classes = new Set();
    }

    addClass(name: string): void {
      this.classes.add(name);
    }

    closest(selector: string): FakeElement | null {
      let wantedTag = "";
      let wantedClass: string | null = null;
      if (selector === "button.isoExtractButton") {
        wantedTag = "button";
        wantedClass = "isoExtractButton";
      } else if (selector === "button.isoDirToggleButton") {
        wantedTag = "button";
        wantedClass = "isoDirToggleButton";
      } else if (selector === "tr") {
        wantedTag = "tr";
        wantedClass = null;
      } else {
        return null;
      }
      let current: FakeElement | null = this;
      while (current) {
        if (
          current.tagName === wantedTag &&
          (wantedClass == null || current.classes.has(wantedClass))
        ) {
          return current;
        }
        current = current.parent;
      }
      return null;
    }
  }

  class FakeButtonElement extends FakeElement {
    disabled = false;
    textContent: string | null = "Download";
    readonly attributes = new Map<string, string>();

    constructor(parent: FakeElement | null = null) {
      super("button", parent);
    }

    getAttribute(name: string): string | null {
      return this.attributes.get(name) ?? null;
    }

    setAttribute(name: string, value: string): void {
      this.attributes.set(name, value);
    }
  }

  globals["Element"] = FakeElement;
  globals["HTMLButtonElement"] = FakeButtonElement;

  class FakeRowElement extends FakeElement {
    hidden = true;

    constructor() {
      super("tr", null);
    }
  }

  class FakeHtmlElement extends FakeElement {
    innerHTML = "";
    readonly attributes = new Map<string, string>();

    getAttribute(name: string): string | null {
      return this.attributes.get(name) ?? null;
    }

    setAttribute(name: string, value: string): void {
      this.attributes.set(name, value);
    }
  }

  let anchor: AnchorStub | null = null;
  let createdBlob: Blob | null = null;

  const body = {
    appendCalls: 0,
    removeCalls: 0,
    lastNode: null as unknown,
    appendChild(node: unknown) {
      this.appendCalls += 1;
      this.lastNode = node;
      return node;
    },
    removeChild(node: unknown) {
      this.removeCalls += 1;
      this.lastNode = node;
      return node;
    }
  };

  const dirRow = new FakeRowElement();
  const dirContainer = new FakeHtmlElement("div", dirRow);
  const dirContainerId = "isoDir-0";

  globals["document"] = {
    body,
    createElement(tagName: string) {
      assert.equal(tagName, "a");
      anchor = {
        href: "",
        download: "",
        clicked: 0,
        click() {
          this.clicked += 1;
        }
      };
      return anchor;
    },
    getElementById(id: string) {
      return id === dirContainerId ? dirContainer : null;
    }
  };

  URL.createObjectURL = (blob: Blob): string => {
    createdBlob = blob;
    return "blob:unit-test";
  };
  URL.revokeObjectURL = () => {};

  const button = new FakeButtonElement();
  button.addClass("isoExtractButton");
  button.setAttribute("data-iso-action", "extract");
  button.setAttribute("data-iso-entry", "0");

  const child = new FakeElement("span", button);

  const dirButton = new FakeButtonElement();
  dirButton.addClass("isoDirToggleButton");
  dirButton.setAttribute("data-iso-action", "toggle-dir");
  dirButton.setAttribute("data-iso-lba", "0");
  dirButton.setAttribute("data-iso-size", "0");
  dirButton.setAttribute("data-iso-path", "/");
  dirButton.setAttribute("data-iso-depth", "0");
  dirButton.setAttribute("data-iso-target", dirContainerId);
  dirButton.textContent = "Expand";

  const dirChild = new FakeElement("span", dirButton);

  const messages: Array<string | null | undefined> = [];

  return {
    getAnchor: () => anchor,
    getButton: () => button as unknown as HTMLButtonElement,
    getChild: () => child as unknown as Element,
    getDirButton: () => dirButton as unknown as HTMLButtonElement,
    getDirChild: () => dirChild as unknown as Element,
    getDirContainer: () => dirContainer as unknown as Element,
    getDirRow: () => dirRow as unknown as { hidden: boolean },
    getCreatedBlob: () => createdBlob,
    getMessages: () => messages,
    restore: () => {
      if (hadGlobals.Element) {
        globals["Element"] = originals.Element;
      } else {
        Reflect.deleteProperty(globals, "Element");
      }
      if (hadGlobals.HTMLButtonElement) {
        globals["HTMLButtonElement"] = originals.HTMLButtonElement;
      } else {
        Reflect.deleteProperty(globals, "HTMLButtonElement");
      }
      if (hadGlobals.document) {
        globals["document"] = originals.document;
      } else {
        Reflect.deleteProperty(globals, "document");
      }
      URL.createObjectURL = originals.createObjectURL;
      URL.revokeObjectURL = originals.revokeObjectURL;
    }
  };
};

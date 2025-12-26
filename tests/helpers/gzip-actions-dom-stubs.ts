"use strict";

import assert from "node:assert/strict";

export type AnchorStub = {
  href: string;
  download: string;
  clicked: number;
  click: () => void;
};

export type GzipActionsDomStubs = {
  getButton: () => HTMLButtonElement;
  getChild: () => Element;
  getAnchor: () => AnchorStub | null;
  getCreatedBlob: () => Blob | null;
  getMessages: () => Array<string | null | undefined>;
  restore: () => void;
};

export const installGzipActionsDomStubs = (): GzipActionsDomStubs => {
  const globals = globalThis as unknown as Record<string, unknown>;

  const hadGlobals = {
    Element: Object.prototype.hasOwnProperty.call(globals, "Element"),
    HTMLButtonElement: Object.prototype.hasOwnProperty.call(globals, "HTMLButtonElement"),
    document: Object.prototype.hasOwnProperty.call(globals, "document"),
    DecompressionStream: Object.prototype.hasOwnProperty.call(globals, "DecompressionStream")
  };

  const originals = {
    Element: globals["Element"],
    HTMLButtonElement: globals["HTMLButtonElement"],
    document: globals["document"],
    DecompressionStream: globals["DecompressionStream"],
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
      if (selector !== "button.gzipDecompressButton") return null;
      let current: FakeElement | null = this;
      while (current) {
        if (current.tagName === "button" && current.classes.has("gzipDecompressButton")) {
          return current;
        }
        current = current.parent;
      }
      return null;
    }
  }

  class FakeButtonElement extends FakeElement {
    disabled = false;
    textContent: string | null = "Decompress";
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
    }
  };

  URL.createObjectURL = (blob: Blob): string => {
    createdBlob = blob;
    return "blob:unit-test";
  };
  URL.revokeObjectURL = () => {};

  const button = new FakeButtonElement();
  button.addClass("gzipDecompressButton");
  button.setAttribute("data-gzip-action", "decompress");

  const child = new FakeElement("span", button);

  const messages: Array<string | null | undefined> = [];

  return {
    getAnchor: () => anchor,
    getButton: () => button as unknown as HTMLButtonElement,
    getChild: () => child as unknown as Element,
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
      if (hadGlobals.DecompressionStream) {
        Object.defineProperty(globals, "DecompressionStream", {
          value: originals.DecompressionStream,
          writable: true,
          configurable: true
        });
      } else {
        Reflect.deleteProperty(globals, "DecompressionStream");
      }
      URL.createObjectURL = originals.createObjectURL;
      URL.revokeObjectURL = originals.revokeObjectURL;
    }
  };
};

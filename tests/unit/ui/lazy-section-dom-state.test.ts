"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import {
  captureLazyDomState,
  restoreLazyDomState
} from "../../../ui/lazy-section-dom-state.js";

type GlobalDom = {
  HTMLElement?: unknown;
};

class FakeChildren extends Array<FakeElement> {
  item(index: number): FakeElement | null {
    return this[index] ?? null;
  }
}

class FakeClassList {
  private readonly values = new Set<string>();

  add(value: string): void {
    this.values.add(value);
  }

  contains(value: string): boolean {
    return this.values.has(value);
  }
}

class FakeElement {
  readonly attributes = new Map<string, string>();
  readonly children = new FakeChildren();
  readonly classList = new FakeClassList();
  readonly dataset: Record<string, string> = {};
  checked?: boolean;
  parentElement: FakeElement | null = null;
  selectedIndex?: number;
  value?: string;

  append(...children: FakeElement[]): void {
    children.forEach(child => {
      child.parentElement = this;
      this.children.push(child);
    });
  }

  getAttribute(name: string): string | null {
    return this.attributes.get(name) ?? null;
  }

  querySelectorAll(selector: string): FakeElement[] {
    const all = this.walk();
    if (selector.includes("data-pe-lazy-state-control")) {
      return all.filter(element => element.dataset["peLazyStateControl"] === "true");
    }
    return all.filter(element =>
      element.getAttribute("aria-selected") === "true" ||
      element.dataset["selected"] === "true" ||
      element.classList.contains("selected")
    );
  }

  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }

  private walk(): FakeElement[] {
    return this.children.flatMap(child => [child, ...child.walk()]);
  }
}

void test("lazy DOM state restores filter controls and selected row markers", () => {
  const globals = globalThis as GlobalDom;
  const originalHTMLElement = globals.HTMLElement;
  globals.HTMLElement = FakeElement;
  try {
    const root = new FakeElement();
    const toolbar = new FakeElement();
    const filter = new FakeElement();
    const row = new FakeElement();
    filter.dataset["peLazyStateControl"] = "true";
    filter.value = "manifest";
    row.setAttribute("aria-selected", "true");
    row.dataset["selected"] = "true";
    row.classList.add("selected");
    toolbar.append(filter);
    root.append(toolbar, row);

    const state = captureLazyDomState(root as unknown as HTMLElement);
    filter.value = "";
    row.attributes.clear();
    row.dataset["selected"] = "";

    restoreLazyDomState(root as unknown as HTMLElement, state);

    assert.equal(filter.value, "manifest");
    assert.equal(row.getAttribute("aria-selected"), "true");
    assert.equal(row.dataset["selected"], "true");
    assert.equal(row.classList.contains("selected"), true);
  } finally {
    globals.HTMLElement = originalHTMLElement;
  }
});

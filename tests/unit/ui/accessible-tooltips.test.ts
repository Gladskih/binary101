"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  accessibleTooltipSelector,
  addAccessibleTooltipToButton,
  updateAccessibleTooltipButton
} from "../../../ui/accessible-tooltips.js";

class FakeTooltipElement {
  attributes = new Map<string, string>();
  children: FakeTooltipElement[] = [];
  className = "";
  hidden = false;
  parentElement: FakeTooltipElement | null = null;
  title = "";
  type = "";
  listeners = new Map<string, (event: { stopPropagation: () => void }) => void>();
  style = { left: "", right: "", removeProperty: () => undefined };
  classList = {
    add: (_: string): void => undefined,
    contains: (): boolean => false,
    remove: (_: string): void => undefined,
    toggle: (_: string, __: boolean): void => undefined
  };
  ownerDocument!: FakeTooltipDocument;

  addEventListener(type: string, listener: (event: { stopPropagation: () => void }) => void): void {
    this.listeners.set(type, listener);
  }

  append(...children: FakeTooltipElement[]): void {
    children.forEach(child => { child.parentElement = this; });
    this.children.push(...children);
  }

  getBoundingClientRect(): DOMRect {
    return { bottom: 0, height: 0, left: 0, top: 0, width: 0 } as DOMRect;
  }

  replaceWith(replacement: FakeTooltipElement): void {
    assert.ok(this.parentElement);
    this.parentElement.children = [replacement];
    replacement.parentElement = this.parentElement;
    this.parentElement = null;
  }

  querySelector(): FakeTooltipElement | null { return this.children[1] ?? null; }

  setAttribute(name: string, value: string): void { this.attributes.set(name, value); }
}

class FakeTooltipDocument {
  documentElement = { clientHeight: 100, clientWidth: 100 };
  addEventListener(): void {}

  createElement(): FakeTooltipElement {
    const element = new FakeTooltipElement();
    element.ownerDocument = this;
    return element;
  }

  querySelectorAll(): FakeTooltipElement[] { return []; }
}

void test("accessible tooltips require an explicit semantic marker", () => {
  assert.equal(accessibleTooltipSelector, "[data-accessible-tooltip][title]");
});

void test("button tooltips open from the supplied button", () => {
  const document = new FakeTooltipDocument();
  const label = document.createElement();
  const button = document.createElement();
  label.append(button);

  addAccessibleTooltipToButton(button as unknown as HTMLButtonElement, "Native crypto is tried first.");

  const control = label.children[0];
  assert.ok(control);
  const popup = control.children[1];
  assert.ok(popup);
  assert.equal(button.title, "Native crypto is tried first.");
  assert.equal(button.attributes.get("aria-expanded"), "false");
  assert.equal(popup.hidden, true);
  button.listeners.get("click")?.({ stopPropagation: () => undefined });
  assert.equal(popup.hidden, false);
  assert.equal(button.attributes.get("aria-expanded"), "true");
  updateAccessibleTooltipButton(button as unknown as HTMLButtonElement, "Native crypto failed; fallback used.");
  assert.equal(button.title, "Native crypto failed; fallback used.");
  assert.equal(popup.attributes.get("aria-label"), "Native crypto failed; fallback used.");
});

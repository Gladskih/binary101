"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { handlePeEntrypointJumpClick } from "../../ui/pe-entrypoint-navigation.js";

type DomGlobals = {
  HTMLElement?: unknown;
};

class FakeClassList {
  private readonly names = new Set<string>();

  add(name: string): void {
    this.names.add(name);
  }

  remove(name: string): void {
    this.names.delete(name);
  }

  contains(name: string): boolean {
    return this.names.has(name);
  }
}

class FakeElement {
  readonly classList = new FakeClassList();
  readonly dataset: Record<string, string> = {};
  focused = false;
  scrolled = false;

  constructor(private readonly closestElement: FakeElement | null = null) {}

  get offsetWidth(): number {
    return 1;
  }

  closest(_selector: string): FakeElement | null {
    return this.closestElement ?? this;
  }

  focus(_options?: FocusOptions): void {
    this.focused = true;
  }

  scrollIntoView(_options?: ScrollIntoViewOptions): void {
    this.scrolled = true;
  }
}

class FakeRoot {
  readonly selectors: string[] = [];

  constructor(
    private readonly row: FakeElement | null,
    private readonly block: FakeElement | null
  ) {}

  querySelector(selector: string): FakeElement | null {
    this.selectors.push(selector);
    return selector.includes(".peEntrypointInstructionRow") ? this.row : this.block;
  }
}

const withFakeHTMLElement = (run: () => void): void => {
  const globals = globalThis as unknown as DomGlobals;
  const originalHTMLElement = globals.HTMLElement;
  globals.HTMLElement = FakeElement;
  try {
    run();
  } finally {
    globals.HTMLElement = originalHTMLElement;
  }
};

void test("handlePeEntrypointJumpClick focuses and flashes an instruction target", () => {
  withFakeHTMLElement(() => {
    const button = new FakeElement();
    button.dataset["peEntrypointJump"] = "4102";
    const row = new FakeElement();
    const root = new FakeRoot(row, null);

    assert.equal(
      handlePeEntrypointJumpClick(button as unknown as Element, root as unknown as ParentNode),
      true
    );
    assert.deepEqual(root.selectors, [
      '[data-pe-entrypoint-rva="4102"].peEntrypointInstructionRow'
    ]);
    assert.equal(row.focused, true);
    assert.equal(row.scrolled, true);
    assert.equal(row.classList.contains("peEntrypointTargetFlash"), true);
  });
});

void test("handlePeEntrypointJumpClick consumes unresolved jump buttons", () => {
  withFakeHTMLElement(() => {
    const button = new FakeElement();
    button.dataset["peEntrypointJump"] = "4102";
    const root = new FakeRoot(null, null);

    assert.equal(
      handlePeEntrypointJumpClick(button as unknown as Element, root as unknown as ParentNode),
      true
    );
  });
});

void test("handlePeEntrypointJumpClick falls back to a block target", () => {
  withFakeHTMLElement(() => {
    const button = new FakeElement();
    button.dataset["peEntrypointJump"] = "4102";
    const block = new FakeElement();
    const root = new FakeRoot(null, block);

    assert.equal(
      handlePeEntrypointJumpClick(button as unknown as Element, root as unknown as ParentNode),
      true
    );
    assert.deepEqual(root.selectors, [
      '[data-pe-entrypoint-rva="4102"].peEntrypointInstructionRow',
      '[data-pe-entrypoint-rva="4102"].peEntrypointBlock'
    ]);
    assert.equal(block.focused, true);
    assert.equal(block.scrolled, true);
    assert.equal(block.classList.contains("peEntrypointTargetFlash"), true);
  });
});

void test("handlePeEntrypointJumpClick ignores unrelated clicks", () => {
  withFakeHTMLElement(() => {
    const clicked = new FakeElement(null);
    const root = new FakeRoot(null, null);
    clicked.closest = () => null;

    assert.equal(
      handlePeEntrypointJumpClick(clicked as unknown as Element, root as unknown as ParentNode),
      false
    );
  });
});

"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../../analyzers/index.js";
import type { CoffObjectParseResult } from "../../../analyzers/coff/types.js";
import { createSectionEntropyClickHandler } from "../../../ui/section-entropy-controls.js";
import { MockFile } from "../../helpers/mock-file.js";

class FakeElement {
  textContent: string | null = null;
  className = "";
  disabled = false;
  readonly attributes = new Map<string, string>();
  constructor(
    private readonly entropyRoot: FakeElement | null = null,
    private readonly tableCell: FakeElement | null = null
  ) {}
  closest(selector: string): FakeElement | null {
    if (selector === "[data-section-entropy-action]") return this;
    if (selector === "[data-section-entropy-root]") return this.entropyRoot;
    if (selector === "td") return this.tableCell;
    return null;
  }
  getAttribute(name: string): string | null {
    return this.attributes.get(name) ?? null;
  }
  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }
  querySelectorAll(_selector: string): FakeElement[] {
    return [];
  }
  querySelector(_selector: string): FakeElement | null {
    return null;
  }
}

const createCoffResult = (): Extract<ParseForUiResult, { analyzer: "coff" }> => ({
  analyzer: "coff",
  parsed: {
    signature: "COFF",
    header: {} as CoffObjectParseResult["header"],
    sections: [
      {
        name: { kind: "inline", value: ".text" },
        virtualSize: 4,
        virtualAddress: 0,
        sizeOfRawData: 4,
        pointerToRawData: 0,
        characteristics: 0
      },
      {
        name: { kind: "inline", value: ".data" },
        virtualSize: 4,
        virtualAddress: 0,
        sizeOfRawData: 4,
        pointerToRawData: 4,
        characteristics: 0
      }
    ]
  }
});

void test("section entropy handler calculates and updates all rendered section values", async () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const originalElement = globals["Element"];
  const cells = [new FakeElement(), new FakeElement()];
  const values = cells.map((cell, index) => {
    const value = new FakeElement(null, cell);
    value.attributes.set("data-section-entropy-index", String(index));
    return value;
  });
  const status = new FakeElement();
  const root = new FakeElement();
  root.querySelectorAll = selector =>
    selector === "[data-section-entropy-index]" ? values : [];
  root.querySelector = selector =>
    selector === "[data-section-entropy-status]" ? status : null;
  const button = new FakeElement(root);
  button.textContent = "Calculate entropy";
  const parseResult = createCoffResult();
  const file = new MockFile(Uint8Array.of(0, 0, 0, 0, 0, 0, 0xff, 0xff));
  const messages: Array<string | null | undefined> = [];
  globals["Element"] = FakeElement;
  try {
    const handler = createSectionEntropyClickHandler({
      getFile: () => file,
      getParseResult: () => parseResult,
      setStatusMessage: message => messages.push(message)
    });

    await handler({ target: button } as unknown as Event);

    assert.deepEqual(parseResult.parsed.sections.map(section => section.entropy), [0, 1]);
    assert.deepEqual(values.map(value => value.textContent), ["0.00", "1.00"]);
    assert.deepEqual(values.map(value => value.className), ["", ""]);
    assert.deepEqual(cells.map(cell => cell.getAttribute("data-sort-value")), ["0", "1"]);
    assert.equal(button.textContent, "Recalculate entropy for all sections");
    assert.equal(button.disabled, false);
    assert.equal(status.textContent, "Calculated for 2 of 2 sections.");
    assert.deepEqual(messages, ["Calculating section entropy...", null]);
  } finally {
    globals["Element"] = originalElement;
  }
});

void test("section entropy handler marks incomplete raw ranges unavailable", async () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const originalElement = globals["Element"];
  const cell = new FakeElement();
  const value = new FakeElement(null, cell);
  value.attributes.set("data-section-entropy-index", "1");
  const status = new FakeElement();
  const root = new FakeElement();
  root.querySelectorAll = selector =>
    selector === "[data-section-entropy-index]" ? [value] : [];
  root.querySelector = selector =>
    selector === "[data-section-entropy-status]" ? status : null;
  const button = new FakeElement(root);
  const parseResult = createCoffResult();
  parseResult.parsed.sections[1]!.sizeOfRawData = 5;
  const file = new MockFile(new Uint8Array(8));
  globals["Element"] = FakeElement;
  try {
    const handler = createSectionEntropyClickHandler({
      getFile: () => file,
      getParseResult: () => parseResult,
      setStatusMessage: () => {}
    });

    await handler({ target: button } as unknown as Event);

    assert.equal(parseResult.parsed.sections[1]!.entropy, null);
    assert.equal(value.textContent, "Unavailable");
    assert.equal(value.className, "dim");
    assert.equal(cell.getAttribute("data-sort-value"), "");
    assert.equal(status.textContent, "Calculated for 1 of 2 sections; 1 raw range unavailable.");
  } finally {
    globals["Element"] = originalElement;
  }
});

void test("section entropy handler reports missing inputs", async () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const originalElement = globals["Element"];
  const button = new FakeElement(new FakeElement());
  const messages: Array<string | null | undefined> = [];
  globals["Element"] = FakeElement;
  try {
    const handler = createSectionEntropyClickHandler({
      getFile: () => null,
      getParseResult: createCoffResult,
      setStatusMessage: message => messages.push(message)
    });

    await handler({ target: button } as unknown as Event);

    assert.deepEqual(messages, ["Section entropy is not available."]);
  } finally {
    globals["Element"] = originalElement;
  }
});

void test("section entropy handler surfaces stream failures and enables retry", async () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const originalElement = globals["Element"];
  const status = new FakeElement();
  const root = new FakeElement();
  root.querySelector = selector =>
    selector === "[data-section-entropy-status]" ? status : null;
  const button = new FakeElement(root);
  const parseResult = createCoffResult();
  const failingFile = {
    size: 8,
    slice: () => ({
      stream: () => new ReadableStream<Uint8Array>({
        start: controller => controller.error(new Error("read failed"))
      })
    })
  } as unknown as File;
  const messages: Array<string | null | undefined> = [];
  globals["Element"] = FakeElement;
  try {
    const handler = createSectionEntropyClickHandler({
      getFile: () => failingFile,
      getParseResult: () => parseResult,
      setStatusMessage: message => messages.push(message)
    });

    await handler({ target: button } as unknown as Event);

    assert.equal(status.textContent, "Entropy calculation failed: read failed");
    assert.equal(button.textContent, "Retry entropy");
    assert.equal(button.disabled, false);
    assert.deepEqual(messages, [
      "Calculating section entropy...",
      "Entropy calculation failed: read failed"
    ]);
  } finally {
    globals["Element"] = originalElement;
  }
});

void test("section entropy handler exposes a busy state while the stream is pending", async () => {
  const globals = globalThis as unknown as Record<string, unknown>;
  const originalElement = globals["Element"];
  const streamState: {
    controller?: ReadableStreamDefaultController<Uint8Array>;
  } = {};
  const file = {
    size: 4,
    slice: () => ({
      stream: () => new ReadableStream<Uint8Array>({
        start: controller => { streamState.controller = controller; }
      })
    })
  } as unknown as File;
  const root = new FakeElement();
  const button = new FakeElement(root);
  const parseResult = createCoffResult();
  parseResult.parsed.sections.splice(1);
  parseResult.parsed.sections[0]!.sizeOfRawData = 4;
  globals["Element"] = FakeElement;
  try {
    const handler = createSectionEntropyClickHandler({
      getFile: () => file,
      getParseResult: () => parseResult,
      setStatusMessage: () => {}
    });

    const pending = handler({ target: button } as unknown as Event);
    await Promise.resolve();

    assert.equal(button.disabled, true);
    assert.equal(button.textContent, "Calculating...");
    const streamController = streamState.controller;
    assert.ok(streamController);
    streamController.enqueue(new Uint8Array(4));
    streamController.close();
    await pending;
    assert.equal(button.disabled, false);
  } finally {
    globals["Element"] = originalElement;
  }
});

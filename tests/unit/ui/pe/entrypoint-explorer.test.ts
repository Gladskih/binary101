"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import {
  enhanceAnalysisEntrypointExplorer,
  enhancePeEntrypointExplorer,
  selectPeEntrypointRva
} from "../../../../ui/pe-entrypoint-explorer.js";

type Listener = (event: { target: FakeElement; preventDefault: () => void }) => void;
type GlobalDom = { Element?: unknown; HTMLElement?: unknown; HTMLInputElement?: unknown };

class FakeElement {
  dataset: Record<string, string> = {};
  innerHTML = "";
  value = "";
  private listeners = new Map<string, Listener>();
  constructor(readonly role: string) {}
  addEventListener(type: string, listener: Listener): void {
    this.listeners.set(type, listener);
  }
  dispatch(type: string, target: FakeElement): void {
    this.listeners.get(type)?.({ target, preventDefault: () => {} });
  }
  matches(selector: string): boolean {
    return selector === "[data-pe-entrypoint-explorer]" && this.role === "explorer";
  }
  closest(selector: string): FakeElement | null {
    if (selector === "[data-pe-entrypoint-block-select]") {
      return this.dataset["peEntrypointBlockSelect"] == null ? null : this;
    }
    if (selector === "[data-pe-entrypoint-page-action]") {
      return this.dataset["peEntrypointPageAction"] == null ? null : this;
    }
    if (selector === "[data-pe-entrypoint-block-sort]") {
      return this.dataset["peEntrypointBlockSort"] == null ? null : this;
    }
    return null;
  }
  querySelectorAll(selector: string): FakeElement[] {
    return selector === "[data-pe-entrypoint-explorer]" ? [fakeExplorer] : [];
  }
}

class FakeInputElement extends FakeElement {}

const fakeRoot = new FakeElement("root");
const fakeExplorer = new FakeElement("explorer");

const createInstruction = (rva: number) => ({
  rva,
  fileOffset: rva - 0x1000,
  text: rva === 0x1078 ? "ret" : "nop"
});

const createPe = (): PeWindowsParseResult =>
  ({
    entrypointDisassembly: {
      bitness: 64,
      entrypointRva: 0x1000,
      bytesDecoded: 121,
      instructionCount: 121,
      blocks: [{
        kind: "entrypoint",
        startRva: 0x1000,
        fileOffsetStart: 0x200,
        instructions: Array.from({ length: 121 }, (_value, index) =>
          createInstruction(0x1000 + index))
      }]
    }
  }) as unknown as PeWindowsParseResult;

const createManyBlockPe = (): PeWindowsParseResult =>
  ({
    entrypointDisassembly: {
      bitness: 64,
      entrypointRva: 0x1000,
      bytesDecoded: 51,
      instructionCount: 51,
      blocks: Array.from({ length: 51 }, (_value, index) => ({
        kind: index === 0 ? "entrypoint" : "followed-call",
        startRva: 0x1000 + index * 0x10,
        fileOffsetStart: 0x200 + index,
        instructions: [createInstruction(0x1000 + index * 0x10)]
      }))
    }
  }) as unknown as PeWindowsParseResult;

const createManySourcePe = (): PeWindowsParseResult =>
  ({
    entrypointDisassembly: {
      bitness: 64,
      entrypointRva: 0x1000,
      bytesDecoded: 10,
      instructionCount: 10,
      blocks: Array.from({ length: 10 }, (_value, index) => ({
        kind: "followed-call",
        startRva: 0x2000,
        fileOffsetStart: 0x200,
        sourceInstructionRva: 0x1000 + index,
        instructions: [createInstruction(0x2000)]
      }))
    }
  }) as unknown as PeWindowsParseResult;

const withFakeDom = (callback: () => void): void => {
  const globals = globalThis as unknown as GlobalDom;
  const originalElement = globals.Element;
  const originalHTMLElement = globals.HTMLElement;
  const originalHTMLInputElement = globals.HTMLInputElement;
  globals.Element = FakeElement;
  globals.HTMLElement = FakeElement;
  globals.HTMLInputElement = FakeInputElement;
  try {
    callback();
  } finally {
    globals.Element = originalElement;
    globals.HTMLElement = originalHTMLElement;
    globals.HTMLInputElement = originalHTMLInputElement;
  }
};

void test("enhancePeEntrypointExplorer pages and selects hidden instruction RVAs", () => {
  withFakeDom(() => {
    fakeExplorer.dataset = {};
    fakeExplorer.innerHTML = "";
    enhancePeEntrypointExplorer(fakeRoot as unknown as ParentNode, createPe());

    assert.match(fakeExplorer.innerHTML, /Instructions 1-120 of 121/);
    assert.equal(fakeExplorer.innerHTML.includes(`data-pe-entrypoint-rva="4216"`), false);
    assert.equal(selectPeEntrypointRva(fakeRoot as unknown as ParentNode, 0x1078), true);
    assert.equal(fakeExplorer.dataset["peEntrypointInstructionPageIndex"], "1");
    assert.match(fakeExplorer.innerHTML, /data-pe-entrypoint-rva="4216"/);
  });
});

void test("enhancePeEntrypointExplorer handles block and page controls", () => {
  withFakeDom(() => {
    fakeExplorer.dataset = {};
    fakeExplorer.innerHTML = "";
    enhancePeEntrypointExplorer(fakeRoot as unknown as ParentNode, createManyBlockPe());

    const nextBlocks = new FakeElement("button");
    nextBlocks.dataset["peEntrypointPageTarget"] = "blocks";
    nextBlocks.dataset["peEntrypointPageAction"] = "next";
    fakeExplorer.dispatch("click", nextBlocks);
    assert.equal(fakeExplorer.dataset["peEntrypointBlockPageIndex"], "1");

    const blockSelector = new FakeElement("button");
    blockSelector.dataset["peEntrypointBlockSelect"] = "50";
    fakeExplorer.dispatch("click", blockSelector);
    assert.equal(fakeExplorer.dataset["peEntrypointSelectedBlockIndex"], "50");
    assert.equal(fakeExplorer.dataset["peEntrypointBlockPageIndex"], "2");

    const input = new FakeInputElement("input");
    input.dataset["peEntrypointPageInput"] = "blocks";
    input.value = "1";
    fakeExplorer.dispatch("change", input);
    assert.equal(fakeExplorer.dataset["peEntrypointBlockPageIndex"], "0");
  });
});

void test("enhancePeEntrypointExplorer sorts block index and pages selected sources", () => {
  withFakeDom(() => {
    fakeExplorer.dataset = {};
    fakeExplorer.innerHTML = "";
    enhancePeEntrypointExplorer(fakeRoot as unknown as ParentNode, createManySourcePe());

    assert.match(fakeExplorer.innerHTML, /Sources 1-8 of 10/);
    assert.equal(fakeExplorer.innerHTML.includes(`data-pe-entrypoint-jump="4103"`), true);
    assert.equal(fakeExplorer.innerHTML.includes(`data-pe-entrypoint-jump="4104"`), false);

    const nextSources = new FakeElement("button");
    nextSources.dataset["peEntrypointPageTarget"] = "sources";
    nextSources.dataset["peEntrypointPageAction"] = "next";
    fakeExplorer.dispatch("click", nextSources);
    assert.equal(fakeExplorer.dataset["peEntrypointSourcePageIndex"], "1");
    assert.equal(fakeExplorer.innerHTML.includes(`data-pe-entrypoint-jump="4104"`), true);

    const sortRva = new FakeElement("button");
    sortRva.dataset["peEntrypointBlockSort"] = "0";
    fakeExplorer.dispatch("click", sortRva);
    assert.equal(fakeExplorer.dataset["peEntrypointBlockSortColumn"], "0");
    assert.equal(fakeExplorer.dataset["peEntrypointBlockSortDirection"], "ascending");
  });
});

void test("enhanceAnalysisEntrypointExplorer ignores non-PE results", () => {
  withFakeDom(() => {
    fakeExplorer.innerHTML = "unchanged";
    enhanceAnalysisEntrypointExplorer(fakeRoot as unknown as ParentNode, {
      analyzer: null,
      parsed: null
    });

    assert.equal(fakeExplorer.innerHTML, "unchanged");
  });
});

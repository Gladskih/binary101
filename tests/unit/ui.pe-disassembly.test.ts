import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeDisassemblyController } from "../../ui/pe-disassembly.js";
import type { ParseForUiResult } from "../../analyzers/index.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { AnalyzePeInstructionSetOptions, PeInstructionSetReport } from "../../analyzers/pe/disassembly.js";
import { MockFile } from "../helpers/mock-file.js";

type GlobalDom = {
  document?: unknown;
  HTMLElement?: unknown;
  HTMLProgressElement?: unknown;
};

class FakeHTMLElement {
  textContent: string | null = null;
}

class FakeHTMLProgressElement extends FakeHTMLElement {
  max = 0;
  value = 0;
  removedAttributes: string[] = [];
  removeAttribute(name: string): void {
    this.removedAttributes.push(name);
  }
}

const createMinimalPe = (): PeParseResult =>
  ({
    coff: { Machine: 0x8664 },
    opt: { isPlus: true, ImageBase: 0x140000000, AddressOfEntryPoint: 0x1000 },
    rvaToOff: () => 0,
    sections: []
  }) as unknown as PeParseResult;

const installFakeDom = (): {
  progress: FakeHTMLProgressElement;
  text: FakeHTMLElement;
  restore: () => void;
} => {
  const globals = globalThis as unknown as GlobalDom;
  const originalDocument = globals.document;
  const originalHTMLElement = globals.HTMLElement;
  const originalHTMLProgressElement = globals.HTMLProgressElement;

  globals.HTMLElement = FakeHTMLElement;
  globals.HTMLProgressElement = FakeHTMLProgressElement;

  const progress = new FakeHTMLProgressElement();
  const text = new FakeHTMLElement();
  globals.document = {
    getElementById: (id: string): unknown => {
      if (id === "peInstructionSetsProgress") return progress;
      if (id === "peInstructionSetsProgressText") return text;
      return null;
    }
  };

  return {
    progress,
    text,
    restore: () => {
      globals.document = originalDocument;
      globals.HTMLElement = originalHTMLElement;
      globals.HTMLProgressElement = originalHTMLProgressElement;
    }
  };
};

const flushTimers = async (): Promise<void> => {
  await new Promise<void>(resolve => setTimeout(resolve, 0));
};

const createFakeReport = (): PeInstructionSetReport => ({
  bitness: 64,
  bytesSampled: 10,
  bytesDecoded: 10,
  instructionCount: 3,
  invalidInstructionCount: 1,
  instructionSets: [],
  issues: []
});

void test("pe disassembly controller updates progress and renders when complete", async () => {
  const dom = installFakeDom();
  const pe = createMinimalPe();
  const file = new MockFile(new Uint8Array([0x90]), "pe.bin");
  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
  const renders: ParseForUiResult[] = [];

  const analyze = async (_file: File, opts: AnalyzePeInstructionSetOptions): Promise<PeInstructionSetReport> => {
    opts.onProgress?.({
      stage: "loading",
      bytesSampled: 10,
      bytesDecoded: 0,
      instructionCount: 0,
      invalidInstructionCount: 0
    });
    opts.onProgress?.({
      stage: "decoding",
      bytesSampled: 10,
      bytesDecoded: 5,
      instructionCount: 2,
      invalidInstructionCount: 1
    });
    opts.onProgress?.({
      stage: "done",
      bytesSampled: 10,
      bytesDecoded: 10,
      instructionCount: 3,
      invalidInstructionCount: 1
    });
    return createFakeReport();
  };

  const controller = createPeDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: result => {
      renders.push(result);
    },
    analyze
  });

  controller.start(file, pe);
  await flushTimers();

  assert.equal(renders.length, 1);
  assert.ok(pe.disassembly);
  assert.equal(pe.disassembly.instructionCount, 3);
  assert.equal(dom.progress.max, 10);
  assert.equal(dom.progress.value, 10);
  assert.ok(dom.progress.removedAttributes.includes("value"));
  assert.ok(dom.text.textContent?.includes("Done."));

  dom.restore();
});

void test("pe disassembly controller does not render after cancel", async () => {
  const dom = installFakeDom();
  const pe = createMinimalPe();
  const file = new MockFile(new Uint8Array([0x90]), "pe.bin");
  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
  const renders: ParseForUiResult[] = [];

  const analyze = async (): Promise<PeInstructionSetReport> => {
    await flushTimers();
    return createFakeReport();
  };

  const controller = createPeDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: result => {
      renders.push(result);
    },
    analyze
  });

  controller.start(file, pe);
  controller.cancel();
  await flushTimers();
  await flushTimers();

  assert.equal(renders.length, 0);
  assert.equal(pe.disassembly, undefined);

  dom.restore();
});

void test("pe disassembly controller ignores results when file changes", async () => {
  const dom = installFakeDom();
  const pe = createMinimalPe();
  const file = new MockFile(new Uint8Array([0x90]), "pe.bin");
  const otherFile = new MockFile(new Uint8Array([0x90]), "other.bin");
  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
  const renders: ParseForUiResult[] = [];

  const controller = createPeDisassemblyController({
    getCurrentFile: () => otherFile,
    getCurrentParseResult: () => parseResult,
    renderResult: result => {
      renders.push(result);
    },
    analyze: async () => createFakeReport()
  });

  controller.start(file, pe);
  await flushTimers();

  assert.equal(renders.length, 0);
  assert.equal(pe.disassembly, undefined);

  dom.restore();
});

void test("pe disassembly controller ignores results when current parse result is not PE", async () => {
  const dom = installFakeDom();
  const pe = createMinimalPe();
  const file = new MockFile(new Uint8Array([0x90]), "pe.bin");
  const renders: ParseForUiResult[] = [];

  const controller = createPeDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => ({ analyzer: null, parsed: null }),
    renderResult: result => {
      renders.push(result);
    },
    analyze: async () => createFakeReport()
  });

  controller.start(file, pe);
  await flushTimers();

  assert.equal(renders.length, 0);
  assert.equal(pe.disassembly, undefined);

  dom.restore();
});

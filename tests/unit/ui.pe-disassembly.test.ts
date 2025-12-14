import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeDisassemblyController } from "../../ui/pe-disassembly.js";
import type { ParseForUiResult } from "../../analyzers/index.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { AnalyzePeInstructionSetOptions, PeInstructionSetReport } from "../../analyzers/pe/disassembly.js";
import { FakeHTMLElement, installFakeDom, flushTimers } from "../helpers/fake-dom.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { MockFile } from "../helpers/mock-file.js";
const createMinimalPe = (): PeParseResult =>
  ({
    coff: { Machine: 0x8664 },
    opt: { isPlus: true, ImageBase: 0x140000000, AddressOfEntryPoint: 0x1000 },
    rvaToOff: () => 0,
    sections: []
  }) as unknown as PeParseResult;
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
void test("pe disassembly controller updates instruction-set chip table while decoding", async () => {
  const chip = new FakeHTMLElement();
  chip.className = "opt dim";
  const count = new FakeHTMLElement();
  count.className = "dim";
  count.textContent = "0";
  const dom = installFakeDom({
    peInstructionSetChip_SSE2: chip,
    peInstructionSetCount_SSE2: count
  });
  const pe = createMinimalPe();
  const file = new MockFile(new Uint8Array([0x90]), "pe.bin");
  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
  const controller = createPeDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: () => {},
    analyze: async (_file: File, opts: AnalyzePeInstructionSetOptions): Promise<PeInstructionSetReport> => {
      opts.onProgress?.({
        stage: "decoding",
        bytesSampled: 10,
        bytesDecoded: 5,
        instructionCount: 2,
        invalidInstructionCount: 0,
        knownFeatureCounts: { SSE2: 7 }
      });
      opts.onProgress?.({
        stage: "done",
        bytesSampled: 10,
        bytesDecoded: 10,
        instructionCount: 3,
        invalidInstructionCount: 0,
        knownFeatureCounts: { SSE2: 9 }
      });
      return createFakeReport();
    }
  });
  controller.start(file, pe);
  await flushTimers();
  assert.equal(count.textContent, "9");
  assert.equal(count.className, "");
  assert.equal(chip.className, "opt sel");
  dom.restore();
});
void test("pe disassembly controller toggles analyze/cancel buttons and renders 0-byte progress", async () => {
  const analyzeButton = new FakeHTMLElement();
  const cancelButton = new FakeHTMLElement();
  cancelButton.hidden = true;
  const dom = installFakeDom({
    peInstructionSetsAnalyzeButton: analyzeButton,
    peInstructionSetsCancelButton: cancelButton
  });
  const pe = createMinimalPe();
  const file = new MockFile(new Uint8Array([0x90]), "pe.bin");
  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
  const controller = createPeDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: () => {},
    analyze: async (_file: File, opts: AnalyzePeInstructionSetOptions): Promise<PeInstructionSetReport> => {
      opts.onProgress?.({
        stage: "loading",
        bytesSampled: 0,
        bytesDecoded: 0,
        instructionCount: 0,
        invalidInstructionCount: 0
      });
      await flushTimers();
      return createFakeReport();
    }
  });
  controller.start(file, pe);
  assert.equal(analyzeButton.disabled, true);
  assert.equal(cancelButton.hidden, false);
  assert.ok(dom.text.textContent?.includes("0 B"));
  await flushTimers();
  await flushTimers();
  assert.equal(analyzeButton.disabled, false);
  assert.equal(cancelButton.hidden, true);
  dom.restore();
});
void test("pe disassembly controller always includes AddressOfEntryPoint alongside exports", async () => {
  const dom = installFakeDom();
  const pe = createMinimalPe();
  pe.exports = {
    entries: [
      { rva: 0x1234, forwarder: null },
      { rva: 0x2000, forwarder: "KERNEL32.Sleep" }
    ]
  } as unknown as PeParseResult["exports"];
  const file = new MockFile(new Uint8Array([0x90]), "pe.bin");
  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
  let captured: AnalyzePeInstructionSetOptions | null = null;
  const controller = createPeDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: () => {},
    analyze: async (_file: File, opts: AnalyzePeInstructionSetOptions): Promise<PeInstructionSetReport> => {
      captured = opts;
      return createFakeReport();
    }
  });
  controller.start(file, pe);
  await flushTimers();
  const capturedOptions = expectDefined<AnalyzePeInstructionSetOptions>(captured);
  assert.equal(capturedOptions.entrypointRva, pe.opt.AddressOfEntryPoint);
  assert.deepEqual(capturedOptions.exportRvas, [0x1234]);
  dom.restore();
});
void test("pe disassembly controller includes unwind begin RVAs when available", async () => {
  const dom = installFakeDom();
  const pe = createMinimalPe();
  pe.exception = {
    functionCount: 2,
    beginRvas: [0x1337, 0x2000],
    uniqueUnwindInfoCount: 2,
    handlerUnwindInfoCount: 0,
    chainedUnwindInfoCount: 0,
    invalidEntryCount: 0,
    issues: []
  } as unknown as PeParseResult["exception"];
  const file = new MockFile(new Uint8Array([0x90]), "pe.bin");
  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
  let captured: AnalyzePeInstructionSetOptions | null = null;
  const controller = createPeDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: () => {},
    analyze: async (_file: File, opts: AnalyzePeInstructionSetOptions): Promise<PeInstructionSetReport> => {
      captured = opts;
      return createFakeReport();
    }
  });
  controller.start(file, pe);
  await flushTimers();
  const capturedOptions = expectDefined<AnalyzePeInstructionSetOptions>(captured);
  assert.deepEqual(capturedOptions.unwindBeginRvas, [0x1337, 0x2000]);
  dom.restore();
});

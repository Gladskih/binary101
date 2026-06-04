import assert from "node:assert/strict";
import { test } from "node:test";
import type { FileRangeReader } from "../../analyzers/file-range-reader.js";
import type { ParseForUiResult } from "../../analyzers/index.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointDisassemblyReport
} from "../../analyzers/pe/disassembly/index.js";
import { createPeEntrypointDisassemblyController } from "../../ui/pe-entrypoint-disassembly.js";
import { FakeHTMLElement, installFakeDom, flushTimers } from "../helpers/fake-dom.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { MockFile } from "../helpers/mock-file.js";

const createMinimalPe = (): PeWindowsParseResult =>
  ({
    coff: { Machine: 0x8664 },
    opt: {
      Magic: 0x20b,
      ImageBase: 0x140000000n,
      AddressOfEntryPoint: 0x1000,
      SizeOfHeaders: 0x400
    },
    rvaToOff: () => 0,
    sections: [],
    imports: { entries: [], thunkEntrySize: 8 },
    delayImports: null,
    loadcfg: null
  }) as unknown as PeWindowsParseResult;

const createFakeReport = (): PeEntrypointDisassemblyReport => ({
  bitness: 64,
  entrypointRva: 0x1000,
  bytesDecoded: 1,
  instructionCount: 1,
  blocks: [{
    kind: "entrypoint",
    startRva: 0x1000,
    fileOffsetStart: 0,
    instructions: [{ rva: 0x1000, fileOffset: 0, text: "nop" }]
  }],
  issues: []
});

void test("pe entrypoint disassembly controller renders when complete", async () => {
  const button = new FakeHTMLElement();
  const instructionSetButton = new FakeHTMLElement();
  const dom = installFakeDom({
    peEntrypointDisassembleButton: button,
    peInstructionSetsAnalyzeButton: instructionSetButton
  });
  const pe = createMinimalPe();
  const file = new MockFile(new Uint8Array([0x90]), "pe.bin");
  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
  const renders: ParseForUiResult[] = [];
  const controller = createPeEntrypointDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: result => {
      renders.push(result);
    },
    analyze: async () => createFakeReport()
  });

  controller.start(file, pe);
  assert.equal(button.disabled, true);
  assert.equal(instructionSetButton.disabled, true);
  await flushTimers();

  assert.equal(renders.length, 1);
  assert.equal(button.disabled, false);
  assert.equal(instructionSetButton.disabled, false);
  assert.equal(pe.entrypointDisassembly?.instructionCount, 1);
  dom.restore();
});

void test("pe entrypoint disassembly controller passes PE entrypoint options", async () => {
  const dom = installFakeDom();
  const pe = createMinimalPe();
  const file = new MockFile(new Uint8Array([0x90]), "pe.bin");
  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
  let captured: AnalyzePeEntrypointDisassemblyOptions | null = null;
  const controller = createPeEntrypointDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: () => {},
    analyze: async (
      _reader: FileRangeReader,
      opts: AnalyzePeEntrypointDisassemblyOptions
    ): Promise<PeEntrypointDisassemblyReport> => {
      captured = opts;
      return createFakeReport();
    }
  });

  controller.start(file, pe);
  await flushTimers();

  const capturedOptions = expectDefined<AnalyzePeEntrypointDisassemblyOptions>(captured);
  assert.equal(capturedOptions.entrypointRva, 0x1000);
  assert.equal(capturedOptions.headerRvaLimit, 0x400);
  assert.equal(capturedOptions.imageBase, 0x140000000n);
  assert.equal(capturedOptions.imports, pe.imports);
  assert.equal(capturedOptions.delayImports, pe.delayImports);
  assert.equal(capturedOptions.loadcfg, pe.loadcfg);
  dom.restore();
});

void test("pe entrypoint disassembly controller ignores results when file changes", async () => {
  const button = new FakeHTMLElement();
  const dom = installFakeDom({ peEntrypointDisassembleButton: button });
  const pe = createMinimalPe();
  const file = new MockFile(new Uint8Array([0x90]), "pe.bin");
  const otherFile = new MockFile(new Uint8Array([0x90]), "other.bin");
  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
  const renders: ParseForUiResult[] = [];
  const controller = createPeEntrypointDisassemblyController({
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
  assert.equal(button.disabled, false);
  assert.equal(pe.entrypointDisassembly, undefined);
  dom.restore();
});

void test("pe entrypoint disassembly controller renders analyzer failures as notes", async () => {
  const dom = installFakeDom();
  const pe = createMinimalPe();
  const file = new MockFile(new Uint8Array([0x90]), "pe.bin");
  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
  const renders: ParseForUiResult[] = [];
  const controller = createPeEntrypointDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: result => {
      renders.push(result);
    },
    analyze: async () => {
      throw new Error("boom");
    }
  });

  controller.start(file, pe);
  await flushTimers();

  assert.equal(renders.length, 1);
  assert.equal(pe.entrypointDisassembly?.instructionCount, 0);
  assert.ok(pe.entrypointDisassembly?.issues.some(issue => /boom/i.test(issue)));
  dom.restore();
});

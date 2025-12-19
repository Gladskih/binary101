"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfDisassemblyController } from "../../ui/elf-disassembly.js";
import type { ParseForUiResult } from "../../analyzers/index.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { AnalyzeElfInstructionSetOptions, ElfInstructionSetReport } from "../../analyzers/elf/disassembly.js";
import { FakeHTMLElement, FakeHTMLProgressElement, installFakeDom, flushTimers } from "../helpers/fake-dom.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { MockFile } from "../helpers/mock-file.js";

const createMinimalElf = (): ElfParseResult =>
  ({
    ident: {
      classByte: 2,
      className: "ELF64",
      dataByte: 1,
      dataName: "Little endian",
      osabi: 0,
      abiVersion: 0
    },
    header: {
      type: 2,
      typeName: "Executable",
      machine: 62,
      machineName: "x86-64",
      entry: 0x1000n,
      phoff: 0n,
      shoff: 0n,
      flags: 0,
      ehsize: 0,
      phentsize: 0,
      phnum: 0,
      shentsize: 0,
      shnum: 0,
      shstrndx: 0
    },
    programHeaders: [],
    sections: [],
    issues: [],
    is64: true,
    littleEndian: true,
    fileSize: 1
  }) as unknown as ElfParseResult;

const createFakeReport = (): ElfInstructionSetReport => ({
  bitness: 64,
  bytesSampled: 10,
  bytesDecoded: 10,
  instructionCount: 3,
  invalidInstructionCount: 1,
  instructionSets: [],
  issues: []
});

void test("elf disassembly controller updates progress and renders when complete", async () => {
  const progress = new FakeHTMLProgressElement();
  const text = new FakeHTMLElement();
  const dom = installFakeDom({
    elfInstructionSetsProgress: progress,
    elfInstructionSetsProgressText: text
  });
  const elf = createMinimalElf();
  const file = new MockFile(new Uint8Array([0x90]), "elf.bin");
  const parseResult: ParseForUiResult = { analyzer: "elf", parsed: elf };
  const renders: ParseForUiResult[] = [];
  const analyze = async (_file: File, opts: AnalyzeElfInstructionSetOptions): Promise<ElfInstructionSetReport> => {
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
  const controller = createElfDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: result => {
      renders.push(result);
    },
    analyze
  });

  controller.start(file, elf);
  await flushTimers();

  assert.equal(renders.length, 1);
  assert.ok(elf.disassembly);
  assert.equal(elf.disassembly.instructionCount, 3);
  assert.equal(progress.max, 10);
  assert.equal(progress.value, 10);
  assert.ok(progress.removedAttributes.includes("value"));
  assert.ok(text.textContent?.includes("Done."));
  dom.restore();
});

void test("elf disassembly controller does not render after cancel", async () => {
  const dom = installFakeDom();
  const elf = createMinimalElf();
  const file = new MockFile(new Uint8Array([0x90]), "elf.bin");
  const parseResult: ParseForUiResult = { analyzer: "elf", parsed: elf };
  const renders: ParseForUiResult[] = [];
  const analyze = async (): Promise<ElfInstructionSetReport> => {
    await flushTimers();
    return createFakeReport();
  };
  const controller = createElfDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: result => {
      renders.push(result);
    },
    analyze
  });

  controller.start(file, elf);
  controller.cancel();
  await flushTimers();
  await flushTimers();

  assert.equal(renders.length, 0);
  assert.equal(elf.disassembly, undefined);
  dom.restore();
});

void test("elf disassembly controller updates instruction-set chip table while decoding", async () => {
  const chip = new FakeHTMLElement();
  chip.className = "opt dim";
  const count = new FakeHTMLElement();
  count.className = "dim";
  count.textContent = "0";
  const dom = installFakeDom({
    elfInstructionSetChip_SSE2: chip,
    elfInstructionSetCount_SSE2: count
  });
  const elf = createMinimalElf();
  const file = new MockFile(new Uint8Array([0x90]), "elf.bin");
  const parseResult: ParseForUiResult = { analyzer: "elf", parsed: elf };
  const controller = createElfDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: () => {},
    analyze: async (_file: File, opts: AnalyzeElfInstructionSetOptions): Promise<ElfInstructionSetReport> => {
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

  controller.start(file, elf);
  await flushTimers();

  assert.equal(count.textContent, "9");
  assert.equal(count.className, "");
  assert.equal(chip.className, "opt sel");
  dom.restore();
});

void test("elf disassembly controller toggles analyze/cancel buttons", async () => {
  const analyzeButton = new FakeHTMLElement();
  const cancelButton = new FakeHTMLElement();
  cancelButton.hidden = true;
  const dom = installFakeDom({
    elfInstructionSetsAnalyzeButton: analyzeButton,
    elfInstructionSetsCancelButton: cancelButton
  });
  const elf = createMinimalElf();
  const file = new MockFile(new Uint8Array([0x90]), "elf.bin");
  const parseResult: ParseForUiResult = { analyzer: "elf", parsed: elf };
  const controller = createElfDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: () => {},
    analyze: async (): Promise<ElfInstructionSetReport> => createFakeReport()
  });

  controller.start(file, elf);
  assert.equal(analyzeButton.disabled, true);
  assert.equal(cancelButton.hidden, false);
  await flushTimers();
  await flushTimers();
  assert.equal(analyzeButton.disabled, false);
  assert.equal(cancelButton.hidden, true);
  dom.restore();
});

void test("elf disassembly controller passes ELF details into analyzer options", async () => {
  const dom = installFakeDom();
  const elf = createMinimalElf();
  elf.header.machine = 3;
  elf.header.entry = 0x1234n;
  const file = new MockFile(new Uint8Array([0x90]), "elf.bin");
  const parseResult: ParseForUiResult = { analyzer: "elf", parsed: elf };
  let captured: AnalyzeElfInstructionSetOptions | null = null;
  const controller = createElfDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: () => {},
    analyze: async (_file: File, opts: AnalyzeElfInstructionSetOptions): Promise<ElfInstructionSetReport> => {
      captured = opts;
      return createFakeReport();
    }
  });

  controller.start(file, elf);
  await flushTimers();

  const capturedOptions = expectDefined<AnalyzeElfInstructionSetOptions>(captured);
  assert.equal(capturedOptions.machine, 3);
  assert.equal(capturedOptions.is64Bit, elf.is64);
  assert.equal(capturedOptions.littleEndian, elf.littleEndian);
  assert.equal(capturedOptions.entrypointVaddr, 0x1234n);
  assert.equal(capturedOptions.yieldEveryInstructions, 1024);
  dom.restore();
});


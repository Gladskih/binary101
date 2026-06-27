"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeDisassemblyController } from "../../../../../ui/pe-disassembly.js";
import type { ParseForUiResult } from "../../../../../analyzers/index.js";
import type { PeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import type { AnalyzePeInstructionSetOptions, PeInstructionSetReport } from "../../../../../analyzers/pe/disassembly/index.js";
import { installFakeDom, flushTimers } from "../../../../helpers/fake-dom.js";
import { expectDefined } from "../../../../helpers/expect-defined.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";

const TEST_IMAGE_BASE = 0x400000n;

const createMinimalPe = (): PeWindowsParseResult =>
  ({
    coff: { Machine: 0x8664 },
    opt: { Magic: 0x20b, ImageBase: TEST_IMAGE_BASE, AddressOfEntryPoint: 0x1000 },
    rvaToOff: (rva: number) => rva,
    sections: []
  }) as unknown as PeWindowsParseResult;

const createFakeReport = (): PeInstructionSetReport => ({
  bitness: 64,
  bytesSampled: 10,
  bytesDecoded: 10,
  instructionCount: 3,
  invalidInstructionCount: 0,
  directIatReferences: [],
  codeStringReferences: [],
  apiStringReferences: [],
  instructionSets: [],
  issues: []
});

const findSeeds = (
  options: AnalyzePeInstructionSetOptions,
  source: string
): number[] =>
  options.extraEntrypoints?.find(entry => entry.source === source)?.rvas ?? [];

const addTextSection = (pe: PeWindowsParseResult): void => {
  pe.sections = [{
    name: inlinePeSectionName(".text"),
    virtualAddress: 0x1000,
    virtualSize: 0x3000,
    sizeOfRawData: 0x3000,
    pointerToRawData: 0x1000,
    characteristics: 0x20000000 // Microsoft PE format: IMAGE_SCN_MEM_EXECUTE.
  }];
};

void test("pe disassembly controller includes extra entrypoints from LOAD_CONFIG CFG pointers/tables", async () => {
  const dom = installFakeDom();
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);

  dv.setBigUint64(0x20, TEST_IMAGE_BASE + 0x2000n, true);
  dv.setBigUint64(0x28, TEST_IMAGE_BASE + 0x3000n, true);
  dv.setBigUint64(0x30, TEST_IMAGE_BASE + 0x2100n, true);
  dv.setBigUint64(0x38, TEST_IMAGE_BASE + 0x2200n, true);
  dv.setBigUint64(0x40, TEST_IMAGE_BASE + 0x2300n, true);
  dv.setBigUint64(0x48, TEST_IMAGE_BASE + 0x2400n, true);
  dv.setUint32(0x50, 0x1111, true);
  dv.setUint32(0x54, 0x2222, true);
  dv.setUint32(0x60, 0x3333, true);

  const file = new MockFile(bytes, "loadcfg-seeds.bin");
  const pe = createMinimalPe();
  addTextSection(pe);
  pe.loadcfg = {
    GuardCFCheckFunctionPointer: TEST_IMAGE_BASE + 0x20n,
    GuardCFDispatchFunctionPointer: TEST_IMAGE_BASE + 0x28n,
    GuardXFGCheckFunctionPointer: TEST_IMAGE_BASE + 0x30n,
    GuardXFGDispatchFunctionPointer: TEST_IMAGE_BASE + 0x38n,
    GuardXFGTableDispatchFunctionPointer: TEST_IMAGE_BASE + 0x40n,
    GuardMemcpyFunctionPointer: TEST_IMAGE_BASE + 0x48n,
    GuardEHContinuationTable: TEST_IMAGE_BASE + 0x50n,
    GuardEHContinuationCount: 2,
    GuardLongJumpTargetTable: TEST_IMAGE_BASE + 0x60n,
    GuardLongJumpTargetCount: 1
  } as unknown as PeWindowsParseResult["loadcfg"];

  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };

  let captured: AnalyzePeInstructionSetOptions | null = null;
  const controller = createPeDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: () => {},
    analyze: async (_reader, opts: AnalyzePeInstructionSetOptions): Promise<PeInstructionSetReport> => {
      captured = opts;
      return createFakeReport();
    }
  });

  controller.start(file, pe);
  await flushTimers();

  const capturedOptions = expectDefined<AnalyzePeInstructionSetOptions>(captured);
  assert.deepEqual(findSeeds(capturedOptions, "GuardCF check function"), [0x2000]);
  assert.deepEqual(findSeeds(capturedOptions, "GuardCF dispatch function"), [0x3000]);
  assert.deepEqual(findSeeds(capturedOptions, "GuardXFG check function"), [0x2100]);
  assert.deepEqual(findSeeds(capturedOptions, "GuardXFG dispatch function"), [0x2200]);
  assert.deepEqual(findSeeds(capturedOptions, "GuardXFG table dispatch function"), [0x2300]);
  assert.deepEqual(findSeeds(capturedOptions, "Guard memcpy function"), [0x2400]);
  assert.deepEqual(findSeeds(capturedOptions, "GuardEH continuation"), [0x1111, 0x2222]);
  assert.deepEqual(findSeeds(capturedOptions, "Guard longjmp target"), [0x3333]);

  dom.restore();
});

void test("pe disassembly controller reads 32-bit LOAD_CONFIG pointer slots", async () => {
  const dom = installFakeDom();
  const bytes = new Uint8Array(0x40).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0x20, Number(TEST_IMAGE_BASE + 0x2000n), true);
  const file = new MockFile(bytes, "loadcfg-32-bit-seeds.bin");
  const pe = createMinimalPe();
  pe.opt.Magic = 0x10b; // Microsoft PE format: PE32 optional-header Magic.
  addTextSection(pe);
  pe.loadcfg = {
    GuardCFCheckFunctionPointer: TEST_IMAGE_BASE + 0x20n,
    GuardCFDispatchFunctionPointer: TEST_IMAGE_BASE + 0x3dn
  } as unknown as PeWindowsParseResult["loadcfg"];
  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };

  let captured: AnalyzePeInstructionSetOptions | null = null;
  const controller = createPeDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: () => {},
    analyze: async (_reader, opts: AnalyzePeInstructionSetOptions): Promise<PeInstructionSetReport> => {
      captured = opts;
      return createFakeReport();
    }
  });

  controller.start(file, pe);
  await flushTimers();

  const capturedOptions = expectDefined<AnalyzePeInstructionSetOptions>(captured);
  assert.deepEqual(findSeeds(capturedOptions, "GuardCF check function"), [0x2000]);
  assert.deepEqual(findSeeds(capturedOptions, "GuardCF dispatch function"), []);

  dom.restore();
});

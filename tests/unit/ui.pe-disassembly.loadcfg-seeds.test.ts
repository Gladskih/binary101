"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeDisassemblyController } from "../../ui/pe-disassembly.js";
import type { ParseForUiResult } from "../../analyzers/index.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { AnalyzePeInstructionSetOptions, PeInstructionSetReport } from "../../analyzers/pe/disassembly.js";
import { installFakeDom, flushTimers } from "../helpers/fake-dom.js";
import { expectDefined } from "../helpers/expect-defined.js";
import { MockFile } from "../helpers/mock-file.js";

const createMinimalPe = (): PeParseResult =>
  ({
    coff: { Machine: 0x8664 },
    opt: { isPlus: true, ImageBase: 0, AddressOfEntryPoint: 0x1000 },
    rvaToOff: (rva: number) => rva,
    sections: []
  }) as unknown as PeParseResult;

const createFakeReport = (): PeInstructionSetReport => ({
  bitness: 64,
  bytesSampled: 10,
  bytesDecoded: 10,
  instructionCount: 3,
  invalidInstructionCount: 0,
  instructionSets: [],
  issues: []
});

const findSeeds = (
  options: AnalyzePeInstructionSetOptions,
  source: string
): number[] =>
  options.extraEntrypoints?.find(entry => entry.source === source)?.rvas ?? [];

void test("pe disassembly controller includes extra entrypoints from LOAD_CONFIG CFG pointers/tables", async () => {
  const dom = installFakeDom();
  const bytes = new Uint8Array(0x200).fill(0);
  const dv = new DataView(bytes.buffer);

  dv.setUint32(0x50, 0x1111, true);
  dv.setUint32(0x54, 0x2222, true);
  dv.setUint32(0x60, 0x3333, true);

  const file = new MockFile(bytes, "loadcfg-seeds.bin");
  const pe = createMinimalPe();
  pe.loadcfg = {
    GuardCFCheckFunctionPointer: 0x2000,
    GuardCFDispatchFunctionPointer: 0x3000,
    GuardEHContinuationTable: 0x50,
    GuardEHContinuationCount: 2,
    GuardLongJumpTargetTable: 0x60,
    GuardLongJumpTargetCount: 1
  } as unknown as PeParseResult["loadcfg"];

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
  assert.deepEqual(findSeeds(capturedOptions, "GuardCF check function"), [0x2000]);
  assert.deepEqual(findSeeds(capturedOptions, "GuardCF dispatch function"), [0x3000]);
  assert.deepEqual(findSeeds(capturedOptions, "GuardEH continuation"), [0x1111, 0x2222]);
  assert.deepEqual(findSeeds(capturedOptions, "Guard longjmp target"), [0x3333]);

  dom.restore();
});


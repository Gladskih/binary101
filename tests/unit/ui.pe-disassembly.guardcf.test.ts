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
  invalidInstructionCount: 1,
  instructionSets: [],
  issues: []
});

void test("pe disassembly controller includes GuardCF function RVAs when available", async () => {
  const dom = installFakeDom();
  const bytes = new Uint8Array(0x100).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0x40 + 0, 0x1337, true);
  dv.setUint32(0x40 + 4, 0, true);
  const file = new MockFile(bytes, "guardcf.bin");

  const pe = createMinimalPe();
  pe.loadcfg = { GuardCFFunctionTable: 0x40, GuardCFFunctionCount: 1 } as unknown as PeParseResult["loadcfg"];

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
  assert.deepEqual(capturedOptions.guardCFFunctionRvas, [0x1337]);

  dom.restore();
});


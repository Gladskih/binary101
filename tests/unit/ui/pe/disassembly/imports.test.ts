"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../../../../analyzers/index.js";
import type {
  AnalyzePeInstructionSetOptions,
  PeInstructionSetReport
} from "../../../../../analyzers/pe/disassembly/index.js";
import type { PeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { createPeDisassemblyController } from "../../../../../ui/pe-disassembly.js";
import { expectDefined } from "../../../../helpers/expect-defined.js";
import { flushTimers, installFakeDom } from "../../../../helpers/fake-dom.js";
import { MockFile } from "../../../../helpers/mock-file.js";

// Microsoft PE format: AMD64 machine type and PE32+ optional-header magic.
const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
const PE32_PLUS_OPTIONAL_HEADER_MAGIC = 0x020b;
const IMAGE_BASE = 0x140000000n;
const ENTRYPOINT_RVA = 0x1000;
const AMD64_BITNESS = 64 as const;

const createPe = (): PeWindowsParseResult => ({
  coff: { Machine: IMAGE_FILE_MACHINE_AMD64 },
  opt: {
    Magic: PE32_PLUS_OPTIONAL_HEADER_MAGIC,
    ImageBase: IMAGE_BASE,
    AddressOfEntryPoint: ENTRYPOINT_RVA
  },
  imports: { entries: [], thunkEntrySize: BigUint64Array.BYTES_PER_ELEMENT },
  delayImports: { entries: [] },
  rvaToOff: () => 0,
  sections: []
}) as unknown as PeWindowsParseResult;

const createReport = (): PeInstructionSetReport => ({
  bitness: AMD64_BITNESS,
  bytesSampled: 0,
  bytesDecoded: 0,
  instructionCount: 0,
  invalidInstructionCount: 0,
  directIatReferences: [],
  instructionSets: [],
  issues: []
});

void test("pe disassembly controller passes eager and delay imports to analysis", async () => {
  const dom = installFakeDom();
  const pe = createPe();
  const file = new MockFile(new Uint8Array(), "pe.bin");
  const parseResult: ParseForUiResult = { analyzer: "pe", parsed: pe };
  let captured: AnalyzePeInstructionSetOptions | null = null;
  const controller = createPeDisassemblyController({
    getCurrentFile: () => file,
    getCurrentParseResult: () => parseResult,
    renderResult: () => {},
    analyze: async (_reader, options): Promise<PeInstructionSetReport> => {
      captured = options;
      return createReport();
    }
  });

  controller.start(file, pe);
  await flushTimers();

  const capturedOptions = expectDefined<AnalyzePeInstructionSetOptions>(captured);
  assert.equal(capturedOptions.imports, pe.imports);
  assert.equal(capturedOptions.delayImports, pe.delayImports);
  dom.restore();
});

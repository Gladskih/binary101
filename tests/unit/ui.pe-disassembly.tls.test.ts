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

void test("pe disassembly controller includes TLS callback RVAs when available", async () => {
  const dom = installFakeDom();
  const pe = createMinimalPe();
  pe.tls = { CallbackRvas: [0x1111, 0x2222] } as unknown as PeParseResult["tls"];
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
  assert.deepEqual(capturedOptions.tlsCallbackRvas, [0x1111, 0x2222]);

  dom.restore();
});


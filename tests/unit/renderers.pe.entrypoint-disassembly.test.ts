"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { renderInstructionSets } from "../../renderers/pe/disassembly.js";

const createPe = (overrides: Partial<PeWindowsParseResult> = {}): PeWindowsParseResult =>
  ({
    coff: { Machine: 0x8664 },
    opt: { AddressOfEntryPoint: 0x1000 },
    sections: [],
    ...overrides
  }) as unknown as PeWindowsParseResult;

void test("renderInstructionSets shows imports that continue at fallthrough", () => {
  const pe = createPe();
  pe.entrypointDisassembly = {
    bitness: 64,
    entrypointRva: 0x1000,
    bytesDecoded: 2,
    instructionCount: 2,
    blocks: [{
      kind: "entrypoint",
      startRva: 0x1000,
      fileOffsetStart: 0x200,
      instructions: [{
        rva: 0x1000,
        fileOffset: 0x200,
        text: "call qword [rel 0000000140002000h]",
        target: {
          kind: "import",
          label: "KERNEL32.dll!GetSystemTimeAsFileTime",
          slotRva: 0x2000,
          importKind: "eager",
          guardIatEntry: false,
          returnRva: 0x1006,
          returnFollowed: true
        }
      }]
    }],
    issues: []
  };

  const out: string[] = [];
  renderInstructionSets(pe, out);
  const html = out.join("");

  assert.ok(html.includes("KERNEL32.dll!GetSystemTimeAsFileTime"));
  assert.ok(html.includes("returns followed to 0x00001006"));
});

void test("renderInstructionSets labels followed returning import fallthrough blocks", () => {
  const pe = createPe();
  pe.entrypointDisassembly = {
    bitness: 64,
    entrypointRva: 0x1000,
    bytesDecoded: 3,
    instructionCount: 3,
    blocks: [
      {
        kind: "entrypoint",
        startRva: 0x1000,
        fileOffsetStart: 0x200,
        instructions: [{ rva: 0x1000, fileOffset: 0x200, text: "call 0000000140001010h" }]
      },
      {
        kind: "followed-import-return",
        startRva: 0x1005,
        fileOffsetStart: 0x205,
        sourceInstructionRva: 0x1010,
        instructions: [{ rva: 0x1005, fileOffset: 0x205, text: "ret" }]
      }
    ],
    issues: []
  };

  const out: string[] = [];
  renderInstructionSets(pe, out);

  assert.ok(out.join("").includes("Followed returning import fallthrough from 0x00001010"));
});

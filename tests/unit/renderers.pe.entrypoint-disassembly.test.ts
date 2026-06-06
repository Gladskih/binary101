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

void test("renderInstructionSets marks followed return blocks", () => {
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
        instructions: [{
          rva: 0x1000,
          fileOffset: 0x200,
          text: "call 0000000140001010h",
          target: {
            kind: "code",
            rva: 0x1010,
            followed: true
          }
        }]
      },
      {
        kind: "followed-return",
        startRva: 0x1005,
        fileOffsetStart: 0x205,
        sourceInstructionRva: 0x1010,
        instructions: [{
          rva: 0x1005,
          fileOffset: 0x205,
          text: "ret",
          target: { kind: "return", rva: 0x1005, followed: true }
        }]
      }
    ],
    issues: []
  };

  const out: string[] = [];
  renderInstructionSets(pe, out);
  const html = out.join("");

  assert.ok(html.includes("return followed 0x00001005"));
  assert.ok(html.includes("Followed return target from 0x00001010"));
});

void test("renderInstructionSets renders entrypoint notes column", () => {
  const pe = createPe();
  pe.entrypointDisassembly = {
    bitness: 64,
    entrypointRva: 0x1000,
    bytesDecoded: 1,
    instructionCount: 1,
    blocks: [{
      kind: "entrypoint",
      startRva: 0x1000,
      fileOffsetStart: 0x200,
      instructions: [{
        rva: 0x1000,
        fileOffset: 0x200,
        text: "mov eax,0BB40E64Eh",
        notes: ["MSVC-compatible x86 /GS default security cookie (0xBB40E64E)."]
      }]
    }],
    issues: []
  };

  const out: string[] = [];
  renderInstructionSets(pe, out);
  const html = out.join("");

  assert.ok(html.includes("<th>Notes</th>"));
  assert.ok(!html.includes("<th>Target</th>"));
  assert.ok(html.includes("MSVC-compatible x86 /GS default security cookie"));
});

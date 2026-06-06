"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeWindowsParseResult } from "../../analyzers/pe/index.js";
import { renderEntrypointDisassembly } from "../../renderers/pe/entrypoint-disassembly.js";

const createPe = (overrides: Partial<PeWindowsParseResult> = {}): PeWindowsParseResult =>
  ({
    coff: { Machine: 0x8664 },
    opt: { AddressOfEntryPoint: 0x1000 },
    sections: [],
    ...overrides
  }) as unknown as PeWindowsParseResult;

void test("renderEntrypointDisassembly shows imports that continue at fallthrough", () => {
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
  renderEntrypointDisassembly(pe, out);
  const html = out.join("");

  assert.ok(html.includes("KERNEL32.dll!GetSystemTimeAsFileTime"));
  assert.ok(html.includes("returns followed"));
  assert.ok(html.includes("0x00001006"));
  assert.ok(html.includes("data-pe-entrypoint-jump=\"4102\""));
});

void test("renderEntrypointDisassembly labels followed returning import fallthrough blocks", () => {
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
  renderEntrypointDisassembly(pe, out);

  assert.ok(out.join("").includes("Followed returning import fallthrough from 0x00001010"));
});

void test("renderEntrypointDisassembly marks followed return blocks", () => {
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
  renderEntrypointDisassembly(pe, out);
  const html = out.join("");

  assert.ok(html.includes("return followed"));
  assert.ok(html.includes("0x00001005"));
  assert.ok(html.includes("Followed return target from 0x00001010"));
});

void test("renderEntrypointDisassembly renders entrypoint notes column", () => {
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
  renderEntrypointDisassembly(pe, out);
  const html = out.join("");

  assert.ok(html.includes("<th>Notes</th>"));
  assert.ok(!html.includes("<th>Target</th>"));
  assert.ok(html.includes("MSVC-compatible x86 /GS default security cookie"));
});

void test("renderEntrypointDisassembly hides diagnostics after instruction tables", () => {
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
        text: "call 0000000140001010h",
        target: { kind: "code", rva: 0x1010, followed: true }
      }]
    }],
    issues: ["Entrypoint preview followed call target."]
  };

  const out: string[] = [];
  renderEntrypointDisassembly(pe, out);
  const html = out.join("");

  assert.ok(html.includes("<table"));
  assert.ok(!html.includes("Entrypoint preview followed call target."));
});
void test("renderEntrypointDisassembly keeps diagnostics when no table was rendered", () => {
  const pe = createPe();
  pe.entrypointDisassembly = {
    bitness: 64,
    entrypointRva: 0x1000,
    bytesDecoded: 0,
    instructionCount: 0,
    blocks: [],
    issues: ["Failed to load iced-x86 disassembler."]
  };

  const out: string[] = [];
  renderEntrypointDisassembly(pe, out);
  const html = out.join("");

  assert.ok(!html.includes("<table"));
  assert.ok(html.includes("Failed to load iced-x86 disassembler."));
});

void test("renderEntrypointDisassembly merges identical blocks", () => {
  const pe = createPe();
  pe.entrypointDisassembly = {
    bitness: 64,
    entrypointRva: 0x1000,
    bytesDecoded: 2,
    instructionCount: 2,
    blocks: [
      {
        kind: "followed-call",
        startRva: 0x1010,
        fileOffsetStart: 0x210,
        sourceInstructionRva: 0x1000,
        instructions: [{ rva: 0x1010, fileOffset: 0x210, text: "ret" }]
      },
      {
        kind: "followed-call",
        startRva: 0x1010,
        fileOffsetStart: 0x210,
        sourceInstructionRva: 0x1006,
        instructions: [{ rva: 0x1010, fileOffset: 0x210, text: "ret" }]
      }
    ],
    issues: []
  };

  const out: string[] = [];
  renderEntrypointDisassembly(pe, out);
  const html = out.join("");

  assert.equal((html.match(/<table/g) ?? []).length, 1);
  assert.ok(html.includes("from 0x00001000, 0x00001006"));
  assert.ok(html.includes("1 duplicate context(s) merged"));
});

void test("renderEntrypointDisassembly merges blocks with only follow-status differences", () => {
  const pe = createPe();
  pe.entrypointDisassembly = {
    bitness: 64,
    entrypointRva: 0x1000,
    bytesDecoded: 4,
    instructionCount: 4,
    blocks: [
      {
        kind: "followed-call",
        startRva: 0x1010,
        fileOffsetStart: 0x210,
        sourceInstructionRva: 0x1000,
        instructions: [{
          rva: 0x1010,
          fileOffset: 0x210,
          text: "jne short 0000000140001020h",
          target: {
            kind: "branch",
            branchRva: 0x1020,
            branchFollowed: true,
            fallthroughRva: 0x1012,
            fallthroughFollowed: false
          }
        }]
      },
      {
        kind: "followed-call",
        startRva: 0x1010,
        fileOffsetStart: 0x210,
        sourceInstructionRva: 0x1000,
        instructions: [{
          rva: 0x1010,
          fileOffset: 0x210,
          text: "jne short 0000000140001020h",
          target: {
            kind: "branch",
            branchRva: 0x1020,
            branchFollowed: false,
            fallthroughRva: 0x1012,
            fallthroughFollowed: false
          }
        }]
      }
    ],
    issues: []
  };

  const out: string[] = [];
  renderEntrypointDisassembly(pe, out);
  const html = out.join("");

  assert.equal((html.match(/<table/g) ?? []).length, 1);
  assert.ok(html.includes("1 duplicate context(s) merged"));
});

"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import { renderEntrypointDisassembly } from "../../../../renderers/pe/entrypoint-disassembly.js";

const createPe = (): PeWindowsParseResult =>
  ({
    coff: { Machine: 0x8664 },
    opt: { AddressOfEntryPoint: 0x1000 },
    sections: []
  }) as unknown as PeWindowsParseResult;

void test("renderEntrypointDisassembly paginates large block indexes", () => {
  const pe = createPe();
  pe.entrypointDisassembly = {
    bitness: 64,
    entrypointRva: 0x1000,
    bytesDecoded: 51,
    instructionCount: 51,
    blocks: Array.from({ length: 51 }, (_value, index) => ({
      kind: index === 0 ? "entrypoint" : "followed-call",
      startRva: 0x1000 + index * 0x10,
      fileOffsetStart: 0x200 + index * 0x10,
      ...(index === 0 ? {} : { sourceInstructionRva: 0x1000 }),
      instructions: [{ rva: 0x1000 + index * 0x10, fileOffset: 0x200 + index, text: "ret" }]
    })),
    issues: []
  };

  const out: string[] = [];
  renderEntrypointDisassembly(pe, out);
  const html = out.join("");

  assert.ok(html.includes("Blocks 1-50 of 51"));
  assert.ok(html.includes("0x00001310"));
  assert.ok(!html.includes("0x00001320"));
});

void test("renderEntrypointDisassembly paginates long selected blocks", () => {
  const pe = createPe();
  pe.entrypointDisassembly = {
    bitness: 64,
    entrypointRva: 0x1000,
    bytesDecoded: 121,
    instructionCount: 121,
    blocks: [{
      kind: "entrypoint",
      startRva: 0x1000,
      fileOffsetStart: 0x200,
      instructions: Array.from({ length: 121 }, (_value, index) => ({
        rva: 0x1000 + index,
        fileOffset: 0x200 + index,
        text: index === 120 ? "ret" : "nop"
      }))
    }],
    issues: []
  };

  const out: string[] = [];
  renderEntrypointDisassembly(pe, out);
  const html = out.join("");

  assert.ok(html.includes("Instructions 1-120 of 121"));
  assert.ok(html.includes(`data-pe-entrypoint-rva="4215"`));
  assert.ok(!html.includes(`data-pe-entrypoint-rva="4216"`));
});

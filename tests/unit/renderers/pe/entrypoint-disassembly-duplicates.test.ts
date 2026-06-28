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

  assert.equal((html.match(/peEntrypointInstructionTable/g) ?? []).length, 1);
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

  assert.equal((html.match(/peEntrypointInstructionTable/g) ?? []).length, 1);
  assert.ok(html.includes("1 duplicate context(s) merged"));
});

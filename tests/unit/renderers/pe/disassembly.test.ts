"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderInstructionSets } from "../../../../renderers/pe/disassembly.js";
import { renderEntrypointDisassembly } from "../../../../renderers/pe/entrypoint-disassembly.js";
import type { PeWindowsParseResult } from "../../../../analyzers/pe/index.js";
import { inlinePeSectionName } from "../../../../analyzers/pe/sections/name.js";

const STRING_RVA = 0x3000;
const CALL_RVA = 0x1010;

const createPe = (overrides: Partial<PeWindowsParseResult> = {}): PeWindowsParseResult =>
  ({
    coff: { Machine: 0x8664 },
    opt: { AddressOfEntryPoint: 0x1000 },
    sections: [],
    ...overrides
  }) as unknown as PeWindowsParseResult;

void test("renderInstructionSets renders a chip table", () => {
  const pe = createPe();
  pe.disassembly = {
    bitness: 64,
    bytesSampled: 10,
    bytesDecoded: 6,
    instructionCount: 2,
    invalidInstructionCount: 0,
    directIatReferences: [],
    apiStringReferences: [],
    issues: [],
    instructionSets: [
      { id: "AVX", label: "AVX", description: "Advanced Vector Extensions", instructionCount: 1 }
    ]
  };

  const out: string[] = [];
  renderInstructionSets(pe, out);
  const html = out.join("");

  assert.ok(html.includes("Instruction-set analysis"));
  assert.ok(html.includes(`class="analysisPanel"`));
  assert.ok(html.includes(`class="analysisPanelSummary"`));
  assert.ok(html.includes("not a PE file section"));
  assert.ok(html.includes("not a full disassembly"));
  assert.ok(html.includes("6 B (6 bytes) / 10 B (10 bytes)"));
  assert.ok(html.includes("CpuidFeature.AVX"));
  assert.ok(html.includes(">AVX<"));
  assert.ok(html.includes("CpuidFeature.SSE2"));
  assert.ok(!html.includes("peEntrypointDisassembleButton"));
});

void test("renderInstructionSets escapes user-controlled strings", () => {
  const pe = createPe();
  pe.disassembly = {
    bitness: 32,
    bytesSampled: 1,
    bytesDecoded: 1,
    instructionCount: 1,
    invalidInstructionCount: 0,
    directIatReferences: [],
    apiStringReferences: [],
    issues: ["note <b>unsafe</b>"],
    instructionSets: [
      {
        id: "WEIRD_FEATURE",
        label: "<b>WEIRD</b>",
        description: "<script>alert(1)</script>",
        instructionCount: 1
      }
    ]
  };
  const out: string[] = [];
  renderInstructionSets(pe, out);
  const html = out.join("");

  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;script>alert(1)&lt;/script>"));
  assert.ok(html.includes("&lt;b>WEIRD&lt;/b>"));
  assert.ok(html.includes("note &lt;b>unsafe&lt;/b>"));
});

void test("renderEntrypointDisassembly separates followed entrypoint blocks", () => {
  const pe = createPe();
  pe.entrypointDisassembly = {
    bitness: 64,
    entrypointRva: 0x1000,
    bytesDecoded: 2,
    instructionCount: 2,
    blocks: [
      {
        kind: "entrypoint",
        startRva: 0x1000,
        fileOffsetStart: 0x200,
        instructions: [{
          rva: 0x1000,
          fileOffset: 0x200,
          text: "call 0000000140001010h",
          target: { kind: "code", rva: 0x1010, followed: true }
        }]
      },
      {
        kind: "followed-call",
        startRva: 0x1010,
        fileOffsetStart: 0x210,
        sourceInstructionRva: 0x1000,
        instructions: [{ rva: 0x1010, fileOffset: 0x210, text: "ret" }]
      }
    ],
    issues: []
  };

  const out: string[] = [];
  renderEntrypointDisassembly(pe, out);
  const html = out.join("");

  assert.ok(html.includes("Entry point"));
  assert.ok(html.includes("Followed call target from 0x00001000"));
  assert.ok(html.includes("followed"));
  assert.ok(html.includes("0x00001010"));
});

void test("renderEntrypointDisassembly labels followed conditional branch blocks", () => {
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
          text: "je short 0000000140001004h",
          target: {
            kind: "branch",
            branchRva: 0x1004,
            branchFollowed: true,
            fallthroughRva: 0x1002,
            fallthroughFollowed: true
          }
        }]
      },
      {
        kind: "followed-branch",
        startRva: 0x1004,
        fileOffsetStart: 0x204,
        sourceInstructionRva: 0x1000,
        instructions: [{ rva: 0x1004, fileOffset: 0x204, text: "xor eax,eax" }]
      },
      {
        kind: "followed-fallthrough",
        startRva: 0x1002,
        fileOffsetStart: 0x202,
        sourceInstructionRva: 0x1000,
        instructions: [{ rva: 0x1002, fileOffset: 0x202, text: "ret" }]
      }
    ],
    issues: []
  };

  const out: string[] = [];
  renderEntrypointDisassembly(pe, out);
  const html = out.join("");

  assert.ok(html.includes("branch followed"));
  assert.ok(html.includes("fallthrough followed"));
  assert.ok(html.includes("0x00001004"));
  assert.ok(html.includes("0x00001002"));
  assert.ok(html.includes("Followed conditional branch target from 0x00001000"));
  assert.ok(html.includes("Followed conditional fallthrough from 0x00001000"));
});

void test("renderInstructionSets renders an empty-state message", () => {
  const pe = createPe();
  pe.disassembly = {
    bitness: 64,
    bytesSampled: 0,
    bytesDecoded: 0,
    instructionCount: 0,
    invalidInstructionCount: 0,
    directIatReferences: [],
    apiStringReferences: [],
    issues: [],
    instructionSets: []
  };

  const out: string[] = [];
  renderInstructionSets(pe, out);
  const html = out.join("");

  assert.ok(html.includes("No instruction-set requirements were detected"));
  assert.ok(html.includes("CpuidFeature.SSE"));
});

void test("renderInstructionSets renders API string references", () => {
  const pe = createPe({
    sections: [{
      name: inlinePeSectionName(".rdata"),
      virtualAddress: STRING_RVA,
      virtualSize: 0x80,
      sizeOfRawData: 0x80,
      pointerToRawData: 0x200,
      characteristics: 0
    }]
  });
  pe.disassembly = {
    bitness: 64,
    bytesSampled: 4,
    bytesDecoded: 4,
    instructionCount: 2,
    invalidInstructionCount: 0,
    directIatReferences: [],
    apiStringReferences: [{
      rva: STRING_RVA,
      encoding: "ascii",
      byteLength: 12,
      text: `<tag "value"`,
      callSites: [{
        instructionRva: CALL_RVA,
        module: "ucrtbase.dll",
        entrypoint: "fopen",
        sourceKind: "ucrt",
        parameterIndex: 0,
        parameterName: "_FileName"
      }]
    }],
    issues: [],
    instructionSets: []
  };

  const out: string[] = [];
  renderInstructionSets(pe, out);
  const html = out.join("");

  assert.ok(html.includes("WinAPI/UCRT string arguments (1)"));
  assert.ok(html.includes(".rdata"));
  assert.ok(html.includes("UCRT ucrtbase.dll!fopen _FileName @ 0x00001010"));
  assert.ok(html.includes("&lt;tag &quot;value&quot;"));
});

void test("renderInstructionSets renders a progress placeholder before analysis", () => {
  const out: string[] = [];
  renderInstructionSets(createPe(), out);
  const html = out.join("");

  assert.ok(html.includes("peInstructionSetsAnalyzeButton"));
  assert.ok(html.includes("peInstructionSetsCancelButton"));
  assert.ok(html.includes("peInstructionSetsProgress"));
  assert.ok(html.includes("peInstructionSetsProgressText"));
  assert.ok(html.includes("peInstructionSetChip_SSE"));
  assert.ok(html.includes("peInstructionSetCount_SSE"));
});

void test("renderEntrypointDisassembly hides entrypoint button when AddressOfEntryPoint is absent", () => {
  const out: string[] = [];
  renderEntrypointDisassembly(createPe({ opt: { AddressOfEntryPoint: 0 } } as Partial<PeWindowsParseResult>), out);

  assert.ok(!out.join("").includes("peEntrypointDisassembleButton"));
});

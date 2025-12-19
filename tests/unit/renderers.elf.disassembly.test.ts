"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderInstructionSets } from "../../renderers/elf/disassembly.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";

void test("renderInstructionSets (ELF) renders a chip table", () => {
  const elf = {
    disassembly: {
      bitness: 64,
      bytesSampled: 10,
      bytesDecoded: 6,
      instructionCount: 2,
      invalidInstructionCount: 0,
      issues: [],
      instructionSets: [{ id: "AVX", label: "AVX", description: "Advanced Vector Extensions", instructionCount: 1 }]
    }
  } as unknown as ElfParseResult;

  const out: string[] = [];
  renderInstructionSets(elf, out);
  const html = out.join("");

  assert.ok(html.includes("Instruction sets"));
  assert.ok(html.includes("not a full disassembly"));
  assert.ok(html.includes("CpuidFeature.AVX"));
  assert.ok(html.includes(">AVX<"));
  assert.ok(html.includes("CpuidFeature.SSE2"));
});

void test("renderInstructionSets (ELF) renders a seed summary and escapes sources", () => {
  const elf = {
    disassembly: {
      bitness: 64,
      bytesSampled: 10,
      bytesDecoded: 6,
      instructionCount: 2,
      invalidInstructionCount: 0,
      issues: [],
      instructionSets: [],
      seedSummary: {
        entrypointVaddr: 0x401000n,
        uniqueEntrypoints: 3,
        fallbackSource: "Segment #0 (PT_LOAD + PF_X)",
        sources: [
          {
            source: "ELF header entry point",
            candidates: 1,
            added: 1,
            skippedZero: 0,
            skippedNotExecutable: 0,
            skippedDuplicate: 0
          },
          {
            source: "<b>DT_INIT_ARRAY</b>",
            candidates: 2,
            added: 1,
            skippedZero: 0,
            skippedNotExecutable: 1,
            skippedDuplicate: 0
          }
        ]
      }
    }
  } as unknown as ElfParseResult;

  const out: string[] = [];
  renderInstructionSets(elf, out);
  const html = out.join("");

  assert.ok(html.includes("Seeds (3 unique entrypoint(s))"));
  assert.ok(html.includes("Entry point: 0x401000"));
  assert.ok(html.includes("fallback: Segment #0 (PT_LOAD + PF_X)"));
  assert.ok(html.includes("&lt;b>DT_INIT_ARRAY&lt;/b>"));
  assert.ok(!html.includes("<b>DT_INIT_ARRAY</b>"));
});

void test("renderInstructionSets (ELF) escapes user-controlled strings", () => {
  const elf = {
    disassembly: {
      bitness: 32,
      bytesSampled: 1,
      bytesDecoded: 1,
      instructionCount: 1,
      invalidInstructionCount: 0,
      issues: ["note <b>unsafe</b>"],
      instructionSets: [
        {
          id: "WEIRD_FEATURE",
          label: "<b>WEIRD</b>",
          description: "<script>alert(1)</script>",
          instructionCount: 1
        }
      ]
    }
  } as unknown as ElfParseResult;

  const out: string[] = [];
  renderInstructionSets(elf, out);
  const html = out.join("");

  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;script>alert(1)&lt;/script>"));
  assert.ok(html.includes("&lt;b>WEIRD&lt;/b>"));
  assert.ok(html.includes("note &lt;b>unsafe&lt;/b>"));
});

void test("renderInstructionSets (ELF) renders an empty-state message", () => {
  const elf = {
    disassembly: {
      bitness: 64,
      bytesSampled: 0,
      bytesDecoded: 0,
      instructionCount: 0,
      invalidInstructionCount: 0,
      issues: [],
      instructionSets: []
    }
  } as unknown as ElfParseResult;

  const out: string[] = [];
  renderInstructionSets(elf, out);
  const html = out.join("");

  assert.ok(html.includes("No instruction-set requirements were detected"));
  assert.ok(html.includes("CpuidFeature.SSE"));
});

void test("renderInstructionSets (ELF) renders a progress placeholder before analysis", () => {
  const elf = {} as unknown as ElfParseResult;
  const out: string[] = [];
  renderInstructionSets(elf, out);
  const html = out.join("");

  assert.ok(html.includes("elfInstructionSetsAnalyzeButton"));
  assert.ok(html.includes("elfInstructionSetsCancelButton"));
  assert.ok(html.includes("elfInstructionSetsProgress"));
  assert.ok(html.includes("elfInstructionSetsProgressText"));
  assert.ok(html.includes("elfInstructionSetChip_SSE"));
  assert.ok(html.includes("elfInstructionSetCount_SSE"));
});

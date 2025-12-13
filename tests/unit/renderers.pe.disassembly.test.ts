"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderInstructionSets } from "../../renderers/pe/disassembly.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

void test("renderInstructionSets renders a chip table", () => {
  const pe = {
    disassembly: {
      bitness: 64,
      bytesSampled: 10,
      bytesDecoded: 6,
      instructionCount: 2,
      invalidInstructionCount: 0,
      issues: [],
      instructionSets: [
        { id: "AVX", label: "AVX", description: "Advanced Vector Extensions", instructionCount: 1 }
      ]
    }
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderInstructionSets(pe, out);
  const html = out.join("");

  assert.ok(html.includes("Instruction sets"));
  assert.ok(html.includes("CpuidFeature.AVX"));
  assert.ok(html.includes(">AVX<"));
  assert.ok(html.includes("CpuidFeature.SSE2"));
});

void test("renderInstructionSets escapes user-controlled strings", () => {
  const pe = {
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
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderInstructionSets(pe, out);
  const html = out.join("");

  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;script>alert(1)&lt;/script>"));
  assert.ok(html.includes("&lt;b>WEIRD&lt;/b>"));
  assert.ok(html.includes("note &lt;b>unsafe&lt;/b>"));
});

void test("renderInstructionSets renders an empty-state message", () => {
  const pe = {
    disassembly: {
      bitness: 64,
      bytesSampled: 0,
      bytesDecoded: 0,
      instructionCount: 0,
      invalidInstructionCount: 0,
      issues: [],
      instructionSets: []
    }
  } as unknown as PeParseResult;

  const out: string[] = [];
  renderInstructionSets(pe, out);
  const html = out.join("");

  assert.ok(html.includes("No instruction-set requirements were detected"));
  assert.ok(html.includes("CpuidFeature.SSE"));
});

void test("renderInstructionSets renders a progress placeholder before analysis", () => {
  const pe = {} as unknown as PeParseResult;
  const out: string[] = [];
  renderInstructionSets(pe, out);
  const html = out.join("");

  assert.ok(html.includes("peInstructionSetsAnalyzeButton"));
  assert.ok(html.includes("peInstructionSetsCancelButton"));
  assert.ok(html.includes("peInstructionSetsProgress"));
  assert.ok(html.includes("peInstructionSetsProgressText"));
  assert.ok(html.includes("peInstructionSetChip_SSE"));
  assert.ok(html.includes("peInstructionSetCount_SSE"));
});

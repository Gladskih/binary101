"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderInstructionSets } from "../../renderers/pe/disassembly.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

void test("renderInstructionSets renders a chip table", () => {
  const pe = {
    disassembly: {
      bitness: 64,
      bytesAnalyzed: 10,
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
  assert.ok(html.includes("Advanced Vector Extensions"));
});

void test("renderInstructionSets escapes user-controlled strings", () => {
  const pe = {
    disassembly: {
      bitness: 32,
      bytesAnalyzed: 1,
      instructionCount: 1,
      invalidInstructionCount: 0,
      issues: ["note <b>unsafe</b>"],
      instructionSets: [
        {
          id: "AVX",
          label: "<b>AVX</b>",
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
  assert.ok(html.includes("&lt;b>AVX&lt;/b>"));
  assert.ok(html.includes("note &lt;b>unsafe&lt;/b>"));
});

void test("renderInstructionSets renders an empty-state message", () => {
  const pe = {
    disassembly: {
      bitness: 64,
      bytesAnalyzed: 0,
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
});

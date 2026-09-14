import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPeAarch64InstructionSets } from "../../../../renderers/pe/disassembly-aarch64.js";
import type { PeInstructionSetReport } from "../../../../analyzers/pe/disassembly/types.js";
import { renderInstructionSetsPanel } from "../../../../renderers/pe/disassembly.js";
import type { PeWindowsParseResult } from "../../../../analyzers/pe/index.js";

const report = (): PeInstructionSetReport => ({
  bitness: 64, instructionCount: 1, bytesDecoded: 4, bytesSampled: 8,
  invalidInstructionCount: 1, instructionSets: [], issues: [],
  directIatReferences: [], codeStringReferences: [], apiStringReferences: [], specialInstructions: []
});

void test("ARM64 pending panel provides analysis, cancellation and progress controls", () => {
  const html = renderPeAarch64InstructionSets();

  assert.ok(html.includes("Not analyzed yet."));
  assert.ok(html.includes("peInstructionSetsAnalyzeButton"));
  assert.ok(html.includes("peInstructionSetsCancelButton"));
  assert.ok(html.includes("peInstructionSetsProgressText"));
  assert.ok(html.includes('id="peInstructionSetsProgress"'));
  assert.ok(!html.includes("CpuidFeature"));
  assert.ok(!html.includes("FEAT_AdvSIMD"));
});

void test("ARM64 result escapes requirements, decoder version and issues", () => {
  const html = renderPeAarch64InstructionSets({ ...report(), decoderVersion: "LLVM <version>",
    issues: ["<bad>"], instructionSets: [{ id: "test", label: "SVE or <SME>",
      description: "", instructionCount: 1 }] });

  assert.ok(html.includes("Re-analyze instruction sets"));
  assert.ok(html.includes("1 instruction(s) decoded from 4 B (4 bytes) / 8 B (8 bytes)"));
  assert.ok(html.includes("Invalid decodes: 1"));
  assert.ok(html.includes("LLVM &lt;version>"));
  assert.ok(html.includes("&lt;bad>"));
  assert.ok(html.includes("SVE or &lt;SME>"));
  assert.ok(html.includes('<td class="isaTable__count">1</td>'));
  assert.ok(!html.includes("<bad>"));
  assert.ok(html.includes('<div class="smallNote dim">LLVM &lt;version></div>'));
  assert.ok(html.includes("<ul><li>&lt;bad></li></ul>"));
  assert.ok(html.includes('<div class="tableWrap"><table class="table aarch64IsaTable"><thead><tr>'));
  assert.ok(html.includes('<th>Requirement</th><th class="isaTable__count">Instr.</th>'));
  assert.ok(html.includes("</tr></thead><tbody><tr><td>SVE or &lt;SME></td>"));
  assert.ok(html.includes("</tbody></table></div>"));
});

void test("PE ARM64 dispatch shows ISA requirements without x86 feature chips", () => {
  // Microsoft PE/COFF Machine Types: ARM64 = 0xaa64.
  const pe = { coff: { Machine: 0xaa64 } } as PeWindowsParseResult;
  const html = renderInstructionSetsPanel(pe);

  assert.ok(html.includes("AArch64 instruction-set requirements"));
  assert.ok(html.includes("peInstructionSetsPanel"));
  assert.ok(!html.includes("CpuidFeature"));
  assert.ok(!html.includes("imports and strings"));
});

void test("ARM64 empty result has no table or empty issues list", () => {
  const html = renderPeAarch64InstructionSets(report());

  assert.ok(html.includes("No instruction-set requirements were detected"));
  assert.ok(!html.includes("<table"));
  assert.ok(!html.includes("<ul>"));
  assert.ok(!html.includes("Stryker was here!"));
});

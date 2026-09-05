import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSpecialInstructions } from
  "../../../../renderers/pe/disassembly-special-instructions.js";

void test("renders an empty sample explicitly", () => {
  assert.match(renderSpecialInstructions([]), /None detected in the sampled code/);
  assert.doesNotMatch(renderSpecialInstructions([]), /<table/);
});

void test("renders categories, counts and escaped instruction names", () => {
  const html = renderSpecialInstructions([
    { category: "syscall", instruction: "SYSCALL", count: 9 },
    { category: "privileged", instruction: "<HLT>", count: 1 },
    { category: "io-privilege", instruction: "CLI", count: 1 },
    { category: "trap", instruction: "INT3", count: 1 }
  ]);
  assert.match(html, /Direct syscall/);
  assert.match(html, /Kernel privilege/);
  assert.match(html, /I\/O privilege/);
  assert.match(html, /Trap/);
  assert.match(html, /&lt;HLT/);
  assert.doesNotMatch(html, /<HLT>/);
  assert.match(html, />9<\/td>/);
  assert.doesNotMatch(html, /RVA/);
  assert.match(html, /not execution frequency/);
  assert.match(html, /<h4>Special instructions<\/h4>/);
  assert.match(html, /<div class="tableWrap"><table class="table"><thead><tr>/);
  assert.match(html, /<th>Category<\/th><th>Instruction<\/th>/);
  assert.match(html, /<th style="text-align:right">Sites<\/th><\/tr><\/thead><tbody>/);
  assert.match(html, /<td style="text-align:right">9<\/td><\/tr>/);
  assert.match(html, /<\/tbody><\/table><\/div>$/);
  assert.match(html, /Kernel-entry instruction/);
  assert.match(html, /administrator rights alone do not suffice/);
  assert.match(html, /I\/O permissions/);
  assert.match(html, /not evidence of malicious code/);
  assert.match(html, /Unvisited code may contain additional sites/);
});

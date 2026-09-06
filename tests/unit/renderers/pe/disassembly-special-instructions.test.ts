import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSpecialInstructions } from
  "../../../../renderers/pe/disassembly-special-instructions.js";

void test("renders an empty sample explicitly", () => {
  assert.match(renderSpecialInstructions([]), /None detected in the sampled code/);
  assert.doesNotMatch(renderSpecialInstructions([]), /<table/);
});

void test("explains instructions and categories with keyboard-accessible disclosures", () => {
  const html = renderSpecialInstructions([
    { categories: ["syscall"], instruction: "SYSCALL", count: 9, sampleRvas: [0x1000, 0x1002] },
    { categories: ["virtualization", "privileged"], instruction: "VMXON", count: 1, sampleRvas: [] },
    { categories: ["io-privilege"], instruction: "CLI", count: 1, sampleRvas: [] },
    { categories: ["trap"], instruction: "INT 0x80", count: 1, sampleRvas: [] }
  ]);
  assert.match(html, /<details><summary>Direct syscall<\/summary>/);
  assert.match(html, /<details><summary>SYSCALL<\/summary>/);
  assert.match(html, /inspect registers to identify the service/);
  assert.match(html, /Enters Intel VMX operation/);
  assert.match(html, /administrator rights alone do not suffice/);
  assert.match(html, /I\/O permissions/);
  assert.match(html, /Invokes a software interrupt vector/);
  assert.match(html, /not evidence of malicious code/);
  assert.match(html, /<td style="text-align:right">9<\/td>/);
  assert.match(html, /data-pe-special-rva="4096"/);
  assert.match(html, /aria-label="Disassemble at RVA 0x00001000"/);
  assert.match(html, /Unavailable/);
  assert.match(html, /not execution frequency/);
  assert.match(html, /Counts are decoded instruction sites/);
  assert.match(html, /Unvisited code may contain additional sites/);
  assert.match(html, /up to three locations/);
  assert.match(html, /<th>Example RVAs<\/th>/);
  assert.match(html, /Intel SDM/);
  assert.match(html, /Instruction reference:/);
  assert.match(html, /AMD APM/);
  assert.match(html, /<h4>Special instructions<\/h4>/);
  assert.match(html, /<th>Category<\/th><th>Instruction<\/th>/);
  assert.match(html, /<th style="text-align:right">Sites<\/th>/);
  assert.match(html, /<div class="tableWrap"><table class="table"><thead><tr>/);
  assert.match(html, /<\/tr><\/thead><tbody><tr><td>/);
  assert.match(html, /<\/tbody><\/table><\/div>$/);
  assert.match(html, /<\/button> <button/);
  assert.match(html, /Expand a category or instruction for an explanation/);
  assert.match(html, /href="https:\/\/www.intel.com\/content\/www\/us\/en\/developer\/articles\/technical\/intel-sdm.html"/);
  assert.match(html, /href="https:\/\/docs.amd.com\/v\/u\/en-US\/24594_3.37"/);
  assert.match(html, /<\/details><details><summary>Kernel privilege/);
  assert.match(html, /<\/td><\/tr><tr><td>/);
});

void test("escapes unrecognized instruction text and explains the privilege fallback", () => {
  const html = renderSpecialInstructions([
    { categories: ["privileged"], instruction: "<HLT>", count: 1, sampleRvas: [] }
  ]);
  assert.match(html, /&lt;HLT>/);
  assert.doesNotMatch(html, /<HLT>/);
  assert.match(html, /A privileged processor operation/);
});

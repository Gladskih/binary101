"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDynamicRelocationDetails } from
  "../../../../renderers/pe/dynamic-relocation-details.js";

void test("renders Guard RF header fields and relocation sites", () => {
  const html = renderDynamicRelocationDetails([{ kind: "v2", symbol: 2n,
    headerSize: 32, fixupInfoSize: 10, symbolGroup: 0, flags: 0, availableBytes: 10,
    guardRf: { kind: "epilogue", epilogueCount: 2, epilogueByteCount: 5,
      branchDescriptorElementSize: 1, branchDescriptors: [[0xaa]],
      branchDescriptorBitmap: [0x01], sites: [{ rva: 0x1234, type: 0 }] } }]);

  assert.match(html, /Guard RF epilogue/);
  assert.match(html, /Epilogue count.*2/);
  assert.match(html, /aa/);
  assert.match(html, /0x00001234/);
});

void test("renders ARM64X fixup values and signed deltas", () => {
  const html = renderDynamicRelocationDetails([{ kind: "v1", symbol: 6n,
    baseRelocSize: 12, availableBytes: 12, arm64xFixups: [
      { kind: "value", rva: 0x2340, size: 2, value: 0xbeefn },
      { kind: "delta", rva: 0x2344, size: 4, delta: -12 }
    ] }]);

  assert.match(html, /ARM64X fixups/);
  assert.match(html, /0x00002340/);
  assert.match(html, /0xbeef/);
  assert.match(html, /-12/);
});

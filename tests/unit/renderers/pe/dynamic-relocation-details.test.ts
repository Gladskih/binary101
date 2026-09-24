"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDynamicRelocationDetails } from
  "../../../../renderers/pe/dynamic-relocation-details.js";

void test("renders Guard RF header fields and relocation sites", () => {
  const html = renderDynamicRelocationDetails([{ kind: "v2", symbol: 2n,
    headerSize: 32, fixupInfoSize: 10, symbolGroup: 0, flags: 0, availableBytes: 10,
    guardRf: { kind: "epilogue", epilogueCount: 2, epilogueByteCount: 5,
      branchDescriptorElementSize: 1, branchDescriptors: [[0xaa], [0xbb]],
      branchDescriptorBitmap: [0x01], sites: [{ rva: 0x1234, type: 0 }] } }]);

  assert.equal(html, [
    `<section class="loadConfigDynamicDetail"><h4>Guard RF epilogue</h4>`,
    `<p>Epilogue count: 2; epilogue byte count: 5; `,
    `branch descriptor element size: 1; branch descriptor count: 2; `,
    `branch descriptors: aa | bb; branch descriptor bitmap: 01</p>`,
    `<p>Bitmap bytes are shown raw; the Windows SDK header does not define their bits.</p>`,
    `<p>Relocation sites: 1</p><div class="tableWrap"><table class="table">`,
    `<thead><tr><th scope="col">RVA</th><th scope="col" class="num">Type</th></tr></thead>`,
    `<tbody><tr><td>0x00001234</td><td class="num">0</td></tr></tbody>`,
    `</table></div></section>`
  ].join(""));
});

void test("renders ARM64X fixup values and signed deltas", () => {
  const html = renderDynamicRelocationDetails([{ kind: "v1", symbol: 6n,
    baseRelocSize: 12, availableBytes: 12, arm64xFixups: [
      { kind: "value", rva: 0x2340, size: 2, value: 0xbeefn },
      { kind: "delta", rva: 0x2344, delta: -12 }
    ] }]);

  assert.equal(html, [
    `<section class="loadConfigDynamicDetail"><h4>ARM64X fixups</h4>`,
    `<p>Decoded records: 2</p><div class="tableWrap"><table class="table">`,
    `<thead><tr><th scope="col">RVA</th><th scope="col">Type</th>`,
    `<th scope="col" class="num">Size</th>`,
    `<th scope="col" class="num">Value / delta</th></tr></thead><tbody>`,
    `<tr><td>0x00002340</td><td>value</td><td class="num">2</td>`,
    `<td class="num">0xbeef</td></tr>`,
    `<tr><td>0x00002344</td><td>delta</td><td class="num">4</td>`,
    `<td class="num">-12</td></tr></tbody></table></div></section>`
  ].join(""));
});

void test("renders records without optional Guard RF headers or fixups", () => {
  const html = renderDynamicRelocationDetails([
    { kind: "v1", symbol: 1n, baseRelocSize: 0, availableBytes: 0,
      guardRf: { kind: "prologue", sites: [] } },
    { kind: "v1", symbol: 2n, baseRelocSize: 0, availableBytes: 0,
      guardRf: { kind: "epilogue", sites: [] } },
    { kind: "v1", symbol: 6n, baseRelocSize: 0, availableBytes: 0,
      arm64xFixups: [] }
  ]);

  assert.match(html, /Guard RF prologue/);
  assert.match(html, /Guard RF epilogue/);
  assert.match(html, /Decoded records: 0/);
  assert.match(html, /Guard RF prologue<\/h4><p>Relocation sites: 0<\/p><\/section>/);
  assert.match(html, /Guard RF epilogue<\/h4><p>Relocation sites: 0<\/p><\/section>/);
  assert.match(html, /Decoded records: 0<\/p><\/section>/);
  assert.match(html, /<\/section><section class="loadConfigDynamicDetail">/);
  assert.doesNotMatch(html, /<table/);
});

void test("caps rendered Guard RF sites and ARM64X records", () => {
  const sites = Array.from({ length: 513 }, (_, index) => ({ rva: index, type: 0 }));
  const fixups = Array.from({ length: 513 }, (_, index) =>
    ({ kind: "zeroFill" as const, rva: index, size: 1 }));
  const html = renderDynamicRelocationDetails([
    { kind: "v1", symbol: 1n, baseRelocSize: 0, availableBytes: 0,
      guardRf: { kind: "prologue", sites } },
    { kind: "v1", symbol: 6n, baseRelocSize: 0, availableBytes: 0, arm64xFixups: fixups }
  ]);

  assert.equal((html.match(/showing first 512, 1 hidden/g) ?? []).length, 2);
  assert.equal((html.match(/<tr>/g) ?? []).length, 1026); // 512 body and one header per table.
});

void test("renders empty byte sequences explicitly", () => {
  const html = renderDynamicRelocationDetails([
    { kind: "v1", symbol: 1n, baseRelocSize: 0, availableBytes: 0,
      guardRf: { kind: "prologue", prologueBytes: [], sites: [] } },
    { kind: "v1", symbol: 2n, baseRelocSize: 0, availableBytes: 0,
      guardRf: { kind: "epilogue", epilogueCount: 0, epilogueByteCount: 0,
        branchDescriptorElementSize: 0, branchDescriptors: [],
        branchDescriptorBitmap: [], sites: [] } }
  ]);

  assert.match(html, /Prologue bytes: -/);
  assert.match(html, /branch descriptors: -; branch descriptor bitmap: -/);
});

void test("renders prologue byte order, adjacent rows and zero-fill values", () => {
  const html = renderDynamicRelocationDetails([
    { kind: "v1", symbol: 1n, baseRelocSize: 0, availableBytes: 0,
      guardRf: { kind: "prologue", prologueBytes: [0x90, 0xcc],
        sites: [{ rva: 0x1000, type: 0 }, { rva: 0x1002, type: 0 }] } },
    { kind: "v1", symbol: 6n, baseRelocSize: 0, availableBytes: 0,
      arm64xFixups: [{ kind: "zeroFill", rva: 0x2000, size: 4 }] }
  ]);

  assert.match(html, /Prologue bytes: 90 cc/);
  assert.match(html, /0x00001000.*<\/tr><tr><td>0x00001002/);
  assert.match(html, /0x00002000<\/td><td>zeroFill<\/td><td class="num">4<\/td>/);
  assert.match(html, /<td class="num">-<\/td>/);
  assert.match(html, /<\/section><section class="loadConfigDynamicDetail">/);
});

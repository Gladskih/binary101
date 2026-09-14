import assert from "node:assert/strict";
import { test } from "node:test";
import { renderElfLsda } from "../../../../renderers/elf/lsda.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";
import { lsdaFixture } from "../../../fixtures/elf-lsda.js";
import type { ElfLsda } from "../../../../analyzers/elf/lsda-types.js";

const render = (lsdas?: ElfLsda[]): string => {
  const elf = relocationFixture().elf;
  if (lsdas) elf.lsdas = lsdas;
  const out: string[] = [];
  renderElfLsda(elf, out);
  return out.join("");
};

const populatedDescriptor = (): ElfLsda => ({
  ...lsdaFixture([]).result,
  // LLVM libcxxabi: zero landing pad means no handler; zero action with a
  // landing pad means cleanup; filter signs classify actions.
  // https://github.com/llvm/llvm-project/blob/main/libcxxabi/src/cxa_personality.cpp
  callSites: [
    { start: 0n, length: 2n, landingPad: 0n, action: 0n },
    { start: 2n, length: 2n, landingPad: 8n, action: 0n },
    { start: 4n, length: 2n, landingPad: 8n, action: 1n },
    { start: 6n, length: 2n, landingPad: 0n, action: 1n }
  ],
  actions: [
    { offset: 0, typeFilter: 0n, nextOffset: 0n },
    { offset: 2, typeFilter: 1n, nextOffset: 0n },
    { offset: 4, typeFilter: -1n, nextOffset: 0n }
  ],
  types: [
    { index: 1n, pointer: { address: 0n, indirect: false } },
    { index: 2n, pointer: { address: 0n, indirect: true } },
    { index: 3n, pointer: { address: 8n, indirect: false } },
    { index: 4n, pointer: null },
    { index: 5n, pointer: { address: 0n, indirect: false } }
  ],
  specifications: [{ filter: -1n, typeIndices: [1n] }]
});

void test("aggregates all descriptors into one summary", () => {
  const html = render([populatedDescriptor(), populatedDescriptor(), lsdaFixture([]).result]);

  assert.equal((html.match(/<details\b/g) ?? []).length, 1);
  assert.match(html, /Exception tables \(\.gcc_except_table\)/);
  assert.deepEqual(
    [...html.matchAll(/<dt>(.*?)<\/dt><dd>(.*?)<\/dd>/g)].map(match => match.slice(1)),
    [
      ["Unique LSDA tables", "3"],
      ["Tables with decoded call sites", "2"],
      ["Tables with warnings", "0"],
      ["Decoded code ranges", "8"],
      ["Ranges without a landing pad", "4"],
      ["Ranges with a landing pad", "4"],
      ["Ranges with direct cleanup only", "2"],
      ["Ranges referencing action chains", "2"],
      ["Decoded action records", "6"],
      ["Cleanup action records", "2"],
      ["Catch action records", "2"],
      ["Exception specification action records", "2"],
      ["Referenced type entries", "10"],
      ["Catch-all type entries (direct null pointers)", "4"],
      ["Indirect type entries", "2"],
      ["Unreadable type entries", "2"],
      ["Decoded exception specification lists", "2"]
    ]
  );
  assert.doesNotMatch(html, /LSDA at|0x1000|data-paged|<table|partial/);
  assert.match(html, /not counts of functions or source-level catch clauses/);
});

void test("omits absent descriptors and renders zero statistics for an empty descriptor", () => {
  assert.equal(render(), "");
  assert.equal(render([]), "");
  assert.match(render([lsdaFixture([]).result]), /<dt>Decoded code ranges<\/dt><dd>0<\/dd>/);
  assert.equal(getElfPagedTableModel(relocationFixture().elf, "elf-lsda-4096-sites"), null);
});

void test("groups escaped diagnostics and counts each affected table once", () => {
  const html = render([
    { ...populatedDescriptor(), issues: ["<truncated>", "<truncated>", "Unsupported encoding"] },
    { ...lsdaFixture([]).result, issues: ["<truncated>"] }
  ]);

  assert.match(html, /<dt>Tables with warnings<\/dt><dd>2<\/dd>/);
  assert.match(html, /partial/);
  assert.match(html, /<th[^>]*>Warning<\/th>/);
  assert.match(html, /<th[^>]*>Affected tables<\/th>/);
  assert.match(html, /<h4>Warnings<\/h4><p class="smallNote">/);
  assert.match(html, /<div class="tableWrap"><table class="table"><thead><tr>/);
  assert.match(html, /<\/tr><\/thead><tbody><tr>/);
  assert.match(html, /<\/tr><\/tbody><\/table><\/div>/);
  assert.match(html, /<td>&lt;truncated><\/td><td class="peNumeric">2<\/td>/);
  assert.match(html, /<td>Unsupported encoding<\/td><td class="peNumeric">1<\/td>/);
  assert.equal((html.match(/&lt;truncated>/g) ?? []).length, 1);
  assert.doesNotMatch(html, /<truncated>/);
});

void test("keeps explanations and semantic summary structure", () => {
  const html = render([lsdaFixture([]).result]);

  assert.match(html, /<h4>Tables<\/h4><dl>/);
  assert.match(html, /<\/dl><h4>Code ranges<\/h4><dl>/);
  assert.match(html, /<h4>Actions and types<\/h4><dl>/);
  assert.match(html, /<\/dl><p class="smallNote">A landing pad is code used for/);
  assert.match(html, /Action chains may contain both catch and cleanup actions\./);
  assert.match(html, /<\/dl><p class="smallNote">Type entries are counted per LSDA/);
  assert.match(html, /Indirect type references are not resolved to names or classified as catch-all\./);
  assert.match(html, /<p class="smallNote">GCC\/LLVM language-specific exception data \(LSDA\)\./);
  assert.ok(html.endsWith("</div></details></section>"));
});

// Signed pointer encodings can yield negative landing-pad offsets; the parser
// preserves such records and warns. They must not be counted as usable landing pads.
for (const [landingPad, action, without, withPad, cleanup, chains] of [
  [0n, 0n, 1, 0, 0, 0],
  [0n, 1n, 1, 0, 0, 0],
  [8n, 0n, 0, 1, 1, 0],
  [8n, 1n, 0, 1, 0, 1],
  [-1n, 0n, 0, 0, 0, 0],
  [-1n, 1n, 0, 0, 0, 0]
] as const) {
  void test(`classifies landing pad ${landingPad} and action ${action}`, () => {
    const html = render([{
      ...lsdaFixture([]).result,
      callSites: [{ start: 0n, length: 2n, landingPad, action }]
    }]);

    assert.ok(html.includes(`<dt>Ranges without a landing pad</dt><dd>${without}</dd>`));
    assert.ok(html.includes(`<dt>Ranges with a landing pad</dt><dd>${withPad}</dd>`));
    assert.ok(html.includes(`<dt>Ranges with direct cleanup only</dt><dd>${cleanup}</dd>`));
    assert.ok(html.includes(`<dt>Ranges referencing action chains</dt><dd>${chains}</dd>`));
  });
}

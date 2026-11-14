import assert from "node:assert/strict";
import { test } from "node:test";
import { DOMParser } from "@xmldom/xmldom";
import {
  renderElfDynamicEntries, renderElfDynamicTagCoverage
} from "../../../../renderers/elf/dynamic-entries.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

void test("shows every record, raw value, description and resolved string in source order", () => {
  const html = renderElfDynamicEntries([
    { tag: 3, value: 0x400000n }, { tag: 21, value: 0n },
    { tag: 24, value: 0n }, { tag: 22, value: 0n },
    { tag: 0x6ffffefc, value: 1n, string: "<audit>" },
    { tag: 0x7fffffff, value: 2n, string: null },
    { tag: 3, value: 0n }, { tag: 1n << 60n, value: 1n << 63n },
    { tag: -1n << 60n, value: 1n }
  ]);
  assert.equal((html.match(/<dt\b/g) ?? []).length, 9);
  assert.equal((html.match(/>DT_PLTGOT</g) ?? []).length, 2);
  assert.match(html, /DT_DEBUG/);
  assert.match(html, /unspecified by the gABI/);
  assert.doesNotMatch(html, /class="opt sel"[^>]*>DT_BIND_NOW/);
  assert.doesNotMatch(html, /class="opt sel"[^>]*>DT_TEXTREL/);
  assert.match(html, /value ignored/);
  assert.match(html, /&lt;audit&gt;/);
  assert.doesNotMatch(html, /<audit>/);
  assert.match(html, /Unresolved string/);
  assert.match(html, /0x1000000000000000/);
  assert.match(html, /-0x1000000000000000/);
  assert.match(html, /0x8000000000000000/);
  assert.match(html, /Unknown tag/);
});

void test("coverage explicitly reports missing tags only after a verified terminator", () => {
  const dynamic = { ...relocationFixture().elf.dynamic!, entries: [], terminated: true };
  const html = renderElfDynamicTagCoverage(dynamic);
  const document = new DOMParser().parseFromString(html, "text/html");
  assert.equal(document.getElementsByTagName("dl").length, 1);
  assert.equal(document.getElementsByTagName("details").length, 0);
  assert.match(html, /DT_NEEDED/);
  assert.match(html, /DT_SONAME/);
  assert.match(html, /DT_RPATH/);
  assert.match(html, /DT_RUNPATH/);
  assert.match(html, /Absent/);
  assert.match(html, /DT_NULL/);
  assert.match(html, /DF_BIND_NOW/);
  assert.doesNotMatch(html, /class="opt sel"/);
  assert.doesNotMatch(html, /<code>0x0<\/code>/);
});

void test("coverage preserves uncertainty for unread tables and never repeats present tags", () => {
  const html = renderElfDynamicTagCoverage({ ...relocationFixture().elf.dynamic!,
    entries: [{ tag: 1, value: 1n, string: "present.so" }], terminated: false });
  assert.doesNotMatch(html, /DT_NEEDED/);
  assert.doesNotMatch(html, /Absent/);
  assert.match(html, /Not determined/);
  assert.match(html, /DT_SONAME/);
});

void test("formats sizes, counts, addresses, relocation enums and all flag families", () => {
  const html = renderElfDynamicEntries([
    { tag: 10, value: 32n }, { tag: 0x6ffffffd, value: 3n },
    { tag: 20, value: 7n }, { tag: 20, value: 17n }, { tag: 20, value: 99n },
    { tag: 30, value: (1n << 60n) | 8n }, { tag: 0x6ffffffb, value: 0n },
    { tag: 0x6ffffdfc, value: 3n }, { tag: 0x6ffffdfd, value: 3n },
    { tag: 1, value: 0n, string: "" }, { tag: 0x70000001, value: 1n }
  ]);
  assert.match(html, /32 bytes/);
  assert.match(html, /3 records/);
  assert.match(html, /DT_RELA/);
  assert.match(html, /DT_REL/);
  assert.match(html, /Unknown relocation encoding/);
  assert.match(html, /class="opt sel"[^>]*>DF_BIND_NOW/);
  assert.match(html, /UNKNOWN_BITS_0x1000000000000000/);
  assert.match(html, /class="opt dim"[^>]*>DF_1_NOW/);
  assert.match(html, /class="opt sel"[^>]*>DTF_1_PARINIT/);
  assert.match(html, /class="opt sel"[^>]*>DF_P1_GROUPPERM/);
  assert.match(html, /Empty string/);
  assert.match(html, /processor-specific/);
  assert.equal(renderElfDynamicEntries([]), "");
});

void test("recognizes the experimental LLVM DT_CREL tag and PLT relocation encoding", () => {
  // llvm/include/llvm/BinaryFormat/DynamicTags.def assigns CREL = 0x40000026.
  const html = renderElfDynamicEntries([
    { tag: 0x40000026, value: 0x400000n }, { tag: 20, value: 0x40000026n }
  ]);
  assert.match(html, /<dt[^>]*>DT_CREL<\/dt>/);
  assert.match(html, /experimental LLVM/i);
  assert.match(html, /class="opt sel"[^>]*>DT_CREL<\/span>/);
  assert.doesNotMatch(html, /Unknown tag|Unknown relocation encoding/);
  const absent = renderElfDynamicTagCoverage({ entries: [], terminated: true });
  assert.match(absent, /DT_CREL/);
});

void test("uses the header field layout and associates raw values with their tags", () => {
  const document = new DOMParser({ onError: (_level, message) => assert.fail(message) })
    .parseFromString(`<section>${renderElfDynamicEntries([
      { tag: 20, value: 17n }, { tag: 20, value: 7n },
      { tag: 3, value: 0n }, { tag: 21, value: 0n }
    ])}</section>`, "text/html");
  assert.equal(document.getElementsByTagName("table").length, 0);
  assert.deepEqual(Array.from(document.getElementsByTagName("dt"))
    .map(term => term.textContent), ["DT_PLTREL", "DT_PLTREL", "DT_PLTGOT", "DT_DEBUG"]);
  assert.deepEqual(Array.from(document.getElementsByTagName("dd"))
    .map(value => value.getElementsByTagName("code")[0]!.textContent),
    ["0x11", "0x7", "0x0", "0x0"]);
  assert.equal(document.getElementsByTagName("h4")[0]!.textContent, "Dynamic entries (4)");
});

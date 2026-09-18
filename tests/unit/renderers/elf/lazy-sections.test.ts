import assert from "node:assert/strict";
import { test } from "node:test";
import { getElfLazySections, renderElfLazy } from "../../../../renderers/elf/lazy-sections.js";
import { renderElf } from "../../../../renderers/elf/index.js";
import { renderElfSectionStart, renderElfSectionEnd } from "../../../../renderers/elf/collapsible-section.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

void test("creates empty shells without rendering table cells", () => {
  const elf = relocationFixture().elf;
  Object.defineProperty(elf.header, "entry", { get: () => { throw new Error("Eager header"); } });
  const html = renderElfLazy(elf);
  assert.match(html, /data-elf-lazy-section="header"/);
  assert.match(html, /id="elfInstructionSetsPanel"/);
  assert.match(html, /<div class="peSectionBody"><\/div>/);
  assert.doesNotMatch(html, /<table|<td/);
  assert.equal(renderElfLazy(null), "");
});

void test("renders each repeated section independently with its original table identifier", () => {
  const elf = relocationFixture().elf;
  elf.armEhabi = [
    { source: "first", entries: [], issues: ["first-only"] },
    { source: "<second>", entries: [], issues: ["second-only"] }
  ];
  elf.symbolTables = [{ sectionIndex: 2, entries: [], issues: [] }];
  elf.unwind = [{ sectionIndex: 1, cies: [], fdes: [], issues: [] }];
  elf.hashTables = [{ kind: "sysv", offset: 0, buckets: [0], chains: [0], issues: [] }];
  elf.attributes = [{ sectionIndex: 1, vendors: [], issues: [] }];
  elf.mips = [{ source: "MIPS", options: [], issues: [] }];
  const sections = getElfLazySections(elf);
  const second = sections.find(section => section.key === "ehabi-1")!;
  assert.match(second.render(), /elf-arm-ehabi-1/);
  assert.match(second.render(), /second-only/);
  assert.doesNotMatch(second.render(), /first-only|elf-arm-ehabi-0/);
  assert.match(renderElfLazy(elf), /&lt;second>/);
  for (const section of sections.filter(section => section.key !== "instruction-sets")) {
    assert.ok(renderElf(elf).includes(renderElfSectionStart(section.title) +
      section.render() + renderElfSectionEnd()), section.key);
  }
});

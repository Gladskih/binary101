import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { analyzeElfEmbeddedResources } from "../../../../analyzers/elf/embedded-resources.js";
import { embeddedResourceFixture } from "../../../fixtures/embedded-resource-builders.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("integrates Qt packages, symbol-backed arrays and GResource in named and ordinary ELF sections", async () => {
  const file = new MockFile(embeddedResourceFixture("qt-glib.so"));
  const parsed = await parseElf(file);
  assert.ok(parsed);
  assert.equal(parsed.embeddedResources?.bundles.length, 4);
  assert.deepEqual(parsed.embeddedResources?.issues, []);
  assert.deepEqual(parsed.embeddedResources?.bundles.map(bundle => bundle.resource.format).sort(),
    ["GLib GResource", "GLib GResource", "Qt RCC", "Qt RCC"]);
  assert.equal(parsed.embeddedResources?.bundles.find(bundle =>
    bundle.evidence.some(evidence => evidence.includes("symbols")))?.resource.format, "Qt RCC");
  const fromSegments = await analyzeElfEmbeddedResources(file, { ...parsed, sections: [], symbolTables: [] });
  assert.equal(fromSegments?.bundles.length, 3);
});

for (const failure of ["valid", "nobits", "compressed", "negative", "end", "section", "absent"] as const) {
  void test(`uses only confirmed ELF relocation targets: ${failure}`, async () => {
    const file = new MockFile(embeddedResourceFixture("qt-glib.so"));
    const parsed = await parseElf(file);
    assert.ok(parsed);
    const target = parsed.embeddedResources!.bundles[0]!.offset;
    const section = { ...parsed.sections[0]!, name: ".fake", index: 9999,
      offset: BigInt(target), size: 1n, addr: 0n, type: 1, flags: 0n };
    const symbol = { name: "resource_probe", value: 0n, sectionIndex: section.index };
    const failures = {
      valid: () => {}, nobits: () => { section.type = 8; }, compressed: () => { section.flags = 0x800n; },
      negative: () => { section.addr = 1n; section.offset += 1n; },
      end: () => { symbol.value = 1n; section.offset -= 1n; },
      section: () => { symbol.sectionIndex = 10000; }, absent: () => {}
    };
    failures[failure]();
    parsed.sections.push(section);
    parsed.relocations = { tables: [], issues: [], entries: [{ tableIndex: 0, recordOffset: 123,
      offset: 0n, type: 1, symbolIndex: 1, addend: 0n, target: null,
      symbol: failure === "absent" ? null : symbol }] };
    const result = await analyzeElfEmbeddedResources(file, parsed);
    assert.deepEqual(result?.bundles[0]?.evidence.filter(item => item.includes("resource_probe")),
      failure === "valid" ? ["ELF relocation at 123 names resource_probe"] : []);
  });
}

for (const failure of ["section", "nobits", "compressed", "empty", "negative", "end"] as const) {
  void test(`rejects ELF array symbols with ${failure} storage`, async () => {
    const file = new MockFile(embeddedResourceFixture("qt-arrays.o"));
    const parsed = await parseElf(file);
    assert.ok(parsed);
    const symbol = parsed.symbolTables!.flatMap(table => table.entries).find(entry => entry.name.includes("qt_resource_struct"))!;
    const section = parsed.sections.find(section => section.index === symbol.sectionIndex)!;
    const failures = {
      section: () => { symbol.sectionIndex = 9999; }, nobits: () => { section.type = 8; },
      compressed: () => { section.flags |= 0x800n; }, empty: () => { symbol.size = 0n; },
      negative: () => { symbol.value = -1n; }, end: () => { symbol.value = section.size; }
    };
    failures[failure]();
    assert.equal(await analyzeElfEmbeddedResources(file, parsed), null);
  });
}

void test("normalizes linked ELF symbol values relative to their owning section address", async () => {
  const file = new MockFile(embeddedResourceFixture("qt-arrays.o"));
  const parsed = await parseElf(file);
  assert.ok(parsed);
  parsed.header.type = 3;
  parsed.sections.forEach(section => { section.addr = 0x1000n; delete section.name; });
  parsed.symbolTables!.forEach(table => table.entries.forEach(symbol => { symbol.value += 0x1000n; }));
  const named = parsed.symbolTables!.flatMap(table => table.entries)
    .find(symbol => symbol.name.includes("qt_resource_struct"))!;
  parsed.relocations!.entries[0]!.symbol = named;
  const result = await analyzeElfEmbeddedResources(file, parsed);
  assert.equal(result?.bundles.length, 1);
  assert.ok(result?.bundles[0]?.evidence.some(item => item.includes("ELF relocation")));
  delete parsed.symbolTables;
  delete parsed.relocations;
  assert.equal(await analyzeElfEmbeddedResources(file, parsed), null);
});

void test("keeps ET_REL symbol and relocation values section-relative despite nonzero sh_addr", async () => {
  const file = new MockFile(embeddedResourceFixture("qt-arrays.o"));
  const parsed = await parseElf(file);
  assert.ok(parsed);
  const named = parsed.symbolTables!.flatMap(table => table.entries)
    .find(symbol => symbol.name.includes("qt_resource_struct"))!;
  parsed.relocations!.entries[0]!.symbol = named;
  parsed.sections.forEach(section => { section.addr = 0x1000n; });
  const result = await analyzeElfEmbeddedResources(file, parsed);
  assert.equal(result?.bundles.length, 1);
  assert.ok(result?.bundles[0]?.evidence.some(item => item.includes("ELF relocation")));
});

void test("reads Qt arrays in generated ELF relocatable objects with section-relative symbols", async () => {
  const file = new MockFile(embeddedResourceFixture("qt-arrays.o"));
  const parsed = await parseElf(file);
  assert.ok(parsed);
  assert.equal(parsed.embeddedResources?.bundles.length, 1);
  assert.equal(parsed.embeddedResources?.bundles[0]?.resource.entries.length, 5);
  assert.match(parsed.embeddedResources!.bundles[0]!.evidence[0]!, /^RCC array symbols in ELF table #\d+, file symbol #\d+$/);
});

void test("retains an ELF symbol-table scope when FILE symbols are unavailable", async () => {
  const file = new MockFile(embeddedResourceFixture("qt-arrays.o"));
  const parsed = await parseElf(file);
  assert.ok(parsed);
  parsed.symbolTables!.forEach(table => { table.entries = table.entries.filter(symbol => (symbol.info & 15) !== 4); });
  const result = await analyzeElfEmbeddedResources(file, parsed);
  assert.match(result!.bundles[0]!.evidence[0]!, /^RCC array symbols in ELF symbol table #\d+$/);
});

for (const storage of ["nobits", "compressed"] as const) {
  void test(`does not scan ${storage} ELF sections as raw resources`, async () => {
    const file = new MockFile(embeddedResourceFixture("qt-glib.so"));
    const parsed = await parseElf(file);
    assert.ok(parsed);
    const mutations = {
      nobits: () => parsed.sections.forEach(section => { section.type = 8; }),
      compressed: () => parsed.sections.forEach(section => { section.flags |= 0x800n; })
    };
    mutations[storage]();
    parsed.symbolTables = [];
    assert.equal(await analyzeElfEmbeddedResources(file, parsed), null);
  });
}

void test("scans only PT_LOAD file-backed segments when ELF section headers are absent", async () => {
  const file = new MockFile(embeddedResourceFixture("qt-glib.so"));
  const parsed = await parseElf(file);
  assert.ok(parsed);
  parsed.sections = [];
  parsed.symbolTables = [];
  parsed.programHeaders.forEach(segment => { segment.type = 2; });
  assert.equal(await analyzeElfEmbeddedResources(file, parsed), null);
});

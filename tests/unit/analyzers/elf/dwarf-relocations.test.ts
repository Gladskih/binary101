import assert from "node:assert/strict";
import { test } from "node:test";
import { applyElfDwarfRelocations } from "../../../../analyzers/elf/dwarf-relocations.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";
import type { ElfRelocation, ElfRelocationInfo } from "../../../../analyzers/elf/relocation-types.js";
import type { DwarfSectionSource } from "../../../../analyzers/dwarf/types.js";
import { createDwarfRelocationFixture } from "../../../fixtures/dwarf-relocation-fixture.js";

const relocate = async (entry: Partial<ElfRelocation> = {}) => {
  const source: DwarfSectionSource = dwarfMacroSources([
    { name: ".debug_info", bytes: new Array<number>(16).fill(0) }
  ]).get(".debug_info")!;
  const elf = relocationFixture().elf;
  elf.sections = [relocationSection(1, { name: ".debug_info", size: 16n })];
  const relocations: ElfRelocationInfo = { tables: [{ offset: 0, size: 24, entrySize: 24,
    encoding: "RELA", sources: [], sectionIndex: 2, symbolTableIndex: 3, targetSectionIndex: 1 }],
  entries: [{ tableIndex: 0, recordOffset: 0, offset: 4n, type: 10, symbolIndex: 1,
    symbol: { name: "target", value: 12n, sectionIndex: 1 }, addend: 4n,
    target: { sectionIndex: 1, sectionOffset: 4n, fileOffset: 4n }, ...entry }], issues: [] };
  const issues: string[] = [];
  source.summary = { ...source.summary, requiresRelocations: true };
  source.decoded = false;
  return { sources: await applyElfDwarfRelocations([source], elf, relocations, issues), issues, source };
};

void test("DWARF relocation overlays adjust bounded fields without changing original bytes", async () => {
  const result = await relocate();

  assert.equal(result.sources[0]?.decoded, true);
  assert.equal(result.sources[0]?.summary.requiresRelocations, undefined);
  assert.equal((await result.sources[0]!.reader.read(4, 4)).getUint32(0, true), 16);
  assert.equal((await result.sources[0]!.reader.read(5, 2)).getUint16(0, true), 0);
  assert.equal((await result.source.reader.read(4, 4)).getUint32(0, true), 0);
  assert.deepEqual(result.issues, []);
});

void test("unknown relocation types keep the affected DWARF section unavailable", async () => {
  const result = await relocate({ type: 999 });

  assert.equal(result.sources[0]?.decoded, false);
  assert.equal(result.sources[0]?.summary.requiresRelocations, true);
  assert.match(result.issues.join(" "), /Unsupported/);
});

void test("DWARF relocation writes cannot escape the target section", async () => {
  const result = await relocate({ type: 1, target: { sectionIndex: 1, sectionOffset: 12n, fileOffset: 12n } });

  assert.equal(result.sources[0]?.decoded, false);
  assert.match(result.issues.join(" "), /outside|truncated/);
});

void test("unresolved symbols and overflow do not create plausible DWARF values", async () => {
  const unresolved = await relocate({ symbol: null });
  const overflow = await relocate({ addend: 0x100000000n });

  assert.equal(unresolved.sources[0]?.decoded, false);
  assert.match(unresolved.issues.join(" "), /symbol/);
  assert.equal(overflow.sources[0]?.decoded, false);
  assert.match(overflow.issues.join(" "), /overflow/);
});

void test("relocation adapters reject invalid source offsets and incomplete relocation records", async () => {
  const fixture = createDwarfRelocationFixture();
  fixture.source.summary.offset = Number.NaN;

  const invalid = await applyElfDwarfRelocations([fixture.source], fixture.elf, fixture.relocations, fixture.issues);

  assert.equal(invalid[0]?.decoded, false);
  assert.match(fixture.issues.join(" "), /invalid file offset/);
  fixture.source.summary.offset = 0;
  fixture.relocations.tables[0]!.size = 48;
  const incomplete = await applyElfDwarfRelocations([fixture.source], fixture.elf, fixture.relocations, fixture.issues);
  assert.equal(incomplete[0]?.decoded, false);
  assert.match(fixture.issues.join(" "), /incomplete/);
  fixture.relocations.tables[0]!.entrySize = 0;
  assert.equal((await applyElfDwarfRelocations([fixture.source], fixture.elf,
    fixture.relocations, fixture.issues))[0]?.decoded, false);
});

void test("relocation adapters preserve unrelated or unavailable compressed sources", async () => {
  const fixture = createDwarfRelocationFixture();
  fixture.source.section.compressed = true;

  assert.equal((await applyElfDwarfRelocations([fixture.source], fixture.elf,
    fixture.relocations, fixture.issues))[0], fixture.source);
  fixture.source.section.compressed = false;
  fixture.elf.sections = [];
  assert.equal((await applyElfDwarfRelocations([fixture.source], fixture.elf,
    fixture.relocations, fixture.issues))[0], fixture.source);
  assert.deepEqual(fixture.issues, []);
});

void test("a section requiring relocations cannot become decoded when its table is absent", async () => {
  const fixture = createDwarfRelocationFixture();
  fixture.source.decoded = true;
  fixture.relocations.tables = [];

  assert.equal((await applyElfDwarfRelocations([fixture.source], fixture.elf,
    fixture.relocations, fixture.issues))[0]?.decoded, false);
  delete fixture.source.summary.requiresRelocations;
  assert.equal((await applyElfDwarfRelocations([fixture.source], fixture.elf,
    fixture.relocations, fixture.issues))[0], fixture.source);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildElfDwarfRelocationPatches } from "../../../../analyzers/elf/dwarf-relocation-patches.js";
import { createDwarfRelocationFixture } from "../../../fixtures/dwarf-relocation-fixture.js";
import type { ElfRelocation } from "../../../../analyzers/elf/relocation-types.js";

void test("DWARF relocation fields preserve both byte orders and REL addends", async () => {
  const fixture = createDwarfRelocationFixture([0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0], "big");
  fixture.relocations.entries[0]!.addend = null;

  const patches = await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues);

  assert.deepEqual(patches, [{ offset: 4, bytes: Uint8Array.of(0, 0, 0, 20) }]);
  assert.deepEqual(fixture.issues, []);
});

void test("RISC-V ADD/SUB pairs reuse the original slot and preserve record order", async () => {
  const fixture = createDwarfRelocationFixture();
  fixture.elf.header.machine = 243;
  fixture.relocations.entries[0]!.type = 35; // R_RISCV_ADD32, psABI relocation table.
  fixture.relocations.entries.push({ ...fixture.relocations.entries[0]!, type: 39, addend: 0n });

  const patches = await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues);

  assert.deepEqual(patches, [{ offset: 4, bytes: Uint8Array.of(4, 0, 0, 0) }]);
  assert.deepEqual(fixture.issues, []);
});

void test("NONE relocations have no target-width or symbol requirement", async () => {
  const fixture = createDwarfRelocationFixture();
  fixture.relocations.entries[0] = { ...fixture.relocations.entries[0]!, type: 0, target: null, symbol: null };

  assert.deepEqual(await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues), []);
  fixture.elf.header.machine = 183;
  fixture.relocations.entries[0]!.type = 256; // AArch64's second R_AARCH64_NONE encoding.
  assert.deepEqual(await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues), []);
  assert.deepEqual(fixture.issues, []);
});

const invalidEntries: Array<{ name: string; entry: Partial<ElfRelocation>; notice: RegExp }> = [
  { name: "unknown type", entry: { type: null }, notice: /Unsupported/ },
  { name: "missing target", entry: { target: null }, notice: /outside/ },
  { name: "negative offset", entry: { target: { sectionIndex: 1, sectionOffset: -1n, fileOffset: null } }, notice: /outside/ },
  { name: "unsafe offset", entry: { target: { sectionIndex: 1, sectionOffset: 0x20000000000000n, fileOffset: null } }, notice: /outside/ }
];
for (const example of invalidEntries) {
  void test(`relocation patches reject ${example.name}`, async () => {
    const fixture = createDwarfRelocationFixture();
    fixture.relocations.entries[0] = { ...fixture.relocations.entries[0]!, ...example.entry };

    assert.equal(await buildElfDwarfRelocationPatches(fixture.source,
      fixture.relocations.entries, fixture.elf, fixture.issues), null);
    assert.match(fixture.issues.join(" "), example.notice);
  });
}

void test("relocation patches reject non-composable writes and partly overlapping fields", async () => {
  const fixture = createDwarfRelocationFixture();
  fixture.relocations.entries.push({ ...fixture.relocations.entries[0]! });

  assert.equal(await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues), null);
  assert.match(fixture.issues.join(" "), /composition/);
  fixture.relocations.entries[1]!.target = { sectionIndex: 1, sectionOffset: 6n, fileOffset: 6n };
  assert.equal(await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues), null);
  assert.match(fixture.issues.join(" "), /fields overlap/);
});

void test("relocation patches reject invalid source ranges and truncated storage", async () => {
  const fixture = createDwarfRelocationFixture();
  fixture.source.section.size = -1;

  assert.equal(await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues), null);
  assert.match(fixture.issues.join(" "), /invalid section range/);
  fixture.source.section.size = 20;
  fixture.relocations.entries[0]!.target = { sectionIndex: 1, sectionOffset: 16n, fileOffset: 16n };
  assert.equal(await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues), null);
  assert.match(fixture.issues.join(" "), /truncated/);
});

void test("relocation patches reject a target referring to a different source section", async () => {
  const fixture = createDwarfRelocationFixture();
  fixture.relocations.entries[0]!.target!.sectionIndex = 99;

  assert.equal(await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues), null);
  assert.match(fixture.issues.join(" "), /disagrees/);
  fixture.relocations.entries[0]!.target!.sectionIndex = 1;
  fixture.elf.sections[0]!.name = ".debug_line";
  assert.equal(await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues), null);
  fixture.elf.sections[0]!.name = ".debug_info";
  fixture.elf.sections[0]!.offset = 4n;
  assert.equal(await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues), null);
});

void test("multi-byte implicit addends retain all significant bytes", async () => {
  const fixture = createDwarfRelocationFixture([0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44], "big");
  fixture.relocations.entries[0]!.addend = null;

  assert.deepEqual(await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues),
  [{ offset: 4, bytes: Uint8Array.of(0x11, 0x22, 0x33, 0x50) }]);
  assert.deepEqual(fixture.issues, []);
});

void test("RISC-V compositions require matching widths and additive operations on both records", async () => {
  const fixture = createDwarfRelocationFixture();
  fixture.elf.header.machine = 243;
  fixture.relocations.entries[0]!.type = 35;
  fixture.relocations.entries.push({ ...fixture.relocations.entries[0]!, type: 36 });

  assert.equal(await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues), null);
  fixture.relocations.entries[1]!.type = 1;
  assert.equal(await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues), null);
  fixture.relocations.entries[0]!.type = 1;
  fixture.relocations.entries[1]!.type = 35;
  assert.equal(await buildElfDwarfRelocationPatches(fixture.source,
    fixture.relocations.entries, fixture.elf, fixture.issues), null);
  assert.match(fixture.issues.join(" "), /composition/);
});

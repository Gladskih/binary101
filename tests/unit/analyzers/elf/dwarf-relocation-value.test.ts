import assert from "node:assert/strict";
import { test } from "node:test";
import { elfDwarfRelocationValue } from "../../../../analyzers/elf/dwarf-relocation-value.js";
import type { ElfDwarfRelocationKind } from "../../../../analyzers/elf/dwarf-relocation-types.js";
import { createDwarfRelocationFixture } from "../../../fixtures/dwarf-relocation-fixture.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";

const value = (overflow: ElfDwarfRelocationKind["overflow"], addend: bigint,
  operation: ElfDwarfRelocationKind["operation"] = "absolute") => {
  const { elf, relocations } = createDwarfRelocationFixture();
  return elfDwarfRelocationValue({ ...relocations.entries[0]!, symbolIndex: 0, addend },
    { width: 4, operation, overflow }, elf, new Map(), 16n, 8n, 32n);
};

void test("relocation overflow checks use each ABI's signed, unsigned, mixed and truncating limits", () => {
  assert.equal(value("unsigned", 0xffffffffn), 0xffffffffn);
  assert.equal(value("unsigned", 0n), 0n);
  assert.equal(value("unsigned", -1n), "DWARF relocation overflow");
  assert.equal(value("unsigned", 0x100000000n), "DWARF relocation overflow");
  assert.equal(value("signed", -0x80000000n), 0x80000000n);
  assert.equal(value("signed", 0x7fffffffn), 0x7fffffffn);
  assert.equal(value("signed", 0x80000000n), "DWARF relocation overflow");
  assert.equal(value("signed", -0x80000001n), "DWARF relocation overflow");
  assert.equal(value("mixed", -0x80000000n), 0x80000000n);
  assert.equal(value("mixed", 0xffffffffn), 0xffffffffn);
  assert.equal(value("mixed", -0x80000001n), "DWARF relocation overflow");
  assert.equal(value("mixed", 0x100000000n), "DWARF relocation overflow");
  assert.equal(value("truncate", -1n), 0xffffffffn);
  assert.equal(value("truncate", 0x100000001n), 1n);
});

void test("relative and composed relocations preserve their algebra", () => {
  assert.equal(value("signed", 12n, "relative"), 0xfffffffcn);
  assert.equal(value("truncate", 12n, "add"), 44n);
  assert.equal(value("truncate", 12n, "subtract"), 20n);
});

void test("relocation symbols distinguish ET_REL section bases, absolute values, and linked images", () => {
  const { elf, relocations } = createDwarfRelocationFixture();
  const kind: ElfDwarfRelocationKind = { width: 4, operation: "absolute", overflow: "unsigned" };
  const sections = new Map([[1, relocationSection(1, { addr: 4096n })]]);
  const entry = relocations.entries[0]!;

  assert.equal(elfDwarfRelocationValue(entry, kind, elf, sections, 0n, 0n, 0n), 4112n);
  elf.header.type = 2;
  assert.equal(elfDwarfRelocationValue(entry, kind, elf, sections, 0n, 0n, 0n), 16n);
  entry.symbol!.sectionIndex = 0xfff1; // gABI SHN_ABS.
  assert.equal(elfDwarfRelocationValue(entry, kind, elf, new Map(), 0n, 0n, 0n), 16n);
  entry.addend = null;
  assert.equal(elfDwarfRelocationValue(entry, kind, elf, new Map(), 0n, 0xfffffffcn, 0n), 8n);
  entry.symbol!.sectionIndex = 0;
  assert.match(String(elfDwarfRelocationValue(entry, kind, elf, new Map(), 0n, 0n, 0n)), /Unresolved/);
  entry.symbol!.sectionIndex = 7;
  assert.match(String(elfDwarfRelocationValue(entry, kind, elf, new Map(), 0n, 0n, 0n)), /unavailable section/);
});

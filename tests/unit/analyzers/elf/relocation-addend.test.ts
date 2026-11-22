import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfStoredRelocationAddend } from "../../../../analyzers/elf/relocation-addend.js";
import { createMemoryRangeReader } from "../../../../analyzers/memory-range-reader.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { relocationTable } from "../../../fixtures/elf-relocations.js";
import type { ElfRelocation } from "../../../../analyzers/elf/relocation-types.js";

const fields = () => {
  const source = dynamicRelocationFixture(32, "big");
  const reader = createMemoryRangeReader(source.bytes);
  const table = relocationTable({ encoding: "REL" });
  const target = { sectionIndex: null, sectionOffset: null, fileOffset: 512n };
  const entry: ElfRelocation = { tableIndex: 0, recordOffset: 64, offset: 0x1200n,
    type: 8, symbolIndex: 0, symbol: null, addend: null, target };
  source.word(512, 0xfedcba98n);
  return { ...source, reader, table, entry, target };
};

void test("reads i386 original words with the declared byte order in REL and packed REL", async () => {
  const { reader, elf, table, entry, target } = fields();
  assert.equal(await readElfStoredRelocationAddend(reader, elf, table, entry, "relative", target), 0xfedcba98n);
  assert.equal(await readElfStoredRelocationAddend(reader, elf, table, entry, "absolute", target), 0xfedcba98n);
  assert.equal(await readElfStoredRelocationAddend(reader, elf, table, entry, "pc-relative", target), 0xfedcba98n);
  table.encoding = "ANDROID_REL";
  assert.equal(await readElfStoredRelocationAddend(reader, elf, table, entry, "resolver", target), 0xfedcba98n);
});

void test("uses file words only for modeled implicit operands with an entire readable target", async () => {
  const { reader, elf, table, entry, target } = fields();
  assert.equal(await readElfStoredRelocationAddend(reader, elf, table, entry, "jump-slot", target), undefined);
  assert.equal(await readElfStoredRelocationAddend(reader, elf, table, entry, "relative", null), undefined);
  assert.equal(await readElfStoredRelocationAddend(reader, elf, table, entry, "relative",
    { ...target, fileOffset: null }), undefined);
  assert.equal(await readElfStoredRelocationAddend(createMemoryRangeReader(new Uint8Array(515)),
    elf, table, entry, "relative", target), undefined);
  assert.equal(await readElfStoredRelocationAddend(reader, elf, table, { ...entry, addend: 0n },
    "relative", target), undefined);
  table.encoding = "RELA";
  assert.equal(await readElfStoredRelocationAddend(reader, elf, table, entry, "relative", target), undefined);
  table.encoding = "REL";
  elf.header.machine = 62;
  assert.equal(await readElfStoredRelocationAddend(reader, elf, table, entry, "relative", target), undefined);
});

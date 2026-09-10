import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfHashTables } from "../../../../analyzers/elf/hash-tables.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";

const fixture = (kind: "sysv" | "gnu", order: "little" | "big" = "little") => {
  const result = relocationFixture(64, order);
  const words = kind === "sysv" ? [1, 3, 1, 0, 2, 0] : [1, 1, 1, 5, 0, 0, 1, 0x1234, 0x5679];
  words.forEach((word, index) => result.view.setUint32(64 + index * 4, word, order === "little"));
  result.elf.sections.push(relocationSection(4, { type: kind === "sysv" ? 5 : 0x6ffffff6,
    offset: 64n, size: BigInt(words.length * 4), link: 2 }));
  return result;
};

void test("reads System V buckets and chains", async () => {
  const source = fixture("sysv");
  const tables = await parseElfHashTables(source.file(), source.elf, []);
  assert.deepEqual(tables[0], { kind: "sysv", offset: 64, buckets: [1], chains: [0, 2, 0], issues: [] });
});

void test("reads GNU bloom words and contiguous chains in big endian", async () => {
  const source = fixture("gnu", "big");
  const tables = await parseElfHashTables(source.file(), source.elf, []);
  assert.deepEqual(tables[0], { kind: "gnu", offset: 64, buckets: [1], chains: [0x1234, 0x5679],
    symbolOffset: 1, bloomShift: 5, bloom: [0n], issues: [] });
});

void test("detects out of bounds buckets and cyclic System V chains", async () => {
  const source = fixture("sysv");
  source.view.setUint32(84, 1, true);
  assert.match((await parseElfHashTables(source.file(), source.elf, []))[0]!.issues.join(" "), /cycle/);
  source.view.setUint32(72, 99, true);
  assert.match((await parseElfHashTables(source.file(), source.elf, []))[0]!.issues.join(" "), /outside/);
});

void test("rejects oversized dimensions before allocating arrays", async () => {
  const source = fixture("gnu");
  source.view.setUint32(72, 0xffffffff, true);
  assert.match((await parseElfHashTables(source.file(), source.elf, []))[0]!.issues.join(" "), /dimensions/);
});

void test("reports unterminated GNU chains", async () => {
  const source = fixture("gnu");
  source.view.setUint32(96, 0x5678, true);
  assert.match((await parseElfHashTables(source.file(), source.elf, []))[0]!.issues.join(" "), /terminat/);
});

void test("reports truncated headers and out of file sections", async () => {
  const source = fixture("sysv");
  source.elf.sections[4]!.size = 4n;
  assert.match((await parseElfHashTables(source.file(), source.elf, []))[0]!.issues.join(" "), /truncated/);
  source.elf.sections[4]!.offset = 1n << 60n;
  assert.match((await parseElfHashTables(source.file(), source.elf, []))[0]!.issues.join(" "), /outside/);
});

const sectionless = (kind: "sysv" | "gnu") => {
  const source = fixture(kind);
  source.elf.sections = [];
  source.elf.programHeaders = [{ index: 0, type: 1, typeName: "LOAD", offset: 64n,
    vaddr: 4096n, paddr: 4096n, filesz: 36n, memsz: 64n, flags: 4,
    flagNames: [], align: 4n }];
  return source;
};

void test("finds both hash formats through dynamic virtual addresses", async () => {
  const sysv = sectionless("sysv");
  assert.deepEqual((await parseElfHashTables(sysv.file(), sysv.elf,
    [{ tag: 4, value: 4096n }]))[0], {
    kind: "sysv", offset: 64, buckets: [1], chains: [0, 2, 0], issues: []
  });
  const gnu = sectionless("gnu");
  assert.deepEqual((await parseElfHashTables(gnu.file(), gnu.elf,
    [{ tag: 0x6ffffef5, value: 4096n }]))[0], {
    kind: "gnu", offset: 64, buckets: [1], chains: [0x1234, 0x5679],
    symbolOffset: 1, bloomShift: 5, bloom: [0n], issues: []
  });
});

void test("rejects hash addresses in memory-only tails and unmapped segments", async () => {
  const source = sectionless("sysv");
  assert.match((await parseElfHashTables(source.file(), source.elf,
    [{ tag: 4, value: 4132n }]))[0]!.issues.join(" "), /outside/);
  source.elf.programHeaders[0]!.type = 4;
  assert.match((await parseElfHashTables(source.file(), source.elf,
    [{ tag: 4, value: 4096n }]))[0]!.issues.join(" "), /outside/);
  assert.deepEqual(await parseElfHashTables(source.file(), source.elf, []), []);
});

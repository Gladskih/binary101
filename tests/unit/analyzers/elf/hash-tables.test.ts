import assert from "node:assert/strict";
import { test } from "node:test";
import {
  associatedElfHashTables, parseElfHashTables, validateElfSysvHashSymbolCount
} from "../../../../analyzers/elf/hash-tables.js";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { parseElfDynamicSymbols } from "../../../../analyzers/elf/dynamic-symbols.js";
import { parseElf } from "../../../../analyzers/elf/index.js";
import type { ElfHashTable } from "../../../../analyzers/elf/hash-types.js";
import { createElfImportLinkageBytes } from "../../../fixtures/elf-import-linkage-file.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";

const associatedSectionHash = () => {
  const fixture = relocationFixture();
  const symbols = fixture.elf.sections[2]!;
  symbols.type = 11; // SHT_DYNSYM, gABI 3.3.
  const hashSection = relocationSection(4, { type: 5, offset: 64n, link: symbols.index });
  fixture.elf.sections.push(hashSection);
  const table: ElfHashTable = { kind: "sysv", offset: 64, buckets: [1], chains: [0, 0], issues: [] };
  return { image: { ...fixture.elf, file: fixture.file() }, symbols, hashSection, table };
};

void test("associates hashes only with the named dynamic symbol section and stored hash offset", () => {
  const { image, symbols, hashSection, table } = associatedSectionHash();
  const symtab = { offset: Number(symbols.offset), size: Number(symbols.size) };

  assert.deepEqual(associatedElfHashTables(image, symtab, [], undefined), []);
  assert.deepEqual(associatedElfHashTables(image, symtab, [], [table]), [table]);
  assert.deepEqual(associatedElfHashTables(image, symtab, [], [{ ...table, offset: 65 }]), []);
  hashSection.link = 1;
  image.sections[1]!.offset = symbols.offset;
  assert.deepEqual(associatedElfHashTables(image, symtab, [], [table]), []);
});

// gABI 8.3: DT_HASH=4, DT_SYMTAB=6. tag values use the same PT_LOAD translation.
const mappedHash = () => {
  const { image, symbols, table } = associatedSectionHash();
  const address = 4096n;
  image.sections = [];
  image.programHeaders.push({ type: 1, typeName: "LOAD", index: 0, offset: 0n, vaddr: address,
    paddr: address, filesz: BigInt(image.file.size), memsz: BigInt(image.file.size),
    flags: 4, flagNames: [], align: 1n });
  return { image, table, symtab: { offset: Number(symbols.offset), size: Number(symbols.size) },
    hash: { tag: 4, value: address + BigInt(table.offset) },
    symbol: { tag: 6, value: address + symbols.offset }, unmapped: address + BigInt(image.file.size) };
};

void test("requires both runtime tags to map to their respective file positions", () => {
  const { image, table, symtab, hash, symbol, unmapped } = mappedHash();

  assert.deepEqual(associatedElfHashTables(image, symtab, [hash, symbol], [table]), [table]);
  assert.deepEqual(associatedElfHashTables(image, symtab, [hash], [table]), []);
  assert.deepEqual(associatedElfHashTables(image, symtab, [symbol], [table]), []);
  assert.deepEqual(associatedElfHashTables(image, symtab, [{ ...hash, value: unmapped }, symbol], [table]), []);
  assert.deepEqual(
    associatedElfHashTables(image, symtab, [hash, { ...symbol, value: symbol.value + 1n }], [table]), []);
  assert.deepEqual(associatedElfHashTables(image, symtab, [hash, symbol], [{ ...table, offset: 65 }]), []);
});

void test("keeps a decoded symbol table distinct from a runtime mapping at its logical offset", () => {
  const { image, table, symtab, hash, symbol } = mappedHash();
  const reader = createFileRangeReader(image.file, 0, image.file.size);

  assert.deepEqual(associatedElfHashTables(image, { ...symtab, reader }, [hash, symbol], [table]), []);
});

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

for (const [count, link, diagnostics] of [[2, 2, false], [3, 2, true], [3, 1, false]] as const) {
  void test(`checks System V nchain ${count} with section link ${link}`, async () => {
    const source = fixture("sysv");
    source.elf.sections[2]!.type = 11; // SHT_DYNSYM, two Elf64_Sym records.
    source.elf.sections[2]!.info = 2;
    source.elf.sections[4]!.link = link;
    source.view.setUint32(68, count, true);
    source.view.setUint32(80, 0, true); // Chain #1 terminates even when nchain is two.
    const file = source.file();
    const tables = await parseElfHashTables(file, source.elf, []);

    await parseElfDynamicSymbols({ ...source.elf, file }, [], undefined, undefined, tables);

    assert.deepEqual(tables[0]?.issues, diagnostics
      ? ["System V hash nchain (3) disagrees with the dynamic symbol count (2)."] : []);
  });
}

for (const [chains, expected] of [[[1], 2], [[], undefined]] as const) {
  void test(`uses GNU chains as a second count source when available: ${expected}`, () => {
    const sysv: ElfHashTable = { kind: "sysv", offset: 64, buckets: [1], chains: [0, 0, 0], issues: [] };
    const gnu: ElfHashTable = { kind: "gnu", offset: 128, buckets: [1], chains: [...chains],
      symbolOffset: 1, bloomShift: 5, bloom: [0n], issues: [] };

    validateElfSysvHashSymbolCount([sysv, gnu]);

    assert.deepEqual(sysv.issues, expected === undefined ? [] :
      [`System V hash nchain (3) disagrees with the dynamic symbol count (${expected}).`]);
  });
}

void test("retains structural hash issues when the table has no reliable chain count", () => {
  const table: ElfHashTable = { kind: "sysv", offset: 64, buckets: [1], chains: [],
    issues: ["Hash table arrays are truncated."] };

  validateElfSysvHashSymbolCount([table], 2);

  assert.deepEqual(table.issues, ["Hash table arrays are truncated."]);
});

void test("checks sectionless DT_HASH against DT_SYMTABSZ", async () => {
  const bytes = createElfImportLinkageBytes();
  // nchain is the second word of the fixture's System V hash, with one spare zero word.
  new DataView(bytes.buffer).setUint32(0x264, 3, true);

  const elf = await parseElf(new File([Uint8Array.from(bytes)], "sectionless-hash.elf"));

  assert.equal(elf?.dynSymbols?.total, 2);
  assert.deepEqual(elf?.hashTables?.[0]?.issues,
    ["System V hash nchain (3) disagrees with the dynamic symbol count (2)."]);
});

for (const bucket of [0, 1]) {
  void test(`checks which System V bucket can find an exported name: ${bucket}`, async () => {
    const bytes = createElfImportLinkageBytes();
    const view = new DataView(bytes.buffer);
    // ELF64 symbol #1: SHN_ABS defines "puts". The gABI hash of "puts" is odd.
    view.setUint16(0x29e, 0xfff1, true);
    view.setUint32(0x260, 2, true);
    view.setUint32(0x268, 0, true);
    view.setUint32(0x268 + bucket * 4, 1, true);

    const elf = await parseElf(new File([Uint8Array.from(bytes)], "sysv-lookup.elf"));

    assert.equal(elf?.dynSymbols?.exportSymbols[0]?.name, "puts");
    assert.deepEqual(elf?.hashTables?.[0]?.issues, bucket === 1 ? [] :
      ["System V hash bucket 0 contains dynamic symbol #1, whose name hashes to bucket 1."]);
  });
}

void test("checks System V bucket membership using the raw name bytes", async () => {
  const bytes = createElfImportLinkageBytes();
  const view = new DataView(bytes.buffer);
  // Hash(0xff) = 255, so its bucket is 3 of 4. Hashing the replacement
  // character's UTF-8 bytes would instead select bucket 1.
  bytes.fill(0, 0x268, 0x280);
  bytes.set([0xff, 0], 0x2b1);
  view.setUint32(0x260, 4, true);
  view.setUint32(0x274, 1, true);

  const elf = await parseElf(new File([Uint8Array.from(bytes)], "sysv-raw-name.elf"));

  assert.equal(elf?.dynSymbols?.importSymbols[0]?.name, "\ufffd");
  assert.deepEqual(elf?.hashTables?.[0]?.issues, []);
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

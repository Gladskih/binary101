import assert from "node:assert/strict";
import { test } from "node:test";
import { collectElfCodeExclusions } from "../../../../analyzers/elf/code-exclusions.js";
import { elfIsaDataOptions } from "../../../fixtures/isa-known-data.js";
import { decodeElfSymbolNames } from "../../../../analyzers/elf/symbol-names.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

void test("ordinary OBJECT symbols use st_size and zero-sized objects mark only their address", () => {
  const opts = elfIsaDataOptions(62);
  const symbol = opts.symbolTables![0]!.entries[0]!;
  symbol.name = "ordinary_data";
  symbol.info = 0x11;

  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), [{ start: 0x1008n, end: 0x1010n }]);
  symbol.size = 0n;
  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), [{ start: 0x1008n, end: 0x1009n }]);
});

void test("undefined, ABS, COMMON-index and TLS symbols cannot become address exclusions", () => {
  const opts = elfIsaDataOptions(62);
  const symbol = opts.symbolTables![0]!.entries[0]!;
  const object = { ...symbol, info: 0x11 };
  opts.symbolTables![0]!.entries = [{ ...object, sectionIndex: 0 },
    { ...object, sectionIndex: 0xfff1 }, { ...object, sectionIndex: 0xfff2 },
    { ...object, info: 0x16 }, { ...object, sectionIndex: 7 }, { ...object, info: 0x12 }];

  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), []);
});

void test("malformed sizes and out-of-section extents cannot suppress neighboring code", () => {
  const opts = elfIsaDataOptions(62);
  const symbol = { ...opts.symbolTables![0]!.entries[0]!, info: 0x11 };
  opts.symbolTables![0]!.entries = [{ ...symbol, size: -1n },
    { ...symbol, value: 0xffff_ffff_ffff_ffffn, size: 2n },
    { ...symbol, value: 0xfffn }, { ...symbol, size: 100n }];
  const issues: string[] = [];

  assert.deepEqual(collectElfCodeExclusions(opts, 32, issues), []);
  assert.equal(issues.length, 2);
  assert.equal(issues[0], "Data symbol _Z5value extends outside its section; ignored.");
});

void test("ET_REL symbol values are section offsets and require that exact section", () => {
  const opts = elfIsaDataOptions(3);
  opts.fileType = 1;
  const symbol = opts.symbolTables![0]!.entries[0]!;
  symbol.info = 0x11;
  symbol.value = 8n;

  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), [{ start: 0x1008n, end: 0x1010n }]);
  symbol.value = 0xffff_ffffn;
  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), []);
});

void test("sectionless dynamic objects require a complete file-backed PT_LOAD mapping", () => {
  const opts = elfIsaDataOptions(62);
  opts.sections = [];
  delete opts.symbolTables;
  opts.dynSymbols = { total: 3, issues: [], importSymbols: [], exportSymbols: [
    { index: 1, name: "data", value: 0x1008n, size: 8n, bind: 1, bindName: "GLOBAL",
      type: 1, typeName: "OBJECT", visibility: 0, visibilityName: "DEFAULT", shndx: 1 },
    { index: 2, name: "unmapped", value: 0x2000n, size: 8n, bind: 1, bindName: "GLOBAL",
      type: 1, typeName: "OBJECT", visibility: 0, visibilityName: "DEFAULT", shndx: 1 }
  ] };

  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), [{ start: 0x1008n, end: 0x1010n }]);
});

for (const machine of [3, 62, 183]) {
  void test(`machine ${machine} treats only mapped dynamic pointer relocations as GOT cells`, () => {
    const opts = elfIsaDataOptions(machine);
    delete opts.symbolTables;
    const entry = { tableIndex: 0, recordOffset: 0, offset: 0x1008n,
      type: machine === 183 ? 1025 : 6, symbolIndex: 1, symbol: null, addend: 0n, target: null };
    opts.relocations = { tables: [], issues: [], entries: [entry, { ...entry, type: 99 },
      { ...entry, offset: 0x2000n }] };

    assert.deepEqual(collectElfCodeExclusions(opts, 32, []), [{ start: 0x1008n,
      end: machine === 3 ? 0x100cn : 0x1010n }]);
  });
}

void test("sectionless reserved indices and TLS offsets remain excluded after successful demangling", async () => {
  const opts = elfIsaDataOptions(62);
  opts.sections = [];
  const symbol = { ...opts.symbolTables![0]!.entries[0]!, info: 0x11 };
  opts.symbolTables![0]!.entries = [{ ...symbol, sectionIndex: 0xff00 },
    { ...symbol, sectionIndex: 0xffff }, { ...symbol, info: 0x16 }];
  await decodeElfSymbolNames({ ...relocationFixture().elf, symbolTables: opts.symbolTables! });

  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), []);
  opts.symbolTables![0]!.entries = [{ ...symbol, sectionIndex: 0x10000 }];
  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), [{ start: 0x1008n, end: 0x1010n }]);
});

void test("ELF function types have priority over data-like Itanium spellings", async () => {
  const opts = elfIsaDataOptions(62);
  const symbol = { ...opts.symbolTables![0]!.entries[0]! };
  opts.symbolTables![0]!.entries = [{ ...symbol, info: 0x12 }, { ...symbol, info: 0x1a }];
  await decodeElfSymbolNames({ ...relocationFixture().elf, symbolTables: opts.symbolTables! });

  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), []);
});

void test("allocated COMMON objects and full-width end boundaries are valid", () => {
  const opts = elfIsaDataOptions(62);
  const symbol = opts.symbolTables![0]!.entries[0]!;
  symbol.info = 0x15;
  symbol.name = "ordinary_common";
  symbol.value = 0n;
  opts.sections[0]!.addr = 0n;
  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), [{ start: 0n, end: 8n }]);
  symbol.value = 0xffff_ffff_ffff_fff8n;
  opts.sections[0]!.addr = symbol.value;
  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), [{ start: symbol.value,
    end: 0x1_0000_0000_0000_0000n }]);
});

void test("unnamed out-of-bounds objects produce an exact visible warning", () => {
  const opts = elfIsaDataOptions(62);
  Object.assign(opts.symbolTables![0]!.entries[0]!, { info: 0x11, name: "", size: 100n });
  const issues: string[] = [];

  assert.deepEqual(collectElfCodeExclusions(opts, 32, issues), []);
  assert.deepEqual(issues, ["Data symbol (unnamed) extends outside its section; ignored."]);
});

void test("ELF relocatable and unresolved relocation records do not imply dynamic pointer cells", () => {
  const opts = elfIsaDataOptions(62);
  delete opts.symbolTables;
  opts.fileType = 1;
  opts.relocations = { tables: [], issues: [], entries: [{ tableIndex: 0,
    recordOffset: 0, offset: 0x1008n, type: 6, symbolIndex: 1,
    symbol: null, addend: null, target: null }] };

  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), []);
  opts.fileType = 3;
  opts.relocations.entries[0]!.type = null;
  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), []);
});

void test("nonallocated and ambiguous relocatable sections cannot suppress executable bytes", () => {
  const opts = elfIsaDataOptions(62);
  opts.symbolTables![0]!.entries[0]!.info = 0x11;
  opts.sections[0]!.flags = 0n;
  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), []);
  opts.fileType = 1;
  opts.symbolTables![0]!.entries[0]!.value = 8n;
  opts.sections[0]!.flags = 2n;
  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), []);
  opts.sections[0]!.flags = 6n;
  opts.sections.push({ ...opts.sections[0]!, index: 4, name: ".text.other", offset: 16n });
  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), []);
});

void test("linked data sections retain their addresses even when nonexecutable sections overlap", () => {
  const opts = elfIsaDataOptions(62);
  opts.symbolTables![0]!.entries[0]!.info = 0x11;
  opts.sections[0]!.flags = 2n;
  opts.sections.push({ ...opts.sections[0]!, index: 4, flags: 6n });

  assert.deepEqual(collectElfCodeExclusions(opts, 32, []), [{ start: 0x1008n, end: 0x1010n }]);
});

for (const [flags, address] of [[2n, 0x1000n], [4n, 0xff0n], [4n, 0x1010n]]) {
  void test(`ET_REL distinct section at ${address} with flags ${flags} does not hide data`, () => {
    const opts = elfIsaDataOptions(62);
    opts.fileType = 1;
    Object.assign(opts.symbolTables![0]!.entries[0]!, { info: 0x11, value: 8n });
    opts.sections.push({ ...opts.sections[0]!, index: 4, flags: flags!, addr: address! });

    assert.deepEqual(collectElfCodeExclusions(opts, 32, []), [{ start: 0x1008n, end: 0x1010n }]);
  });
}

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeElfImportLinkage } from "../../../../analyzers/elf/import-linkage.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { relocationTable, relocationSection } from "../../../fixtures/elf-relocations.js";

const linkageImage = () => {
  const { elf } = dynamicRelocationFixture();
  elf.dynamic = { entries: [], needed: [], soname: null, rpath: null, runpath: null,
    init: null, fini: null, preinitArray: null, initArray: null, finiArray: null,
    flags: null, flags1: null, issues: [], terminated: true };
  elf.relocations = { tables: [relocationTable({ sources: ["DT_JMPREL"],
    symbolTableIndex: null })], entries: [{ tableIndex: 0, recordOffset: 64,
    offset: 0x1200n, type: 7, symbolIndex: 1,
    symbol: { name: "puts", value: 0n, sectionIndex: 0 }, addend: 0n, target: null }], issues: [] };
  return elf;
};

void test("cross-matches a JUMP_SLOT with a complete load mapping", () => {
  const report = analyzeElfImportLinkage(linkageImage())!;
  assert.equal(report.links[0]?.kind, "PLT slot");
  assert.deepEqual(report.links[0]?.loadSegments, [0]);
  assert.deepEqual(report.links[0]?.issues, []);
  assert.equal(report.binding, "Lazy binding permitted");
});

// Relocation IDs and machine IDs are independent ABI oracles (glibc elf.h).
for (const [machine, type, kind] of [
  [3, 7, "PLT slot"], [40, 22, "PLT slot"], [183, 1026, "PLT slot"],
  [243, 5, "PLT slot"], [62, 6, "GOT slot"], [3, 6, "GOT slot"],
  [40, 21, "GOT slot"], [183, 1025, "GOT slot"]
] as const) {
  void test(`classifies machine ${machine}, relocation ${type}`, () => {
    const elf = linkageImage();
    elf.header.machine = machine;
    elf.relocations!.entries[0]!.type = type;
    assert.equal(analyzeElfImportLinkage(elf)!.links[0]?.kind, kind);
  });
}

void test("distinguishes resolver relocations from imports and retains missing symbols", () => {
  const elf = linkageImage();
  Object.assign(elf.relocations!.entries[0]!, { type: 37, symbolIndex: 0, symbol: null });
  assert.equal(analyzeElfImportLinkage(elf)!.links[0]?.kind, "IFUNC resolver slot");
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links[0]?.issues, []);
  elf.relocations!.entries[0]!.symbolIndex = 1;
  assert.match(analyzeElfImportLinkage(elf)!.links[0]!.issues.join(), /symbol index zero/);
  elf.relocations!.entries[0]!.type = 7;
  assert.match(analyzeElfImportLinkage(elf)!.links[0]!.issues.join(), /no decoded symbol/);
});

void test("checks the entire slot and RELRO range without requiring section headers", () => {
  const elf = linkageImage();
  elf.sections = [];
  elf.programHeaders.push({ ...elf.programHeaders[0]!, type: 0x6474e552, index: 1,
    vaddr: 0x1200n, memsz: 8n }); // PT_GNU_RELRO: glibc elf.h.
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links[0]?.relroSegments, [1]);
  elf.programHeaders[1]!.memsz = 7n;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links[0]?.relroSegments, []);
  elf.relocations!.entries[0]!.offset = 0x17f9n; // Last eight-byte slot would cross PT_LOAD end.
  assert.match(analyzeElfImportLinkage(elf)!.links[0]!.issues.join(), /not contained/);
  elf.relocations!.entries[0]!.offset = 0x17f8n;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links[0]?.loadSegments, [0]);
});

void test("reports overlapping and read-only mappings and missing JMPREL", () => {
  const elf = linkageImage();
  elf.programHeaders[0]!.flags = 4; // PF_R without PF_W (gABI program headers).
  elf.relocations!.tables[0]!.sources = ["DT_RELA"];
  assert.match(analyzeElfImportLinkage(elf)!.links[0]!.issues.join(), /without PF_W/);
  assert.match(analyzeElfImportLinkage(elf)!.links[0]!.issues.join(), /not identified/);
  elf.programHeaders.push({ ...elf.programHeaders[0]!, index: 1 });
  assert.match(analyzeElfImportLinkage(elf)!.links[0]!.issues.join(), /overlapping/);
});

void test("retains unknown imported relocations without assigning GOT semantics", () => {
  const elf = linkageImage();
  elf.header.machine = 0;
  assert.equal(analyzeElfImportLinkage(elf)!.links[0]?.kind, "Other symbol relocation");
  assert.match(analyzeElfImportLinkage(elf)!.links[0]!.issues.join(), /Write size is unknown/);
  elf.relocations!.entries[0]!.symbol = null;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links, []);
});

void test("excludes relocatable files, static relocations and NONE records", () => {
  const elf = linkageImage();
  elf.header.type = 1;
  assert.equal(analyzeElfImportLinkage(elf), null);
  elf.header.type = 3;
  elf.relocations!.tables[0]!.sources = [".rela.debug_info"];
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links, []);
  elf.relocations!.tables[0]!.sources = ["DT_RELA"];
  elf.relocations!.entries[0]!.type = 0;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links, []);
  elf.relocations!.entries[0]!.tableIndex = 20;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links, []);
  delete elf.relocations;
  delete elf.dynamic;
  assert.equal(analyzeElfImportLinkage(elf), null);
});

for (const [tag, value] of [[24, 0n], [30, 8n], [0x6ffffffb, 1n]] as const) {
  void test(`honors immediate binding tag ${tag}`, () => {
    const elf = linkageImage();
    elf.dynamic!.entries.push({ tag, value });
    assert.equal(analyzeElfImportLinkage(elf)!.binding, "Immediate binding requested");
  });
}

void test("keeps invalid and absent binding metadata uncertain and propagates parse warnings", () => {
  const elf = linkageImage();
  elf.dynamic!.entries = [{ tag: 30, value: 8n }, { tag: 30, value: 0n }];
  elf.relocations!.issues.push("truncated relocation table");
  assert.match(analyzeElfImportLinkage(elf)!.binding, /Unknown/);
  assert.match(analyzeElfImportLinkage(elf)!.issues.join(), /conflicting|truncated/);
  elf.dynamic!.entries = [];
  elf.dynamic!.terminated = false;
  assert.match(analyzeElfImportLinkage(elf)!.binding, /Unknown/);
  delete elf.dynamic;
  assert.equal(analyzeElfImportLinkage(elf)!.binding, "Unknown (no dynamic table)");
});

void test("accepts allocated DYNSYM relocations but ignores debug relocations", () => {
  const elf = linkageImage();
  elf.sections = [relocationSection(2, { type: 11 }),
    relocationSection(4, { flags: 2n }),
    relocationSection(5, { name: ".got.plt", flags: 2n, addr: 0x1200n, size: 8n })];
  Object.assign(elf.relocations!.tables[0]!, { sources: [".rela.plt"], symbolTableIndex: 2 });
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links[0]?.sections, [5]);
  elf.sections[1]!.flags = 0n;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links, []);
});

void test("handles generic, defined, missing-type and absent-relocation symbols conservatively", () => {
  const elf = linkageImage();
  elf.relocations!.entries[0]!.type = null;
  assert.equal(analyzeElfImportLinkage(elf)!.links[0]?.kind, "Other symbol relocation");
  elf.relocations!.entries[0]!.symbol!.sectionIndex = 1;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links, []);
  delete elf.relocations;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links, []);
  elf.header.type = 2; // ET_EXEC (gABI ELF header).
  assert.ok(analyzeElfImportLinkage(elf));
  elf.header.type = 4; // ET_CORE.
  assert.equal(analyzeElfImportLinkage(elf), null);
});

void test("validates four-byte RISC-V slot bounds and rejects negative ranges", () => {
  const elf = linkageImage();
  elf.header.machine = 243;
  elf.is64 = false;
  elf.relocations!.entries[0]!.type = 5; // R_RISCV_JUMP_SLOT (RISC-V psABI).
  elf.relocations!.entries[0]!.offset = 0x17fcn;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links[0]?.loadSegments, [0]);
  elf.programHeaders[0]!.vaddr = -1n;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links[0]?.loadSegments, []);
  elf.programHeaders[0]!.vaddr = 0x1000n;
  elf.programHeaders[0]!.memsz = -1n;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links[0]?.loadSegments, []);
});

void test("accepts repeated equal flags and rejects out-of-range policy values", () => {
  const elf = linkageImage();
  elf.dynamic!.entries = [{ tag: 30, value: 8n }, { tag: 30, value: 8n },
    { tag: 3, value: 0x1200n }];
  assert.equal(analyzeElfImportLinkage(elf)!.binding, "Immediate binding requested");
  elf.dynamic!.entries = [{ tag: 30, value: 0x100000000n }];
  assert.match(analyzeElfImportLinkage(elf)!.binding, /Unknown/);
  elf.dynamic!.entries = [{ tag: 30, value: -1n }];
  assert.match(analyzeElfImportLinkage(elf)!.binding, /Unknown/);
});

void test("validates DT_PLTGOT without treating it as a complete GOT range", () => {
  const elf = linkageImage();
  elf.dynamic!.entries = [{ tag: 3, value: 0x1200n }];
  assert.deepEqual(analyzeElfImportLinkage(elf)!.issues, []);
  elf.dynamic!.entries.push({ tag: 3, value: 0x9000n });
  assert.match(analyzeElfImportLinkage(elf)!.issues.join(), /conflicting addresses/);
  assert.match(analyzeElfImportLinkage(elf)!.issues.join(), /outside PT_LOAD/);
});

void test("reports slot writes that overflow the ELF address space", () => {
  const elf = linkageImage();
  elf.relocations!.entries[0]!.offset = 0xffffffffffffffffn;
  assert.match(analyzeElfImportLinkage(elf)!.links[0]!.issues.join(), /address space/);
  elf.relocations!.entries[0]!.offset = -1n;
  assert.match(analyzeElfImportLinkage(elf)!.links[0]!.issues.join(), /address space/);
});

void test("accepts exact zero-address and address-space-end slots, rejects underflow", () => {
  const elf = linkageImage();
  Object.assign(elf.programHeaders[0]!, { vaddr: 0n, memsz: 8n });
  elf.relocations!.entries[0]!.offset = 0n;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links[0]?.issues, []);
  Object.assign(elf.programHeaders[0]!, { vaddr: 0xfffffffffffffff8n, memsz: 8n });
  elf.relocations!.entries[0]!.offset = 0xfffffffffffffff8n;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links[0]?.issues, []);
  elf.relocations!.entries[0]!.offset = 0xfffffffffffffff0n;
  assert.match(analyzeElfImportLinkage(elf)!.links[0]!.issues.join(), /not contained/);
  elf.programHeaders[0]!.memsz = 0n;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links[0]?.loadSegments, []);
});

void test("does not mistake other segments or nonallocated sections for slot mappings", () => {
  const elf = linkageImage();
  elf.programHeaders[0]!.type = 2;
  elf.sections = [relocationSection(7, { addr: 0x1200n, size: 8n })];
  const link = analyzeElfImportLinkage(elf)!.links[0]!;
  assert.deepEqual(link.loadSegments, []);
  assert.deepEqual(link.sections, []);
  assert.deepEqual(link.relroSegments, []);
});

void test("requires both the correct symbol table identity and DYNSYM type", () => {
  const elf = linkageImage();
  elf.relocations!.tables[0]!.sources = [".rela.plt"];
  elf.sections = [relocationSection(2, { type: 2 }),
    relocationSection(4, { flags: 2n }), relocationSection(6, { type: 11 })];
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links, []);
  elf.relocations!.tables[0]!.sources.push("DT_JMPREL");
  assert.equal(analyzeElfImportLinkage(elf)!.links.length, 1);
});

void test("zero flags permit lazy binding and DT_BIND_NOW ignores its payload", () => {
  const elf = linkageImage();
  elf.dynamic!.entries = [{ tag: 30, value: 0n }, { tag: 0x6ffffffb, value: 0n }];
  assert.equal(analyzeElfImportLinkage(elf)!.binding, "Lazy binding permitted");
  elf.dynamic!.entries = [{ tag: 30, value: 0xffffffffn }];
  assert.equal(analyzeElfImportLinkage(elf)!.binding, "Immediate binding requested");
  elf.dynamic!.entries = [{ tag: 24, value: 0n }, { tag: 24, value: 7n }];
  assert.equal(analyzeElfImportLinkage(elf)!.binding, "Immediate binding requested");
  assert.deepEqual(analyzeElfImportLinkage(elf)!.issues, []);
});

void test("preserves symbol/version warnings and validates only the DT_PLTGOT address", () => {
  const elf = linkageImage();
  elf.dynamic!.entries = [{ tag: 3, value: 0x1200n }, { tag: 11, value: 24n }];
  elf.dynSymbols = { total: 1, importSymbols: [], exportSymbols: [], issues: ["short dynsym"] };
  elf.symbolVersions = { definitions: [], requirements: [], symbols: [], issues: ["short versym"] };
  assert.deepEqual(analyzeElfImportLinkage(elf)!.issues, ["short dynsym", "short versym"]);
  delete elf.dynamic;
  delete elf.relocations;
  assert.deepEqual(analyzeElfImportLinkage(elf)!.links, []);
});

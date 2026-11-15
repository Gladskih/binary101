import assert from "node:assert/strict";
import { test } from "node:test";
import { renderElfImportLinkage, createElfImportLinkageModel } from
  "../../../../renderers/elf/import-linkage.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { analyzeElfImportLinkage } from "../../../../analyzers/elf/import-linkage.js";
import { relocationTable, relocationSection } from "../../../fixtures/elf-relocations.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { getElfLazySections, renderElfLazy } from "../../../../renderers/elf/lazy-sections.js";

const linkedImage = () => {
  const { elf } = dynamicRelocationFixture();
  elf.relocations = { issues: [], tables: [relocationTable({ sources: ["DT_JMPREL"],
    symbolTableIndex: null })], entries: [{ tableIndex: 0, recordOffset: 64,
    offset: 0x1200n, type: 7, symbolIndex: 1, symbol: {
      name: "<puts>", value: 0n, sectionIndex: 0 }, addend: 0n, target: null }] };
  elf.symbolVersions = { definitions: [], symbols: [0, 2], issues: [], requirements: [{
    file: "<libc.so>", versions: [{ index: 2, flags: 0, hash: 0, name: "<LIBC_1>" }] }] };
  elf.importLinkage = analyzeElfImportLinkage(elf)!;
  return elf;
};

void test("omits absent analysis and exposes an empty, pageable analysis", () => {
  const { elf } = dynamicRelocationFixture();
  const out: string[] = [];
  renderElfImportLinkage(elf, out);
  assert.deepEqual(out, []);
  assert.equal(createElfImportLinkageModel(elf).rowCount, 0);
  elf.importLinkage = { binding: "Lazy binding permitted", links: [], issues: ["<truncated>"] };
  renderElfImportLinkage(elf, out);
  assert.match(out.join(""), /Import linkage|&lt;truncated>/);
  assert.equal(createElfImportLinkageModel(elf).rowCount, 0);
  assert.equal(createElfImportLinkageModel(elf).rowAt(0), null);
});

void test("renders escaped linkage, version requirements and placement with paging", () => {
  const elf = linkedImage();
  const model = createElfImportLinkageModel(elf);
  assert.equal(model.rowCount, 1);
  assert.equal(model.rowAt(0)?.cells[0]?.html, "&lt;puts>");
  assert.equal(model.sortValueAt(0, 1), "<LIBC_1> (<libc.so>)");
  assert.equal(model.sortValueAt(0, 2), "PLT slot");
  assert.equal(model.sortValueAt(0, 3), "R_X86_64_JUMP_SLOT");
  assert.equal(model.sortValueAt(0, 4), "DT_JMPREL");
  assert.equal(model.sortValueAt(0, 5), "-");
  assert.equal(model.sortValueAt(0, 6), "Not covered");
  assert.equal(model.sortValueAt(0, 99), "");
  assert.equal(model.sortValueAt(99, 0), "");
  assert.equal(getElfPagedTableModel(elf, "elf-import-linkage")?.rowCount, 1);
  const out: string[] = [];
  renderElfImportLinkage(elf, out);
  assert.match(out.join(""), /Run ISA analysis/);
  assert.match(out.join(""), /&lt;LIBC_1> \(&lt;libc.so>\)/);
  assert.match(renderElfLazy(elf), /data-analysis-origin="supplemental"[^>]+import-linkage/);
  assert.match(getElfLazySections(elf).find(section => section.key === "import-linkage")!.render(),
    /R_X86_64_JUMP_SLOT/);
});

void test("does not attach a global versym index to a different symbol table", () => {
  const elf = linkedImage();
  elf.relocations!.tables[0]!.symbolTableIndex = 2;
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 1),
    "Unknown (symbol table identity)");
});

void test("rejects non-DYNSYM and conflicting dynamic symbol table addresses for versions", () => {
  const elf = linkedImage();
  elf.relocations!.tables[0]!.symbolTableIndex = 2;
  elf.sections = [relocationSection(2, { type: 11, addr: 0x1400n })];
  elf.dynamic = { entries: [{ tag: 6, value: 0x1400n }, { tag: 6, value: 0x1500n }],
    needed: [], soname: null, rpath: null, runpath: null, init: null, fini: null,
    preinitArray: null, initArray: null, finiArray: null, flags: null, flags1: null, issues: [] };
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 1),
    "Unknown (symbol table identity)");
  elf.dynamic.entries.pop();
  elf.sections[0]!.type = 2;
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 1),
    "Unknown (symbol table identity)");
});

void test("resolves section names without numeric formatting", () => {
  const elf = linkedImage();
  elf.sections = [relocationSection(5, { name: ".got.plt" })];
  elf.importLinkage!.links[0]!.sections = [5];
  const model = createElfImportLinkageModel(elf);
  assert.equal(model.sortValueAt(0, 5), ".got.plt");
  assert.equal(model.columns[5]?.className, "");
  assert.equal(model.columns[0]?.className, "");
  assert.equal(model.rowAt(0)?.cells[5]?.className, "");
  assert.equal(model.rowAt(0)?.cells[0]?.className, "");
});

void test("resolves a confirmed DYNSYM identity and retains unknown version indices", () => {
  const elf = linkedImage();
  elf.relocations!.tables[0]!.symbolTableIndex = 2;
  elf.sections = [relocationSection(2, { type: 11, addr: 0x1400n })];
  elf.dynamic = { entries: [{ tag: 6, value: 0x1400n }, { tag: 3, value: 0x1200n }],
    needed: [], soname: null, rpath: null, runpath: null, init: null, fini: null,
    preinitArray: null, initArray: null, finiArray: null, flags: null, flags1: null, issues: [] };
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 1), "<LIBC_1> (<libc.so>)");
  elf.symbolVersions!.symbols[1] = 0x8003; // GNU hidden bit and unrecognized index 3.
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 1), "Unknown version #3");
  elf.symbolVersions!.symbols[1] = 1;
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 1), "-");
  elf.symbolVersions!.symbols = [];
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 1), "-");
  const out: string[] = [];
  renderElfImportLinkage(elf, out);
  assert.match(out.join(""), /0x1200/);
});

void test("retains malformed references, resolver slots and section identities", () => {
  const elf = linkedImage();
  const link = elf.importLinkage!.links[0]!;
  Object.assign(link, { kind: "IFUNC resolver slot", sections: [9], loadSegments: [],
    relroSegments: [2], issues: ["<bad slot>"] });
  Object.assign(elf.relocations!.entries[0]!, { symbol: null, symbolIndex: 0, type: null });
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 0), "Local resolver");
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 3), "Unknown");
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 5), "#9");
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 6), "Covered");
  assert.equal(createElfImportLinkageModel(elf).rowAt(0)?.cells[7]?.html, "&lt;bad slot>");
  link.kind = "PLT slot";
  elf.relocations!.tables = [];
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 0), "Unknown");
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 4), "Unknown");
  elf.importLinkage!.links[0]!.relocationIndex = 99;
  assert.deepEqual(createElfImportLinkageModel(elf).rowAt(0)?.cells, []);
});

void test("adds exact code evidence after ISA and keeps missing evidence uncertain", () => {
  const elf = linkedImage();
  elf.disassembly = { bitness: 64, bytesSampled: 10, bytesDecoded: 10, instructionCount: 2,
    invalidInstructionCount: 0, instructionSets: [], issues: [], importCode: [{
      slotAddress: 0x1200n, stubAddresses: [0x1100n], references: [{
        kind: "Call to stub", count: 1, sampleAddresses: [0x1000n] }] }] };
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 9), "0");
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 10), "1");
  const out: string[] = [];
  renderElfImportLinkage(elf, out);
  assert.match(out.join(""), /ISA results available/);
  elf.disassembly.importCode = [];
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 10), "0");
  assert.equal(createElfImportLinkageModel(elf).sortValueAt(0, 11), "0");
  delete elf.disassembly.importCode;
  renderElfImportLinkage(elf, out);
  assert.match(out.join(""), /No supported code evidence/);
});

void test("separates slot and stub CALL/JMP counts and omits address columns", () => {
  const elf = linkedImage();
  elf.disassembly = { bitness: 64, bytesSampled: 10, bytesDecoded: 10, instructionCount: 14,
    invalidInstructionCount: 0, instructionSets: [], issues: [], importCode: [{
      slotAddress: 0x1200n, stubAddresses: [0x1100n], references: [
        { kind: "Indirect call", count: 2, sampleAddresses: [0x1000n] },
        { kind: "Indirect jump", count: 3, sampleAddresses: [0x1010n] },
        { kind: "Call to stub", count: 4, sampleAddresses: [0x1020n] },
        { kind: "Jump to stub", count: 5, sampleAddresses: [0x1030n] }
      ] }] };
  const model = createElfImportLinkageModel(elf);
  const headings = model.columns.map(column => column.label);
  assert.doesNotMatch(headings.join("|"), /Target VA|Jump stubs|sample VAs/);
  assert.deepEqual(headings.slice(-4), ["Slot CALL refs", "Slot JMP refs",
    "Stub CALL refs", "Stub JMP refs"]);
  assert.deepEqual(model.rowAt(0)!.cells.slice(-4).map(cell => cell.sortValue), ["2", "3", "4", "5"]);
  assert.ok(model.rowAt(0)!.cells.slice(-4).every(cell => cell.className === "peNumeric"));
  assert.ok(model.columns.slice(-4).every(column => column.className === "peNumeric"));
  assert.doesNotMatch(model.rowAt(0)!.cells.map(cell => cell.html).join("|"), /0x1200|0x1100|0x1000/);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { locateElfRelocationTarget } from "../../../../analyzers/elf/relocation-targets.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { relocationTable } from "../../../fixtures/elf-relocations.js";

void test("ET_REL target can be file-backed or NOBITS, but must lie inside sh_info", () => {
  const fixture = dynamicRelocationFixture();
  fixture.elf.header.type = 1;
  const table = relocationTable();
  const issues: string[] = [];

  assert.equal(locateElfRelocationTarget(fixture.elf, table, 31n, issues)?.fileOffset, 543n);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 32n, issues), null);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, -1n, issues), null);
  assert.equal(locateElfRelocationTarget(fixture.elf,
    relocationTable({ targetSectionIndex: 99 }), 0n, issues), null);
  fixture.elf.sections[1]!.type = 8; // gABI SHT_NOBITS.
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 8n, issues)?.fileOffset, null);
  fixture.elf.sections[1]!.type = 1;
  fixture.elf.sections[1]!.offset = 1024n;
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 8n, issues)?.fileOffset, null);
  assert.match(issues.join(" "), /outside the file/);
});

void test("ET_DYN targets use PT_LOAD virtual addresses including BSS", () => {
  const fixture = dynamicRelocationFixture();
  fixture.elf.sections[1]!.addr = 0x1200n;
  fixture.elf.sections[1]!.flags = 2n; // gABI SHF_ALLOC.
  const issues: string[] = [];

  assert.deepEqual(locateElfRelocationTarget(fixture.elf, relocationTable(), 0x1208n, issues),
    { sectionIndex: 1, sectionOffset: 8n, fileOffset: 520n });
  assert.deepEqual(locateElfRelocationTarget(fixture.elf, relocationTable(), 0x1400n, issues),
    { sectionIndex: null, sectionOffset: null, fileOffset: null });
  assert.equal(locateElfRelocationTarget(fixture.elf, relocationTable(), 0x1800n, issues), null);
  assert.match(issues.join(" "), /outside PT_LOAD/);
});

void test("RELR targets require a whole pointer-sized memory range", () => {
  const fixture = dynamicRelocationFixture();
  const issues: string[] = [];

  assert.equal(locateElfRelocationTarget(fixture.elf,
    relocationTable({ encoding: "RELR" }), 0x17fen, issues), null);
  assert.match(issues.join(" "), /outside PT_LOAD/);
});

void test("virtual targets respect section allocation and both boundaries", () => {
  const fixture = dynamicRelocationFixture();
  const section = fixture.elf.sections[1]!;
  section.addr = 0x1200n;
  const table = relocationTable();

  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x1200n, [])?.sectionIndex, null);
  section.flags = 2n;
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x11ffn, [])?.sectionIndex, null);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x1200n, [])?.sectionIndex, 1);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x121fn, [])?.sectionIndex, 1);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x1220n, [])?.sectionIndex, null);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x1000n, [])?.fileOffset, 0n);
});

void test("only PT_LOAD contributes zero-fill memory and its start is inclusive", () => {
  const fixture = dynamicRelocationFixture();
  const table = relocationTable();
  const issues: string[] = [];
  fixture.elf.programHeaders[0]!.filesz = 0n;
  fixture.elf.programHeaders.push({ ...fixture.elf.programHeaders[0]!, type: 2 });

  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x1000n, [])?.fileOffset, null);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0xfffn, issues), null);
  fixture.elf.programHeaders[0]!.type = 2;
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x1000n, issues), null);
  assert.match(issues.join(" "), /outside PT_LOAD/);
});

void test("ELF32 RELR validates four-byte targets at the memory boundary", () => {
  const fixture = dynamicRelocationFixture(32);
  const table = relocationTable({ encoding: "RELR" });

  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x17fcn, [])?.fileOffset, null);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x17fen, []), null);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { locateElfRelocationTarget } from "../../../../analyzers/elf/relocation-targets.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { relocationSection, relocationTable } from "../../../fixtures/elf-relocations.js";

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

void test("compressed target offsets are bounded against decoded bytes and have no direct file offset", () => {
  const fixture = dynamicRelocationFixture();
  fixture.elf.header.type = 1;
  fixture.elf.sections[1]!.flags = 0x800n; // ELF gABI 3.7: SHF_COMPRESSED.
  const issues: string[] = [];

  assert.deepEqual(locateElfRelocationTarget(fixture.elf, relocationTable(), 40n, issues,
    undefined, new Map([[1, 64n]])), { sectionIndex: 1, sectionOffset: 40n, fileOffset: null });
  assert.deepEqual(issues, []);
  assert.equal(locateElfRelocationTarget(fixture.elf, relocationTable(), 64n, issues,
    undefined, new Map([[1, 64n]])), null);
  assert.equal(locateElfRelocationTarget(fixture.elf, relocationTable(), -1n, issues,
    undefined, new Map([[1, 64n]])), null);
  assert.equal(locateElfRelocationTarget(fixture.elf, relocationTable(), 0n, issues), null);
  assert.match(issues.join(" "), /Compressed|outside/);
});

void test("ET_DYN targets use PT_LOAD virtual addresses including BSS", () => {
  const fixture = dynamicRelocationFixture();
  fixture.elf.sections[1]!.addr = 0x1200n;
  fixture.elf.sections[1]!.flags = 2n; // gABI SHF_ALLOC.
  // Ordinary .bss is SHT_NOBITS with SHF_ALLOC|SHF_WRITE and belongs to PT_LOAD.
  // https://gabi.xinuos.com/elf/03-sheader.html#special-sections
  fixture.elf.sections.push(relocationSection(4, { type: 8, flags: 3n, addr: 0x1400n, size: 16n }));
  const issues: string[] = [];

  assert.deepEqual(locateElfRelocationTarget(fixture.elf, relocationTable(), 0x1208n, issues),
    { sectionIndex: 1, sectionOffset: 8n, fileOffset: 520n });
  assert.deepEqual(locateElfRelocationTarget(fixture.elf, relocationTable(), 0x1400n, issues),
    { sectionIndex: 4, sectionOffset: 0n, fileOffset: null });
  assert.deepEqual(locateElfRelocationTarget(fixture.elf, relocationTable(), 0x1410n, issues),
    { sectionIndex: null, sectionOffset: null, fileOffset: null });
  assert.equal(locateElfRelocationTarget(fixture.elf, relocationTable(), 0x1800n, issues), null);
  assert.match(issues.join(" "), /outside PT_LOAD/);
});

void test("RELR targets require a whole pointer-sized memory range", () => {
  const fixture = dynamicRelocationFixture();
  const issues: string[] = [];

  assert.equal(locateElfRelocationTarget(fixture.elf,
    relocationTable({ encoding: "RELR", targetSectionIndex: null }), 0x17fen, issues), null);
  assert.match(issues.join(" "), /outside PT_LOAD/);
});

void test("virtual targets respect section allocation and both boundaries", () => {
  const fixture = dynamicRelocationFixture();
  const section = fixture.elf.sections[1]!;
  section.addr = 0x1200n;
  const table = relocationTable({ targetSectionIndex: null });

  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x1200n, [])?.sectionIndex, null);
  section.flags = 2n;
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x11ffn, [])?.sectionIndex, null);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x1200n, [])?.sectionIndex, 1);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x121fn, [])?.sectionIndex, 1);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x1220n, [])?.sectionIndex, null);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x1000n, [])?.fileOffset, 0n);
});

// ET_EXEC=2, ET_DYN=3. https://gabi.xinuos.com/elf/02-eheader.html
for (const [type, name] of [[2, "ET_EXEC"], [3, "ET_DYN"]] as const) {
  void test(`${name} relocations can target a non-allocated section named by sh_info`, () => {
    const fixture = dynamicRelocationFixture();
    fixture.elf.header.type = type;
    fixture.elf.programHeaders[0]!.vaddr = 0n; // The first load overlaps debug offsets numerically.
    const table = relocationTable();
    const issues: string[] = [];

    assert.deepEqual(locateElfRelocationTarget(fixture.elf, table, 8n, issues), {
      sectionIndex: 1, sectionOffset: 8n, fileOffset: 520n
    });
    assert.deepEqual(issues, []);
    assert.equal(locateElfRelocationTarget(fixture.elf, table, 32n, issues), null);
    assert.match(issues.join(" "), /outside its target section/);
  });
}

void test("load relocations skip TLS zero-fill when it overlaps file-backed data", () => {
  const fixture = dynamicRelocationFixture();
  // gABI TLS template: SHT_NOBITS=8, SHF_ALLOC|SHF_WRITE|SHF_TLS=0x403.
  // https://gabi.xinuos.com/elf/07-pheader.html#thread-local-storage
  fixture.elf.sections.push(
    relocationSection(4, { type: 8, flags: 0x403n, addr: 0x1150n, size: 32n }),
    relocationSection(5, { flags: 3n, addr: 0x1150n, offset: 0x150n, size: 8n }),
    relocationSection(6, { flags: 0x403n, addr: 0x1148n, offset: 0x148n, size: 8n })
  );
  const table = relocationTable({ encoding: "RELR", targetSectionIndex: null });
  const issues: string[] = [];

  assert.deepEqual(locateElfRelocationTarget(fixture.elf, table, 0x1150n, issues), {
    sectionIndex: 5, sectionOffset: 0n, fileOffset: 0x150n
  });
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x1158n, issues)?.sectionIndex, null);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x1148n, issues)?.sectionIndex, 6);
  assert.deepEqual(issues, []);
});

void test("only PT_LOAD contributes zero-fill memory and its start is inclusive", () => {
  const fixture = dynamicRelocationFixture();
  const table = relocationTable({ targetSectionIndex: null });
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
  const table = relocationTable({ encoding: "RELR", targetSectionIndex: null });

  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x17fcn, [])?.fileOffset, null);
  assert.equal(locateElfRelocationTarget(fixture.elf, table, 0x17fen, []), null);
});

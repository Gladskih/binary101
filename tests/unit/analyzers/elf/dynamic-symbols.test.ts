"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { parseElfDynamicSymbols } from "../../../../analyzers/elf/dynamic-symbols.js";
import { createElfGnuHashDynamicFixture } from "../../../fixtures/elf-gnu-hash-file.js";
import { createElfFile } from "../../../fixtures/elf-sample-file.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";
import type { ElfRelocationSymbol } from "../../../../analyzers/elf/relocation-types.js";

// gABI 3/5/8: Elf32_Sym is 16 bytes, Elf64_Sym is 24 bytes.
// https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
for (const bits of [32, 64] as const) {
  for (const size of [0n, 1n, 48n]) {
    void test(`rejects ELF${bits} dynamic section symbol stride ${size}`, async () => {
      const fixture = relocationFixture(bits);
      fixture.elf.sections[2]!.type = 11;
      fixture.elf.sections[2]!.entsize = size;

      const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf });

      assert.equal(result?.total, 0);
      assert.deepEqual(result?.exportSymbols, []);
      assert.match(result!.issues.join(" "), /entry size/);
    });
  }
}

for (const size of [0n, 16n, 48n, 0xffffffffffffffffn]) {
  void test(`rejects invalid DT_SYMENT ${size}`, async () => {
    const fixture = createElfGnuHashDynamicFixture();
    const bytes = await fixture.file.arrayBuffer();
    // Fixture's fourth Elf64_Dyn: d_val at +8.
    new DataView(bytes).setBigUint64(0x120 + 3 * 16 + 8, size, true);

    const result = await parseElfDynamicSymbols({ file: new File([bytes], "stride.elf"),
      programHeaders: fixture.programHeaders, sections: [], is64: true, littleEndian: true });

    assert.equal(result?.total, 0);
    assert.match(result!.issues.join(" "), /DT_SYMENT/);
  });
}

void test("dynamic symbol total includes types omitted from import/export tables", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11; // SHT_DYNSYM, gABI 3.
  fixture.bytes[284] = 3; // ELF64 st_info: STB_LOCAL / STT_SECTION, gABI 5.
  const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf });
  assert.equal(result?.total, 2);
  assert.deepEqual(result?.importSymbols, []);
  assert.deepEqual(result?.exportSymbols, []);
});

void test("parseElfDynamicSymbols returns imports and exports from .dynsym/.dynstr", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const info = await parseElfDynamicSymbols({
    file,
    programHeaders: elf.programHeaders,
    sections: elf.sections,
    is64: elf.is64,
    littleEndian: elf.littleEndian
  });
  assert.ok(info);
  assert.equal(info.importSymbols.some(sym => sym.name === expected.importSymbol), true);
  assert.equal(info.exportSymbols.some(sym => sym.name === expected.exportSymbol), true);
});

void test("parseElfDynamicSymbols returns null when dynsym is missing", async () => {
  const file = createElfFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const info = await parseElfDynamicSymbols({
    file,
    programHeaders: elf.programHeaders,
    sections: elf.sections,
    is64: elf.is64,
    littleEndian: elf.littleEndian
  });
  assert.equal(info, null);
});

void test("parseElfDynamicSymbols reads sectionless GNU-hash dynsym tables", async () => {
  const fixture = createElfGnuHashDynamicFixture();
  const info = await parseElfDynamicSymbols({
    file: fixture.file,
    programHeaders: fixture.programHeaders,
    sections: [],
    is64: true,
    littleEndian: true
  });

  assert.ok(info);
  assert.equal(info.exportSymbols.length, 1);
  assert.equal(info.exportSymbols[0]?.name, fixture.symbolName);
  assert.equal(info.exportSymbols[0]?.value, fixture.symbolVaddr);
});

void test("shared relocation cache excludes unterminated dynamic symbol names", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11; // SHT_DYNSYM.
  fixture.bytes[391] = 65; // Replace the final string-table NUL.
  const cache = new Map<number, ElfRelocationSymbol>();

  await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf }, [], cache);

  assert.equal(cache.has(280), false);
});

void test("rejects dynamic symbols extending beyond their load segment", async () => {
  const fixture = createElfGnuHashDynamicFixture();
  // Fixture .dynsym ends at 0xf0; PT_LOAD starts at 0x40. Clip its last byte.
  fixture.programHeaders[0]!.filesz = 0xafn;

  const result = await parseElfDynamicSymbols({ file: fixture.file,
    programHeaders: fixture.programHeaders, sections: [], is64: true, littleEndian: true });

  assert.deepEqual(result?.exportSymbols, []);
  assert.match(result!.issues.join(" "), /DT_SYMTAB.*PT_LOAD/);
});

void test("accepts dynamic symbols ending exactly at the load segment boundary", async () => {
  const fixture = createElfGnuHashDynamicFixture();
  fixture.programHeaders[0]!.filesz = 0xb0n;

  const result = await parseElfDynamicSymbols({ file: fixture.file,
    programHeaders: fixture.programHeaders, sections: [], is64: true, littleEndian: true });

  assert.equal(result?.exportSymbols[0]?.name, fixture.symbolName);
  assert.deepEqual(result?.issues, []);
});

void test("rejects dynamic strings extending beyond their load segment", async () => {
  const fixture = createElfGnuHashDynamicFixture();
  const bytes = await fixture.file.arrayBuffer();
  // Fixture's second Elf64_Dyn is DT_STRSZ; extend beyond PT_LOAD and EOF.
  new DataView(bytes).setBigUint64(0x120 + 16 + 8, BigInt(bytes.byteLength), true);

  const result = await parseElfDynamicSymbols({ file: new File([bytes], "strings.elf"),
    programHeaders: fixture.programHeaders, sections: [], is64: true, littleEndian: true });

  assert.deepEqual(result?.exportSymbols, []);
  assert.match(result!.issues.join(" "), /DT_STRTAB.*PT_LOAD/);
});

// gABI 5.4: DEFAULT/PROTECTED are externally visible; INTERNAL/HIDDEN are not.
// https://gabi.xinuos.com/elf/05-symtab.html#symbol-visibility
for (const [visibility, exports] of [[0, 1], [1, 0], [2, 0], [3, 1]] as const) {
  void test(`classifies dynamic export visibility ${visibility}`, async () => {
    const fixture = relocationFixture();
    fixture.elf.sections[2]!.type = 11;
    fixture.bytes[284] = 0x12; // STB_GLOBAL | STT_FUNC.
    fixture.bytes[285] = visibility;

    const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf });

    assert.equal(result?.exportSymbols.length, exports);
    assert.deepEqual(result?.issues, []);
  });
}

void test("includes allocated STT_COMMON definitions in dynamic exports", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11;
  fixture.bytes[284] = 0x15; // STB_GLOBAL | STT_COMMON, gABI 5.3.

  const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf });

  assert.equal(result?.exportSymbols[0]?.name, "target");
  assert.equal(result?.exportSymbols[0]?.typeName, "COMMON");
});

for (const link of [0, 1, 99]) {
  void test(`rejects invalid dynamic string table link ${link} without name fallback`, async () => {
    const fixture = relocationFixture();
    fixture.elf.sections[2]!.type = 11;
    fixture.elf.sections[2]!.link = link;
    fixture.elf.sections[3]!.name = ".dynstr";
    fixture.bytes[284] = 0x12;

    const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf });

    assert.deepEqual(result?.exportSymbols, []);
    assert.match(result!.issues.join(" "), /sh_link.*SHT_STRTAB/);
  });
}

void test("rejects a nonempty PROGBITS section used as dynamic strings", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11;
  fixture.elf.sections[3]!.type = 1;
  fixture.bytes[284] = 0x12;

  const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf });

  assert.deepEqual(result?.exportSymbols, []);
  assert.match(result!.issues.join(" "), /sh_link.*SHT_STRTAB/);
});

void test("reports unterminated dynamic names without exporting or caching them", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11;
  fixture.bytes[284] = 0x12;
  fixture.bytes[391] = 65;
  const cache = new Map<number, ElfRelocationSymbol>();

  const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf }, [], cache);

  assert.deepEqual(result?.exportSymbols, []);
  assert.match(result!.issues.join(" "), /unterminated/);
  assert.equal(cache.has(280), false);
});

void test("reports dynamic name offsets at the end of the string table", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11;
  fixture.bytes[284] = 0x12;
  fixture.view.setUint32(280, 8, true); // Fixture string table has eight bytes.
  const cache = new Map<number, ElfRelocationSymbol>();

  const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf }, [], cache);

  assert.deepEqual(result?.exportSymbols, []);
  assert.match(result!.issues.join(" "), /string table offset/);
  assert.equal(cache.has(280), false);
});

for (const [bits, order, offset] of [
  [32, "little", 272], [32, "big", 272], [64, "little", 280], [64, "big", 280]
] as const) {
  void test(`caches valid ELF${bits} ${order} symbols at their file offsets`, async () => {
    const fixture = relocationFixture(bits, order);
    fixture.elf.sections[2]!.type = 11;
    fixture.bytes[284] = 0x12; // Fixture st_info offset for both classes.
    const cache = new Map<number, ElfRelocationSymbol>();

    const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf }, [], cache);

    assert.equal(result?.exportSymbols[0]?.name, "target");
    assert.deepEqual(cache.get(offset), { name: "target", value: 4n, sectionIndex: 1 });
    assert.deepEqual(result?.issues, []);
  });
}

void test("does not cache unresolved SHN_XINDEX dynamic symbols", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11;
  fixture.view.setUint16(286, 0xffff, true); // SHN_XINDEX, gABI 5.5.
  const cache = new Map<number, ElfRelocationSymbol>();

  await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf }, [], cache);

  assert.equal(cache.has(280), false);
});

// gABI 5: st_info binding nibble, SHN_UNDEF=0, string offset zero names nothing.
for (const [info, section, name, imports, exports] of [
  [0x12, 0, 1, 1, 0], [0x12, 1, 1, 0, 1], [0x02, 0, 1, 0, 0],
  [0x02, 1, 1, 0, 0], [0x12, 0, 0, 0, 0], [0x12, 1, 0, 0, 0]
] as const) {
  void test(`classifies symbols with info=${info}, section=${section}, name=${name}`, async () => {
    const fixture = relocationFixture();
    fixture.elf.sections[2]!.type = 11;
    fixture.bytes[284] = info;
    fixture.view.setUint16(286, section, true);
    fixture.view.setUint32(280, name, true);

    const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf });

    assert.equal(result?.importSymbols.length, imports);
    assert.equal(result?.exportSymbols.length, exports);
  });
}

for (const [bits, order, shndxOffset] of [
  [32, "little", 286], [32, "big", 286], [64, "little", 286], [64, "big", 286]
] as const) {
  void test(`resolves ELF${bits} ${order} dynamic SHN_XINDEX`, async () => {
    const fixture = relocationFixture(bits, order);
    fixture.elf.sections[2]!.type = 11;
    fixture.bytes[284] = 0x12;
    fixture.view.setUint16(shndxOffset, 0xffff, fixture.elf.littleEndian);
    fixture.elf.sections.push({ ...fixture.elf.sections[3]!, index: 4, type: 18,
      link: 2, offset: 640n, size: 8n, entsize: 4n });
    // gABI 5.5: SHN_XINDEX -> corresponding Elf32_Word in SHT_SYMTAB_SHNDX.
    // https://gabi.xinuos.com/elf/05-symtab.html
    fixture.view.setUint32(644, 0x10000, fixture.elf.littleEndian);

    const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf });

    assert.equal(result?.exportSymbols[0]?.shndx, 0x10000);
    assert.deepEqual(result?.issues, []);
  });
}

void test("warns and omits dynamic exports with unresolved SHN_XINDEX", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11;
  fixture.bytes[284] = 0x12;
  fixture.view.setUint16(286, 0xffff, true);

  const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf });

  assert.deepEqual(result?.exportSymbols, []);
  assert.match(result!.issues.join(" "), /SHN_XINDEX/);
});



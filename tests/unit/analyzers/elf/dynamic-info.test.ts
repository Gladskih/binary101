"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { parseElfDynamicInfo } from "../../../../analyzers/elf/dynamic-info.js";
import type { ElfProgramHeader, ElfSectionHeader } from "../../../../analyzers/elf/types.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";

const makeSection = (partial: Partial<ElfSectionHeader>): ElfSectionHeader =>
  ({
    nameOff: 0,
    type: 0,
    typeName: null,
    flags: 0n,
    flagNames: [],
    addr: 0n,
    offset: 0n,
    size: 0n,
    link: 0,
    info: 0,
    addralign: 0n,
    entsize: 0n,
    index: 0,
    ...partial
  }) as ElfSectionHeader;

void test("parseElfDynamicInfo reads DT_NEEDED / DT_SONAME / DT_RUNPATH", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  assert.ok(parsed);
  assert.ok(parsed.dynamic);
  assert.equal(parsed.dynamic.terminated, true);
  assert.deepEqual(parsed.dynamic.needed, expected.needed);
  assert.equal(parsed.dynamic.soname, expected.soname);
  assert.equal(parsed.dynamic.runpath, expected.runpath);
  assert.equal(parsed.dynamic.init, 0x401000n);
});

void test("preserves every dynamic record in order and resolves extended string tags", async () => {
  const fixture = dynamicStringsFixture("\0<audit.so>\0");
  // glibc elf/elf.h: AUDIT, DEPAUDIT, FILTER, AUXILIARY are string references.
  const entries = [
    { tag: 3, value: 0x400000n }, { tag: 21, value: 0n },
    { tag: 22, value: 0n }, { tag: 24, value: 0n },
    { tag: 0x6ffffefc, value: 1n }, { tag: 0x6ffffefb, value: 1n },
    { tag: 0x7fffffff, value: 1n }, { tag: 0x7ffffffd, value: 1n },
    { tag: 0x1234, value: 1n << 63n }, { tag: 3, value: 99n }
  ];
  const result = await parseElfDynamicInfo({ ...fixture, programHeaders: [] }, entries);
  assert.deepEqual(result?.entries.map(({ tag, value }) => ({ tag, value })), entries);
  assert.deepEqual(result?.entries.slice(4, 8).map(entry => entry.string),
    ["<audit.so>", "<audit.so>", "<audit.so>", "<audit.so>"]);
});

void test("keeps invalid audit string references and their warnings", async () => {
  const fixture = dynamicStringsFixture();
  const result = await parseElfDynamicInfo({ ...fixture, programHeaders: [] },
    [{ tag: 0x6ffffefc, value: 1n << 60n }]);
  assert.deepEqual(result?.entries, [{ tag: 0x6ffffefc, value: 1n << 60n, string: null }]);
  assert.match(result!.issues.join(" "), /reference|offset/);
});

void test("keeps unrecognized 64-bit tag identities without numeric conversion", async () => {
  const fixture = dynamicStringsFixture();
  const result = await parseElfDynamicInfo({ ...fixture, programHeaders: [] },
    [{ tag: (1n << 60n) + 1n, value: 0n }]);
  assert.deepEqual(result?.entries, [{ tag: (1n << 60n) + 1n, value: 0n }]);
});

void test("parseElfDynamicInfo falls back to linked strings when DT_STRTAB doesn't map", async () => {
  const dynstrText = "\0libc.so.6\0";
  const dynstrBytes = new TextEncoder().encode(dynstrText);
  const dynEntrySize = 16;
  const dynEntryCount = 4;
  const dynamicBytes = new Uint8Array(dynEntrySize * dynEntryCount).fill(0);
  const dv = new DataView(dynamicBytes.buffer);
  const writeDyn = (index: number, tag: number, value: bigint): void => {
    const base = index * dynEntrySize;
    dv.setBigInt64(base + 0, BigInt(tag), true);
    dv.setBigUint64(base + 8, value, true);
  };
  writeDyn(0, 5, 0x12340000n); // DT_STRTAB (unmapped)
  writeDyn(1, 10, BigInt(dynstrBytes.length)); // DT_STRSZ
  writeDyn(2, 1, 1n); // DT_NEEDED
  writeDyn(3, 0, 0n); // DT_NULL

  const bytes = new Uint8Array(dynamicBytes.length + dynstrBytes.length).fill(0);
  bytes.set(dynamicBytes, 0);
  bytes.set(dynstrBytes, dynamicBytes.length);
  const file = new MockFile(bytes, "dyninfo.bin", "application/x-elf");
  const sections: ElfSectionHeader[] = [
    makeSection({ index: 0, type: 6, name: ".dynamic", offset: 0n,
      size: BigInt(dynamicBytes.length), link: 1 }),
    makeSection({
      index: 1,
      type: 3,
      name: ".dynstr",
      offset: BigInt(dynamicBytes.length),
      size: BigInt(dynstrBytes.length)
    })
  ];

  const info = await parseElfDynamicInfo({
    file,
    programHeaders: [] as ElfProgramHeader[],
    sections,
    is64: true,
    littleEndian: true
  });
  assert.ok(info);
  assert.deepEqual(info.needed, ["libc.so.6"]);
  assert.ok(info.issues.some(issue => issue.includes("does not map into a PT_LOAD segment")));
});
const dynamicStringsFixture = (text = "\0libtest.so\0") => {
  const bytes = new Uint8Array(128);
  const strings = new TextEncoder().encode(text);
  bytes.set(strings, 64); // Synthetic disjoint placement after four Elf64_Dyn entries.
  const sections = [
    makeSection({ index: 0 }),
    makeSection({ index: 1, type: 6, size: 64n, entsize: 16n, link: 2 }),
    makeSection({ index: 2, type: 3, name: "renamed", offset: 64n,
      size: BigInt(strings.length) })
  ];
  const load: ElfProgramHeader = { index: 0, type: 1, typeName: null,
    offset: 64n, vaddr: 0x1040n, paddr: 0n, filesz: BigInt(strings.length),
    memsz: BigInt(strings.length), flags: 4, flagNames: [], align: 1n };
  // DT_STRTAB, DT_STRSZ, DT_NEEDED: gABI 8.3.
  // https://gabi.xinuos.com/elf/08-dynamic.html
  const entries = [{ tag: 5, value: load.vaddr }, { tag: 10, value: BigInt(strings.length) },
    { tag: 1, value: 1n }];
  return { file: new File([bytes], "dynamic-strings"), sections, load, entries,
    is64: true, littleEndian: true };
};

// gABI 8.3: DT_PREINIT_ARRAY/DT_INIT_ARRAY/DT_FINI_ARRAY and their sizes.
for (const [baseTag, sizeTag] of [[32, 33], [25, 27], [26, 28]] as const) {
  for (const [size, terminated, diagnostic] of [
    [undefined, true, /requires .*ARRAYSZ/], [undefined, false, null],
    [0n, true, null], [8n, true, null], [9n, true, /whole number of pointers/],
    [16n, true, /outside PT_LOAD memory/]
  ] as const) {
    void test(`checks dynamic array tag ${baseTag}, size ${size}, terminated ${terminated}`, async () => {
      const fixture = dynamicStringsFixture();
      const load = { ...fixture.load, vaddr: 0n, filesz: 0n, memsz: 12n };
      const entries = [{ tag: baseTag, value: 0n },
        ...(size === undefined ? [] : [{ tag: sizeTag, value: size }])];

      const result = await parseElfDynamicInfo({ ...fixture, programHeaders: [load] },
        { entries, terminated });

      assert.deepEqual(result?.issues.map(issue => diagnostic?.test(issue)), diagnostic ? [true] : []);
      assert.equal(result?.entries.length, entries.length);
    });
  }
}

void test("accepts ELF32 pointers crossing adjacent load ranges", async () => {
  const fixture = dynamicStringsFixture();
  const first = { ...fixture.load, vaddr: 0n, filesz: 0n, memsz: 2n };
  const second = { ...first, index: 1, vaddr: 2n };

  const result = await parseElfDynamicInfo({ ...fixture, is64: false, programHeaders: [first, second] },
    { entries: [{ tag: 25, value: 0n }, { tag: 27, value: 4n }], terminated: true });

  assert.deepEqual(result?.initArray, { vaddr: 0n, size: 4n });
  assert.deepEqual(result?.issues, []);
});

for (const [type, size, mapped] of [[1, 4n, true], [1, 8n, false], [4, 4n, false]] as const) {
  void test(`handles ELF32 array at the address limit with segment type ${type}, size ${size}`, async () => {
    const fixture = dynamicStringsFixture();
    const load = { ...fixture.load, type, vaddr: 0xfffffffcn, filesz: 0n, memsz: 8n };
    const entries = [{ tag: 25, value: load.vaddr }, { tag: 27, value: size }];

    const result = await parseElfDynamicInfo({ ...fixture, is64: false, programHeaders: [load] },
      { entries, terminated: true });

    assert.deepEqual(result?.issues, mapped ? [] : ["DT_INIT_ARRAY range is outside PT_LOAD memory."]);
  });
}

void test("rejects dynamic strings crossing the file-backed load boundary", async () => {
  const fixture = dynamicStringsFixture();
  fixture.load.filesz -= 1n;
  const result = await parseElfDynamicInfo({ ...fixture, sections: [],
    programHeaders: [fixture.load, { ...fixture.load, type: 2, offset: 0n, filesz: 64n }] },
  fixture.entries);
  assert.deepEqual(result?.needed, []);
  assert.match(result!.issues.join(" "), /DT_STRTAB.*PT_LOAD/);
});

void test("accepts dynamic strings ending exactly at the load boundary", async () => {
  const fixture = dynamicStringsFixture();
  const result = await parseElfDynamicInfo({ ...fixture, programHeaders: [fixture.load] },
    fixture.entries);
  assert.deepEqual(result?.needed, ["libtest.so"]);
  assert.deepEqual(result?.issues, []);
});
void test("follows SHT_DYNAMIC sh_link regardless of string table name", async () => {
  const fixture = dynamicStringsFixture();
  const result = await parseElfDynamicInfo({ ...fixture, programHeaders: [] }, fixture.entries);
  assert.deepEqual(result?.needed, ["libtest.so"]);
});

void test("does not substitute a named dynstr for an invalid dynamic sh_link", async () => {
  const fixture = dynamicStringsFixture();
  fixture.sections[1]!.link = 99;
  fixture.sections[2]!.name = ".dynstr";
  const result = await parseElfDynamicInfo({ ...fixture, programHeaders: [] }, fixture.entries);
  assert.deepEqual(result?.needed, []);
  assert.match(result!.issues.join(" "), /sh_link/);
});
for (const [text, index, warning] of [
  ["\0libtest.so", 1n, /unterminated|NUL/],
  ["\0libtest.so\0", 12n, /reference|offset/],
  ["\0libtest.so\0", 1n << 60n, /reference|offset/]
] as const) {
  void test(`reports malformed dynamic strings: ${index} ${text.length}`, async () => {
    const fixture = dynamicStringsFixture(text);
    fixture.entries[2]!.value = index;
    const result = await parseElfDynamicInfo({ ...fixture, programHeaders: [fixture.load] },
      fixture.entries);
    assert.deepEqual(result?.needed, []);
    assert.match(result!.issues.join(" "), warning);
  });
}
void test("does not use an unrelated dynamic section as the segment fallback", async () => {
  const fixture = dynamicStringsFixture();
  fixture.sections[1]!.offset = 16n;
  const result = await parseElfDynamicInfo({ ...fixture,
    programHeaders: [{ ...fixture.load, type: 2, offset: 0n, filesz: 64n }] }, fixture.entries);
  assert.deepEqual(result?.needed, []);
  assert.match(result!.issues.join(" "), /DT_STRTAB/);
});

void test("validates the type and file range of linked dynamic strings", async () => {
  const fixture = dynamicStringsFixture();
  fixture.sections[2]!.type = 1;
  const wrongType = await parseElfDynamicInfo({ ...fixture, programHeaders: [] }, fixture.entries);
  assert.deepEqual(wrongType?.needed, []);
  assert.match(wrongType!.issues.join(" "), /sh_link/);
  fixture.sections[2]!.type = 3;
  fixture.sections[2]!.offset = BigInt(fixture.file.size);
  const outside = await parseElfDynamicInfo({ ...fixture, programHeaders: [] }, fixture.entries);
  assert.deepEqual(outside?.needed, []);
  assert.match(outside!.issues.join(" "), /outside the file/);
});

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
  assert.deepEqual(parsed.dynamic.needed, expected.needed);
  assert.equal(parsed.dynamic.soname, expected.soname);
  assert.equal(parsed.dynamic.runpath, expected.runpath);
  assert.equal(parsed.dynamic.init, 0x401000n);
});

void test("parseElfDynamicInfo falls back to .dynstr when DT_STRTAB doesn't map", async () => {
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
    makeSection({ index: 0, type: 6, name: ".dynamic", offset: 0n, size: BigInt(dynamicBytes.length) }),
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



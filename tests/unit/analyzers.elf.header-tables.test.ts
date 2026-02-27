"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseProgramHeadersWithGuards,
  parseSectionHeadersWithNames,
  resolveExtendedHeaderCounts
} from "../../analyzers/elf/header-tables.js";
import type { ElfHeader } from "../../analyzers/elf/types.js";
import { MockFile } from "../helpers/mock-file.js";

const baseHeader = (partial: Partial<ElfHeader>): ElfHeader => ({
  type: 2,
  typeName: "Executable",
  machine: 0x3e,
  machineName: "x86-64",
  entry: 0n,
  phoff: 0n,
  shoff: 0n,
  flags: 0,
  ehsize: 64,
  phentsize: 56,
  phnum: 0,
  shentsize: 64,
  shnum: 0,
  shstrndx: 0,
  ...partial
});

void test("resolveExtendedHeaderCounts reads values from section header #0", async () => {
  const bytes = new Uint8Array(256).fill(0);
  const sectionZero = new DataView(bytes.buffer, 64, 64);
  sectionZero.setBigUint64(32, 7n, true); // real shnum
  sectionZero.setUint32(40, 3, true); // real shstrndx
  sectionZero.setUint32(44, 5, true); // real phnum
  const file = new MockFile(bytes, "ext.elf", "application/x-elf");

  const issues: string[] = [];
  const resolved = await resolveExtendedHeaderCounts(
    file,
    baseHeader({ phnum: 0xffff, shoff: 64n, shnum: 0, shstrndx: 0xffff }),
    true,
    true,
    issues,
    64
  );

  assert.equal(resolved.phnum, 5);
  assert.equal(resolved.shnum, 7);
  assert.equal(resolved.shstrndx, 3);
  assert.deepEqual(issues, []);
});

void test("resolveExtendedHeaderCounts reports missing section table for extended numbering", async () => {
  const file = new MockFile(new Uint8Array(64), "ext-missing.elf", "application/x-elf");
  const issues: string[] = [];
  const resolved = await resolveExtendedHeaderCounts(
    file,
    baseHeader({ phnum: 0xffff, shoff: 0n, shnum: 0, shstrndx: 0xffff }),
    true,
    true,
    issues,
    64
  );

  assert.equal(resolved.phnum, 0);
  assert.equal(resolved.shnum, 0);
  assert.equal(resolved.shstrndx, 0);
  assert.ok(issues.some(issue => issue.includes("requires section header #0")));
});

void test("parseProgramHeadersWithGuards rejects undersized entries", async () => {
  const file = new MockFile(new Uint8Array(256), "ph-small.elf", "application/x-elf");
  const issues: string[] = [];
  const entries = await parseProgramHeadersWithGuards(
    file,
    baseHeader({ phoff: 64n, phnum: 1, phentsize: 16 }),
    true,
    true,
    issues
  );

  assert.deepEqual(entries, []);
  assert.ok(issues.some(issue => issue.includes("Program header entry size (16)")));
});

void test("parseProgramHeadersWithGuards parses available program headers", async () => {
  const bytes = new Uint8Array(256).fill(0);
  new DataView(bytes.buffer).setUint32(64, 1, true);
  const file = new MockFile(bytes, "ph-ok.elf", "application/x-elf");
  const entries = await parseProgramHeadersWithGuards(
    file,
    baseHeader({ phoff: 64n, phnum: 1, phentsize: 56 }),
    true,
    true,
    []
  );

  assert.equal(entries.length, 1);
  assert.equal(entries[0]?.type, 1);
});

void test("parseSectionHeadersWithNames resolves section names from string table", async () => {
  const headerSize = 64;
  const tableOffset = headerSize;
  const entrySize = 64;
  const strings = new TextEncoder().encode("\0.sec0\0.shstrtab\0");
  const stringsOffset = tableOffset + entrySize * 2;
  const bytes = new Uint8Array(stringsOffset + strings.length).fill(0);
  const dv = new DataView(bytes.buffer);
  const section0 = tableOffset;
  const section1 = tableOffset + entrySize;
  dv.setUint32(section0 + 0, 1, true); // ".sec0"
  dv.setUint32(section0 + 4, 1, true);
  dv.setUint32(section1 + 0, 7, true); // ".shstrtab"
  dv.setUint32(section1 + 4, 3, true);
  dv.setBigUint64(section1 + 24, BigInt(stringsOffset), true);
  dv.setBigUint64(section1 + 32, BigInt(strings.length), true);
  bytes.set(strings, stringsOffset);
  const file = new MockFile(bytes, "sections.elf", "application/x-elf");

  const sections = await parseSectionHeadersWithNames(
    file,
    baseHeader({ shoff: BigInt(tableOffset), shnum: 2, shentsize: 64, shstrndx: 1 }),
    true,
    true,
    [],
    64
  );

  assert.equal(sections.length, 2);
  assert.equal(sections[0]?.name, ".sec0");
  assert.equal(sections[1]?.name, ".shstrtab");
});

void test("parseSectionHeadersWithNames rejects undersized section entries", async () => {
  const file = new MockFile(new Uint8Array(256), "sections-small.elf", "application/x-elf");
  const issues: string[] = [];
  const sections = await parseSectionHeadersWithNames(
    file,
    baseHeader({ shoff: 64n, shnum: 1, shentsize: 16 }),
    true,
    true,
    issues,
    64
  );

  assert.deepEqual(sections, []);
  assert.ok(issues.some(issue => issue.includes("Section header entry size (16)")));
});

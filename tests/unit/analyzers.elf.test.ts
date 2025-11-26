"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { MockFile } from "../helpers/mock-file.js";

const writeElfHeader = (
  bytes,
  {
    phoff = 0n,
    shoff = 0n,
    phnum = 0,
    shnum = 0,
    shentsize = 64,
    shstrndx = 0,
    headerVersion = 1,
    identVersion = 1
  }
) => {
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 0x7f454c46); // \x7FELF
  dv.setUint8(4, 2); // 64-bit
  dv.setUint8(5, 1); // little endian
  dv.setUint8(6, identVersion); // ident version
  dv.setUint16(0x10, 2, true); // type: executable
  dv.setUint16(0x12, 0x3e, true); // machine: x86-64
  dv.setUint32(0x14, headerVersion, true);
  dv.setBigUint64(0x18, 0n, true); // entry
  dv.setBigUint64(0x20, phoff, true);
  dv.setBigUint64(0x28, shoff, true);
  dv.setUint32(0x30, 0, true); // flags
  dv.setUint16(0x34, 0x40, true); // ehsize
  dv.setUint16(0x36, 0x38, true); // phentsize
  dv.setUint16(0x38, phnum, true);
  dv.setUint16(0x3a, shentsize, true);
  dv.setUint16(0x3c, shnum, true);
  dv.setUint16(0x3e, shstrndx, true);
};

void test("parseElf returns null for non-ELF files", async () => {
  const file = new MockFile(new Uint8Array([0, 1, 2, 3]));
  const parsed = await parseElf(file);
  assert.strictEqual(parsed, null);
});

void test("parseElf notes program headers that sit outside the file", async () => {
  const bytes = new Uint8Array(64).fill(0);
  writeElfHeader(bytes, { phoff: 200n, phnum: 1, shnum: 0 });
  const parsed = await parseElf(new MockFile(bytes, "elf-invalid.bin", "application/x-elf"));
  assert.ok(parsed);
  assert.deepStrictEqual(parsed.programHeaders, []);
  assert.ok(parsed.issues.some(msg => msg.includes("Program header table falls outside the file.")));
});

void test("parseElf surfaces version mismatches and truncated section name table", async () => {
  const bytes = new Uint8Array(160).fill(0);
  // Section table starts after the ELF header, one entry pointing to a truncated name table.
  writeElfHeader(bytes, {
    phoff: 0n,
    phnum: 0,
    shoff: 64n,
    shnum: 1,
    shentsize: 64,
    shstrndx: 0,
    headerVersion: 2,
    identVersion: 2
  });
  const sectionOffset = 64;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(sectionOffset + 0, 0, true); // nameOff
  dv.setUint32(sectionOffset + 4, 1, true); // type
  dv.setBigUint64(sectionOffset + 24, 120n, true); // offset to names
  dv.setBigUint64(sectionOffset + 32, 50n, true); // size of names (truncated)

  const parsed = await parseElf(new MockFile(bytes, "elf-truncated.bin", "application/x-elf"));
  assert.ok(parsed);
  assert.strictEqual(parsed.sections.length, 1);
  assert.strictEqual(parsed.sections[0].name, "");
  assert.ok(parsed.issues.some(msg => msg.includes("Unexpected ELF version")));
  assert.ok(parsed.issues.some(msg => msg.includes("Section name table is truncated.")));
});
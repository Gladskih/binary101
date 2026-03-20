"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseSectionHeaders } from "../../analyzers/pe/sections.js";
import { MockFile } from "../helpers/mock-file.js";

type SectionShape = { name: string; va: number; vs: number; rawSize: number; rawOff: number };
const createSectionTable = (sections: SectionShape[]): Uint8Array => {
  const buffer = new Uint8Array(sections.length * 40);
  const view = new DataView(buffer.buffer);
  sections.forEach((section, idx) => {
    const base = idx * 40;
    [...section.name].slice(0, 8).forEach((ch, i) => view.setUint8(base + i, ch.charCodeAt(0)));
    view.setUint32(base + 8, section.vs, true);
    view.setUint32(base + 12, section.va, true);
    view.setUint32(base + 16, section.rawSize, true);
    view.setUint32(base + 20, section.rawOff, true);
    view.setUint32(base + 36, 0, true);
  });
  return buffer;
};

void test("parseSectionHeaders reads section entries and maps RVAs to offsets", async () => {
  const table = createSectionTable([
    { name: ".text", va: 0x1000, vs: 0x200, rawSize: 0x200, rawOff: 0x400 },
    { name: ".rdata", va: 0x2000, vs: 0x180, rawSize: 0x200, rawOff: 0x800 }
  ]);
  const optionalHeaderOffset = 0x100;
  const sizeOfOptionalHeader = 0xE0;
  const fileBytes = new Uint8Array(optionalHeaderOffset + sizeOfOptionalHeader + table.length);
  fileBytes.set(table, optionalHeaderOffset + sizeOfOptionalHeader);
  const file = new MockFile(fileBytes);
  const { sections, rvaToOff, sectOff } = await parseSectionHeaders(
    file,
    optionalHeaderOffset,
    sizeOfOptionalHeader,
    2,
    optionalHeaderOffset + sizeOfOptionalHeader
  );

  assert.strictEqual(sectOff, optionalHeaderOffset + sizeOfOptionalHeader);
  assert.strictEqual(sections.length, 2);
  const [first] = sections;
  if (!first) assert.fail("first section missing");
  assert.strictEqual(first.name, ".text");
  assert.strictEqual(rvaToOff(0x1000), 0x400);
  assert.strictEqual(rvaToOff(0x2000 + 0x10), 0x800 + 0x10);
  assert.strictEqual(rvaToOff(0x3000), null);
});

void test("parseSectionHeaders does not map zero-filled virtual tail beyond raw section bytes", async () => {
  const table = createSectionTable([
    { name: ".data", va: 0x1000, vs: 0x300, rawSize: 0x200, rawOff: 0x400 }
  ]);
  const optionalHeaderOffset = 0x80;
  const sizeOfOptionalHeader = 0xE0;
  const fileBytes = new Uint8Array(optionalHeaderOffset + sizeOfOptionalHeader + table.length);
  fileBytes.set(table, optionalHeaderOffset + sizeOfOptionalHeader);

  const { rvaToOff } = await parseSectionHeaders(
    new MockFile(fileBytes),
    optionalHeaderOffset,
    sizeOfOptionalHeader,
    1,
    optionalHeaderOffset + sizeOfOptionalHeader
  );

  assert.strictEqual(rvaToOff(0x1000 + 0x1ff), 0x400 + 0x1ff);
  assert.strictEqual(
    rvaToOff(0x1000 + 0x200),
    null,
    "RVA in zero-filled tail should not map to bytes from another file region"
  );
});

void test("parseSectionHeaders does not map raw-file padding beyond VirtualSize into the loaded image", async () => {
  const table = createSectionTable([
    { name: ".text", va: 0x1000, vs: 0x80, rawSize: 0x200, rawOff: 0x400 }
  ]);
  const optionalHeaderOffset = 0x80;
  const sizeOfOptionalHeader = 0xE0;
  const fileBytes = new Uint8Array(optionalHeaderOffset + sizeOfOptionalHeader + table.length);
  fileBytes.set(table, optionalHeaderOffset + sizeOfOptionalHeader);

  const { rvaToOff } = await parseSectionHeaders(
    new MockFile(fileBytes),
    optionalHeaderOffset,
    sizeOfOptionalHeader,
    1,
    optionalHeaderOffset + sizeOfOptionalHeader
  );

  assert.strictEqual(rvaToOff(0x1000 + 0x7f), 0x400 + 0x7f);
  assert.strictEqual(
    rvaToOff(0x1000 + 0x80),
    null,
    "RVA in raw padding beyond VirtualSize should not resolve inside the image"
  );
});

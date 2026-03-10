"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseBaseRelocations } from "../../analyzers/pe/reloc.js";
import { MockFile } from "../helpers/mock-file.js";

type CoverageEntry = { label: string; start: number; size: number };

const rvaToOff = (rva: number): number => rva;

const collectCoverage = (): {
  regions: CoverageEntry[];
  add: (label: string, start: number, size: number) => void;
} => {
  const regions: CoverageEntry[] = [];
  const add = (label: string, start: number, size: number) => {
    regions.push({ label, start, size });
  };
  return { regions, add };
};

void test("parseBaseRelocations counts entries and stops on invalid blocks", async () => {
  const bytes = new Uint8Array(0x200).fill(0);
  const relOff = 0x40;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(relOff + 0, 0x1000, true);
  dv.setUint32(relOff + 4, 0x10, true);
  const invalidBlock = relOff + 0x10;
  dv.setUint32(invalidBlock + 0, 0x2000, true);
  dv.setUint32(invalidBlock + 4, 0x00, true);

  const { regions, add } = collectCoverage();
  const parsed = await parseBaseRelocations(
    new MockFile(bytes, "reloc.bin"),
    [{ name: "BASERELOC", rva: relOff, size: 0x20 }],
    rvaToOff,
    add
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.blocks.length, 1);
  assert.strictEqual(parsed.totalEntries, 4);
  assert.ok(regions.some(r => r.label.includes("BASERELOC")));
});

void test("parseBaseRelocations accepts a relocation block for page RVA 0", async () => {
  const bytes = new Uint8Array(0x100).fill(0);
  const relOff = 0x20;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(relOff + 0, 0, true);
  dv.setUint32(relOff + 4, 0x0c, true);
  dv.setUint16(relOff + 8, 0x3001, true);
  dv.setUint16(relOff + 10, 0x0000, true);

  const parsed = await parseBaseRelocations(
    new MockFile(bytes, "reloc-page-zero.bin"),
    [{ name: "BASERELOC", rva: relOff, size: 0x0c }],
    rvaToOff,
    () => {}
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.blocks.length, 1);
  assert.strictEqual(parsed.blocks[0]?.pageRva, 0);
  assert.strictEqual(parsed.totalEntries, 2);
});

void test("parseBaseRelocations does not silently cap valid tables at 256 blocks", async () => {
  const blockCount = 257;
  const relOff = 0x40;
  const bytes = new Uint8Array(relOff + blockCount * 8).fill(0);
  const dv = new DataView(bytes.buffer);
  for (let index = 0; index < blockCount; index += 1) {
    const off = relOff + index * 8;
    dv.setUint32(off + 0, (0x1000 + index * 0x1000) >>> 0, true);
    dv.setUint32(off + 4, 8, true);
  }

  const parsed = await parseBaseRelocations(
    new MockFile(bytes, "reloc-many-blocks.bin"),
    [{ name: "BASERELOC", rva: relOff, size: blockCount * 8 }],
    rvaToOff,
    () => {}
  );

  assert.ok(parsed);
  assert.strictEqual(parsed.blocks.length, blockCount);
});

"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { probeMachO } from "../../analyzers/macho/probe.js";
import { createMinimalJavaClassBytes } from "../fixtures/java-class-fixtures.js";
import { createTruncatedFatMachOBytes } from "../fixtures/macho-fixtures.js";

const dvFromMagic = (magic: number, byteLength = 8): DataView => {
  const bytes = new Uint8Array(byteLength);
  new DataView(bytes.buffer).setUint32(0, magic, false);
  return new DataView(bytes.buffer);
};

void test("probeMachO differentiates 32-bit, 64-bit and fat", () => {
  assert.strictEqual(probeMachO(dvFromMagic(0xfeedface, 4)), "Mach-O 32-bit"); // MH_MAGIC
  assert.strictEqual(probeMachO(dvFromMagic(0xcefaedfe, 4)), "Mach-O 32-bit"); // MH_CIGAM
  assert.strictEqual(probeMachO(dvFromMagic(0xfeedfacf, 4)), "Mach-O 64-bit"); // MH_MAGIC_64
  assert.strictEqual(probeMachO(dvFromMagic(0xcffaedfe, 4)), "Mach-O 64-bit"); // MH_CIGAM_64
  assert.strictEqual(probeMachO(dvFromMagic(0xcafebabe)), "Mach-O universal (Fat)"); // FAT_MAGIC
  assert.strictEqual(probeMachO(dvFromMagic(0xcafebabf)), "Mach-O universal (Fat)"); // FAT_MAGIC_64
  // Not one of the Mach-O or fat magic values above.
  assert.strictEqual(probeMachO(dvFromMagic(0x00010203, 4)), null);
});

void test("probeMachO excludes Java class files and swapped fat constants", () => {
  const javaClass = new DataView(createMinimalJavaClassBytes().buffer);
  assert.strictEqual(probeMachO(javaClass), null);
  // Byte-swapped FAT_MAGIC / FAT_MAGIC_64 are not valid Mach-O signatures.
  assert.strictEqual(probeMachO(dvFromMagic(0xbebafeca)), null);
  assert.strictEqual(probeMachO(dvFromMagic(0xbfbafeca)), null);
});

void test("probeMachO keeps truncated fat wrappers visible", () => {
  const truncatedFat = new DataView(createTruncatedFatMachOBytes().buffer);
  assert.strictEqual(probeMachO(truncatedFat, truncatedFat.byteLength), "Mach-O universal (Fat, truncated)");
});

void test("probeMachO keeps plausible large fat binaries out of the Java-class fast path", () => {
  const sliceCount = 45;
  const headerSize = 8;
  const archSize = 20;
  const sliceSize = 4;
  const tableSize = headerSize + sliceCount * archSize;
  const bytes = new Uint8Array(tableSize + sliceCount * sliceSize);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0xcafebabe, false);
  view.setUint32(4, sliceCount, false);
  for (let index = 0; index < sliceCount; index += 1) {
    const recordOffset = headerSize + index * archSize;
    const sliceOffset = tableSize + index * sliceSize;
    // mach/machine.h: CPU_TYPE_X86_64 == 0x01000007.
    view.setUint32(recordOffset, 0x01000007, false);
    view.setUint32(recordOffset + 4, 3, false);
    view.setUint32(recordOffset + 8, sliceOffset, false);
    view.setUint32(recordOffset + 12, sliceSize, false);
    view.setUint32(recordOffset + 16, 0, false);
    // mach-o/loader.h: MH_MAGIC_64 == 0xfeedfacf.
    view.setUint32(sliceOffset, 0xfeedfacf, false);
  }
  assert.strictEqual(probeMachO(new DataView(bytes.buffer), bytes.length), "Mach-O universal (Fat)");
});

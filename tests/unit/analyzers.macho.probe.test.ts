"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { probeMachO } from "../../analyzers/macho/probe.js";

const dvFromMagic = (magic: number, byteLength = 8): DataView => {
  const bytes = new Uint8Array(byteLength);
  new DataView(bytes.buffer).setUint32(0, magic, false);
  return new DataView(bytes.buffer);
};

const createFatLikeJavaClass = (): DataView => {
  const bytes = new Uint8Array(10);
  const view = new DataView(bytes.buffer);
  // JVM class files also start with CAFEBABE.
  view.setUint32(0, 0xcafebabe, false);
  // JVM class files place minor/major version fields immediately after CAFEBABE.
  view.setUint16(4, 0, false);
  view.setUint16(6, 52, false);
  view.setUint16(8, 1, false);
  return view;
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
  const javaClass = createFatLikeJavaClass();
  assert.strictEqual(probeMachO(javaClass), null);
  // Byte-swapped FAT_MAGIC / FAT_MAGIC_64 are not valid Mach-O signatures.
  assert.strictEqual(probeMachO(dvFromMagic(0xbebafeca)), null);
  assert.strictEqual(probeMachO(dvFromMagic(0xbfbafeca)), null);
});

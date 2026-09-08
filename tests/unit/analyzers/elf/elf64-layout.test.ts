import assert from "node:assert/strict";
import { test } from "node:test";
import { createElf64Layout } from "../../../../analyzers/elf/elf64-layout.js";

void test("ELF64 preserves full-width addresses, unsigned r_info halves and signed addends", () => {
  // gABI Elf64_Rela: three 8-byte fields, two 32-bit halves in r_info.
  // https://gabi.xinuos.com/elf/06-reloc.html
  const view = new DataView(new ArrayBuffer(24));
  view.setBigUint64(0, 0xffff_ffff_ffff_fffen);
  view.setBigUint64(8, 0xffff_ffff_ffff_fff0n);
  view.setBigInt64(16, -(1n << 63n));
  const layout = createElf64Layout("big");

  assert.deepEqual(layout.relocations.RELA.read(view), {
    offset: 0xffff_ffff_ffff_fffen, type: 0xfffffff0, symbolIndex: 0xffffffff,
    addend: -(1n << 63n)
  });
  assert.equal(layout.supportsSymbolicRelocations(8), false); // EM_MIPS compound ELF64 r_info.
  assert.equal(layout.supportsSymbolicRelocations(62), true); // EM_X86_64.
});

void test("ELF64 symbol values remain bigints and do not lose high bits", () => {
  // https://gabi.xinuos.com/elf/05-symtab.html: Elf64_Sym byte layout.
  const view = new DataView(new ArrayBuffer(24));
  view.setUint32(0, 7);
  view.setUint8(4, 0xab);
  view.setUint8(5, 0xfe);
  view.setUint16(6, 0xffff);
  view.setBigUint64(8, 0xffff_ffff_ffff_fffen);
  view.setBigUint64(16, 1n << 63n);

  assert.deepEqual(createElf64Layout("big").readSymbol(view), {
    nameOffset: 7, value: 0xffff_ffff_ffff_fffen, size: 1n << 63n,
    info: 0xab, other: 0xfe, sectionIndex: 0xffff
  });
});

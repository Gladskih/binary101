import assert from "node:assert/strict";
import { test } from "node:test";
import { createElf64Layout } from "../../../../analyzers/elf/elf64-layout.js";

// Elf64_Ehdr: https://gabi.xinuos.com/elf/02-eheader.html
const header64 = (order: "little" | "big") => {
  const view = new DataView(new ArrayBuffer(64));
  view.setUint16(16, 2, order === "little");
  view.setUint16(18, 62, order === "little");
  view.setUint32(20, 1, order === "little");
  [0xfffffffffffffffen, 64n, 0x100000100n].forEach((value, index) =>
    view.setBigUint64(24 + index * 8, value, order === "little"));
  view.setUint32(48, 0x80000000, order === "little");
  [64, 56, 5, 64, 13, 12].forEach((value, index) =>
    view.setUint16(52 + index * 2, value, order === "little"));
  return view;
};

for (const order of ["little", "big"] as const) {
  void test(`ELF64 reads the complete ${order}-endian file header without losing address bits`, () => {
    assert.deepEqual(createElf64Layout(order).readHeader(header64(order)), {
      type: 2, machine: 62, version: 1, entry: 0xfffffffffffffffen, phoff: 64n,
      shoff: 0x100000100n, flags: 0x80000000, ehsize: 64, phentsize: 56,
      phnum: 5, shentsize: 64, shnum: 13, shstrndx: 12
    });
  });
}

void test("ELF64 rejects a header truncated within the final field", () => {
  assert.equal(createElf64Layout("little").readHeader(new DataView(new ArrayBuffer(63))), null);
});

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

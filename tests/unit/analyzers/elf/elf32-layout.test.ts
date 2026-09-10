import assert from "node:assert/strict";
import { test } from "node:test";
import { createElf32Layout } from "../../../../analyzers/elf/elf32-layout.js";

// Elf32_Ehdr: https://gabi.xinuos.com/elf/02-eheader.html
const header32 = (order: "little" | "big") => {
  const view = new DataView(new ArrayBuffer(52));
  view.setUint16(16, 3, order === "little");
  view.setUint16(18, 40, order === "little");
  view.setUint32(20, 1, order === "little");
  [0xffffffff, 52, 256, 0x5000400].forEach((value, index) =>
    view.setUint32(24 + index * 4, value, order === "little"));
  [52, 32, 7, 40, 11, 10].forEach((value, index) =>
    view.setUint16(40 + index * 2, value, order === "little"));
  return view;
};

for (const order of ["little", "big"] as const) {
  void test(`ELF32 reads the complete ${order}-endian file header`, () => {
    assert.deepEqual(createElf32Layout(order).readHeader(header32(order)), {
      type: 3, machine: 40, version: 1, entry: 0xffffffffn, phoff: 52n, shoff: 256n,
      flags: 0x5000400, ehsize: 52, phentsize: 32, phnum: 7,
      shentsize: 40, shnum: 11, shstrndx: 10
    });
  });
}

void test("ELF32 rejects a header truncated within the final field", () => {
  assert.equal(createElf32Layout("little").readHeader(new DataView(new ArrayBuffer(51))), null);
});

void test("ELF32 preserves unsigned address and r_info fields and signed RELA addends", () => {
  // gABI Elf32_Rela: three 4-byte fields; r_info has 24 symbol bits and 8 type bits.
  // https://gabi.xinuos.com/elf/06-reloc.html
  const view = new DataView(new ArrayBuffer(12));
  view.setUint32(0, 0xffff_fffe);
  view.setUint32(4, 0xffff_ff80);
  view.setInt32(8, -0x8000_0000);
  const layout = createElf32Layout("big");

  assert.deepEqual(layout.relocations.RELA.read(view), {
    offset: 0xffff_fffen, type: 128, symbolIndex: 0xffffff, addend: -0x8000_0000n
  });
  assert.equal(layout.supportsSymbolicRelocations(8), true); // EM_MIPS has generic ELF32 r_info.
});

void test("ELF32 st_info, st_other and st_shndx keep their independent byte offsets", () => {
  // https://gabi.xinuos.com/elf/05-symtab.html: Elf32_Sym byte layout.
  const view = new DataView(new ArrayBuffer(16));
  view.setUint32(0, 7);
  view.setUint32(4, 0xffff_fffe);
  view.setUint32(8, 0x8000_0000);
  view.setUint8(12, 0xab);
  view.setUint8(13, 0xfe);
  view.setUint16(14, 0xffff);

  assert.deepEqual(createElf32Layout("big").readSymbol(view), {
    nameOffset: 7, value: 0xffff_fffen, size: 0x8000_0000n,
    info: 0xab, other: 0xfe, sectionIndex: 0xffff
  });
});

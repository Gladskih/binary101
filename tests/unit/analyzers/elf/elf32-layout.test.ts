import assert from "node:assert/strict";
import { test } from "node:test";
import { createElf32Layout } from "../../../../analyzers/elf/elf32-layout.js";

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
